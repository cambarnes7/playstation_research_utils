#include <stdint.h>

/*
 * ktext_mapper — Expanded ktext function pointer map
 *
 * Reads IDT entries (256 interrupt handlers) to get ktext pointers
 * spread across the ENTIRE kernel text segment, not just the syscall
 * stub region.
 *
 * Also scans kdata for potential ktext pointers by walking known
 * structure areas (linker_set, callback tables, etc.)
 *
 * Output layout (uint64_t indices):
 *   [0]   magic "KMAP" (0x4B4D4150) | status(32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   ktext_end (ktext_base + 0xC00000)
 *   [4]   IDT base address
 *   [5]   total unique ktext pointers found
 *   [6..N] sorted, deduplicated ktext function pointers
 *
 * Max output: (2304 - 48) / 8 = 282 pointers
 */

#define MAGIC_KMAP    0x4B4D4150  /* "KMAP" */
#define IDT_OFF       0x64cdc80   /* FW 4.03: IDT in kdata */
#define NUM_IDT       256
#define MAX_PTRS      270         /* fit in 2304-byte readback */

typedef struct {
    uint64_t kdata_base;
    uint32_t fw_ver;
} kproc_args;

static inline uint64_t rdmsr(uint32_t msr)
{
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

/* Extract handler address from AMD64 IDT gate descriptor (16 bytes) */
static inline uint64_t idt_handler(volatile uint8_t* gate)
{
    uint16_t off_lo  = *(volatile uint16_t*)(gate + 0);
    uint16_t off_mid = *(volatile uint16_t*)(gate + 6);
    uint32_t off_hi  = *(volatile uint32_t*)(gate + 8);
    return (uint64_t)off_lo | ((uint64_t)off_mid << 16) | ((uint64_t)off_hi << 32);
}

static int add_unique(uint64_t* arr, int count, uint64_t val, int max)
{
    if (count >= max) return count;
    for (int i = 0; i < count; i++)
        if (arr[i] == val) return count;  /* duplicate */
    arr[count] = val;
    return count + 1;
}

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;
    uint64_t ktext_end = ktext_base + 0xC00000;

    volatile uint64_t* out = (volatile uint64_t*)args;

    /* Header */
    out[0] = ((uint64_t)0x0001 << 32) | MAGIC_KMAP;
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = ktext_end;
    out[4] = kdata_base + IDT_OFF;
    out[5] = 0; /* filled later */

    uint64_t* ptrs = (uint64_t*)&out[6];
    int count = 0;

    /* === Source 1: IDT entries (256 gates, 16 bytes each) === */
    volatile uint8_t* idt_base = (volatile uint8_t*)(kdata_base + IDT_OFF);
    for (int i = 0; i < NUM_IDT; i++) {
        uint64_t handler = idt_handler(idt_base + i * 16);
        if (handler >= ktext_base && handler < ktext_end)
            count = add_unique(ptrs, count, handler, MAX_PTRS);
    }

    /* === Source 2: Scan kdata for ktext pointers === */
    /* Walk through known data regions looking for aligned uint64_t values
       that fall within ktext range. Focus on areas likely to contain
       function pointer tables (vtables, ops structs, callback arrays).

       Known structure areas in kdata:
       - 0x160000..0x180000: various ops structs (apic_ops at 0x1656b0,
         sysent at 0x1709c0)
       - 0x000000..0x010000: early kernel data, init arrays
       - 0x640000..0x660000: IDT/GDT/TSS area
    */

    /* Scan region around init data (early kdata) */
    volatile uint64_t* scan;
    int scan_len;

    /* Region: kdata+0x0 to kdata+0x8000 (early init data) */
    scan = (volatile uint64_t*)(kdata_base);
    scan_len = 0x8000 / 8;
    for (int i = 0; i < scan_len && count < MAX_PTRS; i++) {
        uint64_t val = scan[i];
        if (val >= ktext_base && val < ktext_end)
            count = add_unique(ptrs, count, val, MAX_PTRS);
    }

    /* Region: kdata+0x150000 to kdata+0x180000 (ops structs area) */
    scan = (volatile uint64_t*)(kdata_base + 0x150000);
    scan_len = 0x30000 / 8;
    for (int i = 0; i < scan_len && count < MAX_PTRS; i++) {
        uint64_t val = scan[i];
        if (val >= ktext_base && val < ktext_end)
            count = add_unique(ptrs, count, val, MAX_PTRS);
    }

    /* Region: kdata+0x640000 to kdata+0x650000 (near IDT/GDT) */
    scan = (volatile uint64_t*)(kdata_base + 0x640000);
    scan_len = 0x10000 / 8;
    for (int i = 0; i < scan_len && count < MAX_PTRS; i++) {
        uint64_t val = scan[i];
        if (val >= ktext_base && val < ktext_end)
            count = add_unique(ptrs, count, val, MAX_PTRS);
    }

    /* === Sort results === */
    for (int i = 1; i < count; i++) {
        uint64_t key = ptrs[i];
        int j = i - 1;
        while (j >= 0 && ptrs[j] > key) {
            ptrs[j + 1] = ptrs[j];
            j--;
        }
        ptrs[j + 1] = key;
    }

    out[5] = count;

    return 0;
}
