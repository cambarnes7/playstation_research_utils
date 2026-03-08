/*
 * kdata_scanner — Scan kdata for pointers into ktext
 *
 * Instead of blindly calling ktext addresses (which crashes on valid
 * destructive functions), this scans readable kdata for 8-byte values
 * that fall within the ktext range. Every kernel function pointer
 * referenced from data structures (sysent, apic_ops, vtables, IDT
 * handlers, pcpu function pointers, etc.) shows up here.
 *
 * This gives us a map of every ktext address referenced from kdata,
 * which we can use to find cpu_switch, savectx, etc. by offset
 * proximity — without executing a single unknown address.
 *
 * Mode (via fw_ver):
 *   0x403:  FULL SCAN page 0 — sorted unique ktext pointers (entries 0-56)
 *   0x405:  FULL SCAN page 1 — entries 57-113
 *   0x406:  FULL SCAN page 2 — entries 114-170
 *   0x407:  FULL SCAN page 3 — entries 171-227
 *   0x408:  FULL SCAN page 4 — entries 228-269
 *
 *   0x404:  TARGETED SCAN — scan for pointers near cpu_switch
 *           Shows kdata locations that reference cpu_switch vicinity
 *           (savectx, resumectx, fork_trampoline, etc. are nearby)
 *
 * Output layout (uint64_t indices):
 *   [0]   magic "KSCN" (0x4B53434E) | status(32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   cpu_switch_addr
 *   [4]   total_unique_ptrs (all modes) or total_hits (0x404)
 *   [5]   scan_bytes_total | page(8) << 56 | entries_this_page(16) << 40
 *
 *   Mode 0x403/0x405-0x408 (paged full scan):
 *     [6 + i]  sorted unique ktext pointers (up to 57 per page)
 *
 *   Mode 0x404:
 *     [6 + i*3 + 0]  kdata address where pointer was found
 *     [6 + i*3 + 1]  pointer value (the ktext address)
 *     [6 + i*3 + 2]  offset from cpu_switch (signed)
 *     (max 80 hits)
 *
 *   [279] sentinel 0xdeadbeefcafe0025
 */

#include <stdint.h>

#define MAGIC_KSCN       0x4B53434E  /* "KSCN" */
#define SENTINEL         0xdeadbeefcafe0025ULL

/* FW 4.03 offsets */
#define CPU_SWITCH_OFF   (-0x9d6f80)
#define LSTAR_OFF        0x294218

/* ktext is roughly 12MB (0xC00000) before kdata_base */
#define KTEXT_SIZE       0xC00000

#define MAX_UNIQUE       270
#define MAX_TARGETED     80
#define OUT_SLOTS        280
#define PAGE_ENTRIES     57   /* entries 6..62 visible in 0x1f8 readback */

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

static inline uint64_t read8(uint64_t addr)
{
    return *(volatile uint64_t*)addr;
}

/* Simple insertion sort for the unique array */
static void sort_u64(uint64_t* arr, int n)
{
    for (int i = 1; i < n; i++) {
        uint64_t key = arr[i];
        int j = i - 1;
        while (j >= 0 && arr[j] > key) {
            arr[j + 1] = arr[j];
            j--;
        }
        arr[j + 1] = key;
    }
}

/* Check if val is already in sorted array (linear scan, small N) */
static int contains(uint64_t* arr, int n, uint64_t val)
{
    for (int i = 0; i < n; i++)
        if (arr[i] == val) return 1;
    return 0;
}

/*
 * Scan a region of kdata for 8-byte aligned values in [ktext_lo, ktext_hi).
 * For mode 0x403: adds unique values to uniq[] array.
 * For mode 0x404: adds (kdata_addr, value, offset_from_cpu_switch) triples.
 */
static int scan_region(uint64_t start, uint64_t end,
                       uint64_t ktext_lo, uint64_t ktext_hi,
                       uint32_t mode, uint64_t cpu_switch,
                       volatile uint64_t* out, int current_count, int max_count)
{
    int count = current_count;

    for (uint64_t addr = start; addr + 8 <= end && count < max_count; addr += 8) {
        uint64_t val = read8(addr);

        if (val >= ktext_lo && val < ktext_hi) {
            if (mode == 0x403) {
                /* Full scan: collect unique ktext pointers */
                if (!contains((uint64_t*)&out[6], count, val)) {
                    out[6 + count] = val;
                    count++;
                }
            } else {
                /* Targeted scan: only pointers near cpu_switch */
                int64_t offset = (int64_t)(val - cpu_switch);
                if (offset >= -0x2000 && offset <= 0x4000) {
                    out[6 + count * 3 + 0] = addr;
                    out[6 + count * 3 + 1] = val;
                    out[6 + count * 3 + 2] = (uint64_t)offset;
                    count++;
                }
            }
        }
    }

    return count;
}

__attribute__((section(".text.module_start")))
int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    uint32_t mode = args->fw_ver;
    volatile uint64_t* out = (volatile uint64_t*)args;
    volatile uint32_t* out32 = (volatile uint32_t*)args;

    /* Zero output buffer */
    for (int i = 0; i < OUT_SLOTS; i++)
        out[i] = 0;

    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - LSTAR_OFF;
    uint64_t ktext_end = ktext_base + KTEXT_SIZE;
    uint64_t cpu_switch = kdata_base + CPU_SWITCH_OFF;

    /* Determine if this is a paged full-scan mode */
    int page = -1;
    uint32_t scan_mode = mode;
    if (mode == 0x403) {
        page = 0;
        scan_mode = 0x403;
    } else if (mode >= 0x405 && mode <= 0x408) {
        page = (int)(mode - 0x404);  /* 0x405=1, 0x406=2, 0x407=3, 0x408=4 */
        scan_mode = 0x403;
    }

    out32[0] = MAGIC_KSCN;
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = cpu_switch;

    int max_count = (scan_mode == 0x403) ? MAX_UNIQUE : MAX_TARGETED;
    int count = 0;
    uint64_t bytes_scanned = 0;

    /*
     * Scan regions of kdata known to contain function pointers:
     *
     * Region 1: kdata_base + 0x000000 .. + 0x200000  (2MB)
     *   Contains: sysent, sysentvec, linker_set, apic_ops, various vtables
     *
     * Region 2: kdata_base + 0x640_0000 .. + 0x660_0000  (2MB)
     *   Contains: pcpu area, IDT, TSS, GDT
     *
     * Region 3: kdata_base + 0xD00000 .. + 0xD20000  (128KB)
     *   Contains: more sysent/sysentvec entries
     *
     * Region 4: kdata_base + 0x150000 .. + 0x1A0000  (320KB)
     *   Contains: apic_ops table (at +0x1656b0), other driver vtables
     */

    /* Region 1: main kdata structures */
    count = scan_region(kdata_base, kdata_base + 0x200000,
                        ktext_base, ktext_end, scan_mode, cpu_switch,
                        out, count, max_count);
    bytes_scanned += 0x200000;

    /* Region 2: pcpu/IDT area */
    count = scan_region(kdata_base + 0x6400000, kdata_base + 0x6600000,
                        ktext_base, ktext_end, scan_mode, cpu_switch,
                        out, count, max_count);
    bytes_scanned += 0x200000;

    /* Region 3: extended sysent */
    count = scan_region(kdata_base + 0xD00000, kdata_base + 0xD20000,
                        ktext_base, ktext_end, scan_mode, cpu_switch,
                        out, count, max_count);
    bytes_scanned += 0x20000;

    /* Region 4: driver vtable area (apic_ops etc.) */
    count = scan_region(kdata_base + 0x150000, kdata_base + 0x1A0000,
                        ktext_base, ktext_end, scan_mode, cpu_switch,
                        out, count, max_count);
    bytes_scanned += 0x50000;

    /* Sort unique pointers for full-scan modes */
    if (scan_mode == 0x403 && count > 0) {
        sort_u64((uint64_t*)&out[6], count);
    }

    /*
     * For paged full-scan: move the requested page slice to out[6..62].
     * The full sorted array is in out[6..6+count-1].
     * Page N shows entries [N*57 .. (N+1)*57-1].
     */
    int entries_this_page = 0;
    if (page >= 0 && count > 0) {
        int start_idx = page * PAGE_ENTRIES;
        int end_idx = start_idx + PAGE_ENTRIES;
        if (end_idx > count) end_idx = count;

        if (start_idx < count) {
            entries_this_page = end_idx - start_idx;
            /* If page > 0, shift entries down to out[6] */
            if (page > 0) {
                for (int i = 0; i < entries_this_page; i++)
                    out[6 + i] = out[6 + start_idx + i];
                /* Clear remaining slots */
                for (int i = entries_this_page; i < PAGE_ENTRIES; i++)
                    out[6 + i] = 0;
            }
        }
    }

    out[4] = (uint64_t)count;
    /* Pack: bytes_scanned(40) | page(8) << 56 | entries_this_page(16) << 40 */
    out[5] = (bytes_scanned & 0xFFFFFFFFFFULL)
           | ((uint64_t)(page >= 0 ? page : 0) << 56)
           | ((uint64_t)entries_this_page << 40);
    out32[1] = 0x0001; /* status = completed */
    out[279] = SENTINEL;

    return 0;
}
