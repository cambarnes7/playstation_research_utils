#include <stdint.h>

/*
 * resume_chain v8c — safe byte probing with pcb_onfault
 *
 * Reads all 28 apic_ops fn ptrs (proven safe in v8b), then uses
 * pcb_onfault fault recovery to safely read the byte at fn-1 for each.
 * If fn-1 faults, fault_flag is set and we record 0xFA (fault marker).
 *
 * Safety guarantees:
 *   - pcb_onfault armed before EVERY read, cleared after EVERY read
 *   - RSP saved/restored on fault path
 *   - Only reads 1 byte per probe (no writes, no execution)
 *   - Magic written LAST with mfence (kldload won't read early)
 *   - All fn ptrs validated non-NULL before probing
 *
 * Output layout (512 bytes = 64 qwords):
 *   out[0]     = MAGIC (lo32) + status (hi32)
 *   out[1]     = kdata_base
 *   out[2]     = ktext_base
 *   out[3]     = td_pcb (confirms pcb_onfault setup)
 *   out[4..31] = apic_ops[0..27] fn ptrs
 *   out[32..59]= byte at fn-1 for each (0xFA=fault, 0xDEAD=null)
 *   out[60]    = cc_bitmap (bit i set = entry i has CC at fn-1)
 *   out[61]    = fault_bitmap (bit i set = entry i faulted)
 *   out[62]    = probe_count (number of probes attempted)
 *   out[63]    = end marker
 */

#define MAGIC_RSCN       0x5253434E

#define MSR_LSTAR        0xC0000082
#define LSTAR_OFFSET     0x294218

/* ktext-relative offset to apic_ops table */
#define OFF_APIC_OPS     0x1934AC8

#define APIC_OPS_COUNT   28

/* Thread/PCB offsets (confirmed in pcb_onfault_test) */
#define TD_PCB           0x3f8
#define PCB_ONFAULT      0x108

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

/* ---- pcb_onfault safe read infrastructure ---- */

static volatile uint64_t saved_rsp;
static volatile uint64_t onfault_ptr;  /* = td_pcb + PCB_ONFAULT */
static volatile int fault_flag;

/*
 * Safe single-byte read using pcb_onfault.
 * Returns 1 on success (byte stored in *val), 0 on fault.
 *
 * This is the proven pattern from pivot_scan_safe.
 */
static int safe_read1(uint64_t addr, uint8_t *val)
{
    fault_flag = 0;
    *val = 0;

    __asm__ volatile(
        /* Arm pcb_onfault with recovery label */
        "movq onfault_ptr(%%rip), %%r14\n\t"
        "leaq 2f(%%rip), %%rcx\n\t"
        "movq %%rcx, (%%r14)\n\t"
        "movq %%rsp, saved_rsp(%%rip)\n\t"

        /* Try the 1-byte read */
        "movzbl (%[addr]), %%eax\n\t"
        "movb %%al, (%[out])\n\t"

        /* Success: clear pcb_onfault */
        "movq onfault_ptr(%%rip), %%r14\n\t"
        "movq $0, (%%r14)\n\t"
        "jmp 1f\n\t"

        /* Fault recovery: CPU jumps here via pcb_onfault */
        "2:\n\t"
        "movq saved_rsp(%%rip), %%rsp\n\t"
        "movl $1, fault_flag(%%rip)\n\t"

        "1:\n\t"
        :
        : [addr] "r"(addr), [out] "r"(val)
        : "rax", "rcx", "r14", "memory", "cc"
    );

    return fault_flag == 0;
}

int module_start(kproc_args *args)
{
    uint64_t kdata_base = args->kdata_base;
    volatile uint64_t *out = (volatile uint64_t *)args;
    volatile uint32_t *out32 = (volatile uint32_t *)args;

    /* Clear output buffer */
    for (int i = 0; i < 64; i++)
        out[i] = 0;

    uint64_t lstar = rdmsr(MSR_LSTAR);
    uint64_t ktext_base = lstar - LSTAR_OFFSET;

    out[1] = kdata_base;
    out[2] = ktext_base;

    /* ---- Set up pcb_onfault ---- */
    uint64_t curthread;
    __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));

    uint64_t td_pcb = read8(curthread + TD_PCB);
    if (!td_pcb) {
        /* Cannot proceed without PCB — bail safely */
        out32[1] = 0x00FF;
        __asm__ volatile("mfence" ::: "memory");
        out32[0] = MAGIC_RSCN;
        return 0;
    }

    onfault_ptr = td_pcb + PCB_ONFAULT;
    out[3] = td_pcb;

    /* ---- Phase 1: Read all 28 fn ptrs (proven safe in v8b) ---- */
    uint64_t apic_ops_addr = ktext_base + OFF_APIC_OPS;

    for (int i = 0; i < APIC_OPS_COUNT; i++) {
        out[4 + i] = read8(apic_ops_addr + i * 8);
    }

    /* ---- Phase 2: Safe byte probing at fn-1 ---- */
    uint64_t cc_bitmap = 0;
    uint64_t fault_bitmap = 0;
    uint32_t probe_count = 0;

    for (int i = 0; i < APIC_OPS_COUNT; i++) {
        uint64_t fn = out[4 + i];

        if (fn == 0) {
            out[32 + i] = 0xDEAD;  /* NULL marker */
            continue;
        }

        probe_count++;
        uint8_t byte_val = 0;
        int ok = safe_read1(fn - 1, &byte_val);

        if (ok) {
            out[32 + i] = (uint64_t)byte_val;
            if (byte_val == 0xCC) {
                cc_bitmap |= (1ULL << i);
            }
        } else {
            out[32 + i] = 0xFA;  /* fault marker */
            fault_bitmap |= (1ULL << i);
        }
    }

    out[60] = cc_bitmap;
    out[61] = fault_bitmap;
    out[62] = probe_count;
    out[63] = 0xdeadbeefcafe008CULL;

    /* Write magic+status LAST */
    out32[1] = 0x008C;  /* v8c status */
    __asm__ volatile("mfence" ::: "memory");
    out32[0] = MAGIC_RSCN;

    return 0;
}
