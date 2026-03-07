#include <stdint.h>

/*
 * resume_chain v8a — diagnostic canary
 *
 * Minimal version: no IDT changes, no function calls, no test_cc_byte.
 * Just reads apic_ops entries and reports the bytes at fn-1.
 *
 * Output layout:
 *   out[0]     = MAGIC (lo32) + status (hi32)
 *   out[1]     = kdata_base
 *   out[2]     = ktext_base
 *   out[3]     = apic_ops_addr (computed)
 *   out[4]     = apic_ops[0] (create fn ptr)
 *   out[5]     = apic_ops[1] (init fn ptr)
 *   out[6]     = apic_ops[2] (xapic_mode fn ptr)
 *   out[7]     = byte at apic_ops[0]-1 | byte at [1]-1 << 8 | ...
 *   out[8..35] = apic_ops[i] fn ptrs (all 28)
 *   out[36..63]= byte at apic_ops[i]-1 (low byte of each)
 *   out[131]   = v8a end marker
 */

#define MAGIC_RSCN       0x5253434E

#define MSR_LSTAR        0xC0000082
#define LSTAR_OFFSET     0x294218

/* ktext-relative offset */
#define OFF_APIC_OPS     0x1934AC8

#define APIC_OPS_COUNT   28

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

static inline uint8_t read1(uint64_t addr)
{
    return *(volatile uint8_t *)addr;
}

int module_start(kproc_args *args)
{
    uint64_t kdata_base = args->kdata_base;
    volatile uint64_t *out = (volatile uint64_t *)args;
    volatile uint32_t *out32 = (volatile uint32_t *)args;

    /* Clear output buffer */
    for (int i = 0; i < 140; i++)
        out[i] = 0;

    uint64_t lstar = rdmsr(MSR_LSTAR);
    uint64_t ktext_base = lstar - LSTAR_OFFSET;

    out32[0] = MAGIC_RSCN;
    out[1] = kdata_base;
    out[2] = ktext_base;

    uint64_t apic_ops_addr = ktext_base + OFF_APIC_OPS;
    out[3] = apic_ops_addr;

    /* Read all 28 function pointers */
    for (int i = 0; i < APIC_OPS_COUNT; i++) {
        out[8 + i] = read8(apic_ops_addr + i * 8);
    }

    /* Report first 3 separately for easy reading */
    out[4] = out[8];   /* create */
    out[5] = out[9];   /* init */
    out[6] = out[10];  /* xapic_mode */

    /* Read byte at fn-1 for each entry */
    for (int i = 0; i < APIC_OPS_COUNT; i++) {
        uint64_t fn = out[8 + i];
        if (fn == 0) {
            out[36 + i] = 0xDEAD0000;  /* NULL ptr */
        } else if (fn >= ktext_base && fn < ktext_base + 0x2000000) {
            /* Valid ktext pointer — safe to read fn-1 */
            out[36 + i] = read1(fn - 1);
        } else {
            out[36 + i] = 0xDEAD0000 | (fn & 0xFFFF);  /* unexpected addr */
        }
    }

    out32[1] = 0x008A;  /* v8a canary status */
    out[131] = 0xdeadbeefcafe008AULL;  /* v8a end marker */
    return 0;
}
