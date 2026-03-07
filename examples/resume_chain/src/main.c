#include <stdint.h>

/*
 * resume_chain v8b — diagnostic canary (fn ptrs only)
 *
 * Reads all 28 apic_ops function pointers. No byte reads (avoids faults).
 * Magic written LAST so kldload only reads back when payload is fully done.
 *
 * Output layout:
 *   out[0]     = MAGIC (lo32) + status (hi32)
 *   out[1]     = kdata_base
 *   out[2]     = ktext_base
 *   out[3]     = apic_ops_addr (computed)
 *   out[4..31] = apic_ops[0..27] fn ptrs
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

    uint64_t apic_ops_addr = ktext_base + OFF_APIC_OPS;
    out[3] = apic_ops_addr;

    /* Read all 28 function pointers */
    for (int i = 0; i < APIC_OPS_COUNT; i++) {
        out[4 + i] = read8(apic_ops_addr + i * 8);
    }

    /* Write magic+status LAST — signals "all done" to kldload */
    out32[1] = 0x008B;  /* v8b status */
    __asm__ volatile("mfence" ::: "memory");
    out32[0] = MAGIC_RSCN;

    return 0;
}
