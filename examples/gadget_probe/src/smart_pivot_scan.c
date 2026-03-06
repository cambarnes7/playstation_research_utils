#include <stdint.h>

/*
 * smart_pivot_scan v15 — MINIMAL SMOKE TEST
 *
 * v14 panicked, likely in pcb dump loop (dereferencing bad pointer).
 * v15 does NOTHING risky: just writes magic + rdmsr + kdata_base.
 * No curthread, no pcb, no pointer following.
 *
 * If this panics: issue is in kproc_create/exec infrastructure.
 * If this works: issue is in our curthread/pcb code.
 *
 * Output:
 *   [0x00] 0x0001_53505654 when complete (0xAAAA during exec)
 *   [0x08] kdata_base
 *   [0x10] ktext_base
 *   [0x18] LSTAR
 *   [0x20] curthread (gs:0 - just read, no dereference)
 *   [0x28] sentinel 0xDEADBEEFCAFE0001
 */

#define MAGIC_SPVT     0x53505654

typedef struct {
    uint64_t kdata_base;
    uint32_t fw_ver;
} kproc_args;

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;

    volatile uint64_t* out = (volatile uint64_t*)args;

    /* Zero only 64 bytes (8 qwords) — minimal writes */
    for (int i = 0; i < 8; i++)
        out[i] = 0;

    out[0] = ((uint64_t)0xAAAA << 32) | MAGIC_SPVT;
    out[1] = kdata_base;

    /* rdmsr LSTAR */
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"((uint32_t)0xC0000082));
    uint64_t lstar = ((uint64_t)hi << 32) | lo;

    out[2] = lstar - 0x294218;  /* ktext_base */
    out[3] = lstar;

    /* Read curthread but DO NOT dereference it */
    uint64_t curthread;
    __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
    out[4] = curthread;

    /* Sentinel — proves we completed */
    out[5] = 0xDEADBEEFCAFE0001ULL;

    /* Signal done */
    out[0] = ((uint64_t)0x0001 << 32) | MAGIC_SPVT;
    return 0;
}
