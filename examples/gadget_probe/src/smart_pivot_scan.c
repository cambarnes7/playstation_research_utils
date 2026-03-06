#include <stdint.h>

/*
 * smart_pivot_scan v16 — Dump thread structure to find td_pcb offset
 *
 * v15 confirmed: infrastructure works, curthread=DMAP address.
 * v14 crashed dereferencing bad pcb pointer.
 *
 * v16: dump 1024 bytes of struct thread (128 qwords) from curthread.
 * NO pointer dereferences — just raw reads from the thread struct.
 * We'll identify td_pcb by looking for kernel heap pointers in the dump.
 *
 * Output layout:
 *   [0x00] magic|status
 *   [0x08] kdata_base
 *   [0x10] ktext_base
 *   [0x18] LSTAR
 *   [0x20] curthread
 *   [0x28..0x420] 128 qwords from curthread (thread struct dump)
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

    /* Zero header */
    for (int i = 0; i < 8; i++)
        out[i] = 0;

    out[0] = ((uint64_t)0xAAAA << 32) | MAGIC_SPVT;

    /* rdmsr LSTAR */
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"((uint32_t)0xC0000082));
    uint64_t lstar = ((uint64_t)hi << 32) | lo;

    out[1] = kdata_base;
    out[2] = lstar - 0x294218;
    out[3] = lstar;

    /* Read curthread */
    uint64_t curthread;
    __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
    out[4] = curthread;

    /* Dump 128 qwords (1024 bytes) of thread struct */
    volatile uint64_t* td = (volatile uint64_t*)curthread;
    for (int i = 0; i < 128; i++) {
        out[5 + i] = td[i];
    }

    /* Signal done */
    out[0] = ((uint64_t)0x0001 << 32) | MAGIC_SPVT;
    return 0;
}
