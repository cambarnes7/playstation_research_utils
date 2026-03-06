#include <stdint.h>

/*
 * smart_pivot_scan v17 — Dump PCB structure to find cr3/rsp offsets
 *
 * v16 confirmed: td_pcb at curthread+0x3f8 (kernel heap pointer).
 * v14 crash was bad pcb sub-offsets, not wrong td_pcb offset.
 *
 * v17: dereference td_pcb and dump 256 bytes (32 qwords) of struct pcb.
 * We'll identify pcb_cr3 by looking for physical address values and
 * pcb_rsp/pcb_rbp by looking for kernel stack addresses.
 *
 * Output layout:
 *   [0x00] magic|status
 *   [0x08] kdata_base
 *   [0x10] ktext_base
 *   [0x18] curthread
 *   [0x20] pcb_ptr (value at curthread+0x3f8)
 *   [0x28..0x120] 32 qwords from pcb structure
 *   [0x128] sentinel 0xdeadbeefcafe0017
 */

#define MAGIC_SPVT     0x53505654
#define TD_PCB_OFF     0x3f8

typedef struct {
    uint64_t kdata_base;
    uint32_t fw_ver;
} kproc_args;

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    volatile uint64_t* out = (volatile uint64_t*)args;

    /* Zero output area */
    for (int i = 0; i < 40; i++)
        out[i] = 0;

    out[0] = ((uint64_t)0xAAAA << 32) | MAGIC_SPVT;

    /* rdmsr LSTAR */
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"((uint32_t)0xC0000082));
    uint64_t lstar = ((uint64_t)hi << 32) | lo;

    out[1] = kdata_base;
    out[2] = lstar - 0x294218;  /* ktext_base */

    /* Read curthread from gs:0 */
    uint64_t curthread;
    __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
    out[3] = curthread;

    /* Read td_pcb at curthread+0x3f8 */
    volatile uint64_t* td = (volatile uint64_t*)curthread;
    uint64_t pcb_ptr = td[TD_PCB_OFF / 8];  /* td[0x7f] */
    out[4] = pcb_ptr;

    /* Dump 32 qwords (256 bytes) of struct pcb */
    if (pcb_ptr != 0 && (pcb_ptr >> 40) == 0xffffff) {
        volatile uint64_t* pcb = (volatile uint64_t*)pcb_ptr;
        for (int i = 0; i < 32; i++) {
            out[5 + i] = pcb[i];
        }
    }

    /* Sentinel */
    out[5 + 32] = 0xdeadbeefcafe0017ULL;

    /* Signal done */
    out[0] = ((uint64_t)0x0001 << 32) | MAGIC_SPVT;
    return 0;
}
