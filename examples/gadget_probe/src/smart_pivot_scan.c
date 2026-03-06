#include <stdint.h>

/*
 * smart_pivot_scan v14 — DIAGNOSTIC MODE
 *
 * v11-v13 all panicked. v13 panicked BEFORE "calling kproc_create" debug line.
 * Need to diagnose: are pcb_onfault offsets correct? Does the mechanism work?
 *
 * This version does NO ktext jumps. It:
 *   1. Dumps curthread, pcb, and pcb neighborhood
 *   2. Tests pcb_onfault by triggering a NULL read (page fault on kdata page 0)
 *   3. Reports whether the fault was caught
 *
 * Output layout (uint64_t[]):
 *   [0] tag|magic
 *   [1] kdata_base
 *   [2] ktext_base (computed)
 *   [3] LSTAR
 *   [4] curthread
 *   [5] pcb (curthread+0x3f8)
 *   [6] pcb_alt (curthread+0x3f0)  — alternative offset
 *   [7] pcb[0x00..0x07]
 *   [8] pcb[0x08..0x0f]
 *   ...
 *   [7+N] pcb bytes dumped (32 qwords = 256 bytes starting at pcb)
 *   [39] = pcb[0xa0..0xa7]
 *   [40] = pcb[0xa8..0xaf]
 *   [41] = pcb[0xb0..0xb7]  ← expected onfault slot
 *   [42] = pcb[0xb8..0xbf]
 *   [43] = pcb[0xc0..0xc7]  ← alternative onfault slot
 *   ...
 *   [55] = pcb[0xf0..0xf7]
 *   [56] = fault_test_result (0=not_run, 1=fault_caught, 2=no_fault_needed, 0xDEAD=failed)
 *   [57] = fault_handler address (for reference)
 *   [58] = test read value (what we read from a safe address as control)
 */

#define MAGIC_SPVT     0x53505654

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

static volatile uint64_t g_saved_rsp;
static volatile uint64_t g_resume_rip;

__attribute__((naked))
static void fault_handler(void)
{
    __asm__ volatile(
        "movq g_saved_rsp(%%rip), %%rsp\n\t"
        "jmpq *g_resume_rip(%%rip)\n\t"
        ::: "memory"
    );
}

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;

    volatile uint64_t* out = (volatile uint64_t*)args;

    /* Clear output area */
    for (int i = 0; i < 512 / 8; i++)
        out[i] = 0;

    out[0] = ((uint64_t)0xAAAA << 32) | MAGIC_SPVT;
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = lstar;

    /* Read curthread from gs:0 */
    uint64_t curthread;
    __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
    out[4] = curthread;

    /* Try two possible td_pcb offsets */
    uint64_t pcb_3f8 = *(volatile uint64_t*)(curthread + 0x3f8);
    uint64_t pcb_3f0 = *(volatile uint64_t*)(curthread + 0x3f0);
    out[5] = pcb_3f8;
    out[6] = pcb_3f0;

    /* Use the more likely pcb pointer — should be a kernel address */
    uint64_t pcb = pcb_3f8;
    /* Heuristic: valid kernel pointer starts with 0xffffff80 or 0xffffffff */
    if ((pcb >> 40) != 0xffffff && (pcb >> 32) != 0xffffffff) {
        pcb = pcb_3f0;  /* try alternative */
    }

    /* Dump 32 qwords (256 bytes) of pcb structure */
    for (int i = 0; i < 32; i++) {
        out[7 + i] = *(volatile uint64_t*)(pcb + i * 8);
    }

    /* out[56] = fault test result */
    out[57] = (uint64_t)fault_handler;

    /* Control test: read from a known-safe address (kdata_base) */
    out[58] = *(volatile uint64_t*)(kdata_base);

    /*
     * Now test pcb_onfault mechanism:
     * Write fault_handler to pcb+0xb0, then trigger a page fault
     * by reading from an unmapped address.
     */
    volatile uint64_t *onfault = (volatile uint64_t *)(pcb + 0xb0);
    uint64_t old_onfault = *onfault;

    /* Save state for fault recovery */
    volatile uint64_t fault_caught = 0;

    __asm__ volatile("movq %%rsp, %0" : "=m"(g_saved_rsp));

    /* Set resume point to after the fault test */
    __asm__ volatile(
        "leaq 1f(%%rip), %%rax\n\t"
        "movq %%rax, %0\n\t"
        "1:\n\t"
        : "=m"(g_resume_rip)
        : /* no inputs */
        : "rax", "memory"
    );

    if (fault_caught == 0) {
        /* First pass: arm onfault and trigger fault */
        fault_caught = 0xDEAD;  /* mark as "attempted" */
        *onfault = (uint64_t)fault_handler;

        /* Trigger page fault: read from address 0x1000 (unmapped) */
        volatile uint64_t bad_read = *(volatile uint64_t*)0x1000ULL;
        (void)bad_read;

        /* If we reach here, no fault occurred (address was mapped?!) */
        fault_caught = 2;
    } else {
        /* Second pass: we got here via fault_handler */
        fault_caught = 1;
    }

    /* Restore onfault */
    *onfault = old_onfault;

    out[56] = fault_caught;

    /* Signal completion */
    out[0] = ((uint64_t)0x0001 << 32) | MAGIC_SPVT;
    return 0;
}
