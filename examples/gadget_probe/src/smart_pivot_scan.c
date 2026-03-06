#include <stdint.h>

/*
 * smart_pivot_scan v18 — Validate pcb_onfault fault recovery
 *
 * v17 confirmed PCB layout matches standard FreeBSD:
 *   pcb_r12=exec_code, pcb_rsp=stack, pcb_rbx=args, pcb_rip=fork_trampoline
 *
 * v18: Test pcb_onfault at offset +0xb0 (standard FreeBSD 11).
 *   1. Read td_pcb from curthread+0x3f8
 *   2. Write recovery label address to pcb+0xb0
 *   3. Trigger a deliberate fault (read from address 0)
 *   4. If recovery works, we land at recovery label → report success
 *   5. Clear pcb_onfault after recovery
 *
 * Output layout:
 *   [0x00] magic|status  (0x0001 = no onfault, 0x0002 = onfault worked!)
 *   [0x08] kdata_base
 *   [0x10] ktext_base
 *   [0x18] curthread
 *   [0x20] pcb_ptr
 *   [0x28] onfault_test_result (1=worked, 0=didn't trigger)
 *   [0x30] recovery_label_addr
 *   [0x38] pcb_onfault_offset_used
 *   [0x40] sentinel
 */

#define MAGIC_SPVT     0x53505654
#define TD_PCB_OFF     0x3f8
#define PCB_ONFAULT_OFF 0xb0  /* Standard FreeBSD 11 offset */

typedef struct {
    uint64_t kdata_base;
    uint32_t fw_ver;
} kproc_args;

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    volatile uint64_t* out = (volatile uint64_t*)args;

    /* Zero output */
    for (int i = 0; i < 12; i++)
        out[i] = 0;

    out[0] = ((uint64_t)0xAAAA << 32) | MAGIC_SPVT;

    /* rdmsr LSTAR */
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"((uint32_t)0xC0000082));
    uint64_t lstar = ((uint64_t)hi << 32) | lo;

    out[1] = kdata_base;
    out[2] = lstar - 0x294218;

    /* Read curthread */
    uint64_t curthread;
    __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
    out[3] = curthread;

    /* Read td_pcb */
    uint64_t pcb_ptr = *(volatile uint64_t*)(curthread + TD_PCB_OFF);
    out[4] = pcb_ptr;
    out[7] = PCB_ONFAULT_OFF;

    /*
     * The onfault test is done entirely in asm to ensure
     * the recovery label is in the same compilation unit.
     *
     * rcx = pcb_ptr
     * rdx = &out[5] (result slot)
     * r8 = &out[6] (recovery addr slot)
     *
     * 1. LEA recovery label into r9
     * 2. Store recovery addr to out[6]
     * 3. Write r9 to pcb+0xb0 (pcb_onfault)
     * 4. Read from NULL (trigger fault)
     * 5. If no fault: write 0 to result, jump to end
     * 6. recovery_label: write 1 to result, clear pcb_onfault
     * 7. end:
     */
    __asm__ volatile(
        /* r9 = recovery label address */
        "lea 1f(%%rip), %%r9\n"

        /* out[6] = recovery label addr */
        "movq %%r9, (%[out6])\n"

        /* pcb_onfault = recovery label */
        "movq %%r9, %c[onfault_off](%[pcb])\n"

        /* Trigger fault: read from address 0 */
        "xorq %%rax, %%rax\n"
        "movq (%%rax), %%rax\n"

        /* If we get here, fault didn't trigger onfault */
        "movq $0, (%[result])\n"
        "jmp 2f\n"

        /* Recovery point */
        "1:\n"
        /* Re-read curthread from gs:0, re-derive pcb */
        "movq %%gs:0, %%rcx\n"
        "movq %c[td_pcb_off](%%rcx), %%rcx\n"
        /* Clear pcb_onfault */
        "movq $0, %c[onfault_off](%%rcx)\n"
        /* Write success marker - use stored out pointer from r10 */
        "movq $1, (%[result])\n"

        "2:\n"
        :
        : [pcb] "r"(pcb_ptr),
          [result] "r"(&out[5]),
          [out6] "r"(&out[6]),
          [onfault_off] "i"(PCB_ONFAULT_OFF),
          [td_pcb_off] "i"(TD_PCB_OFF)
        : "rax", "rcx", "r9", "memory"
    );

    /* Sentinel */
    out[8] = 0xdeadbeefcafe0018ULL;

    /* Signal done */
    if (out[5] == 1)
        out[0] = ((uint64_t)0x0002 << 32) | MAGIC_SPVT;  /* onfault worked! */
    else
        out[0] = ((uint64_t)0x0001 << 32) | MAGIC_SPVT;  /* no onfault */

    return 0;
}
