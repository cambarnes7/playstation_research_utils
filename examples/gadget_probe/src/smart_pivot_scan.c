#include <stdint.h>

/*
 * smart_pivot_scan v19 — pcb_onfault multi-offset probe
 *
 * v18 crashed: NULL read with onfault at +0xb0 caused kernel panic.
 * Possible causes:
 *   A) Hypervisor intercepts NULL faults before FreeBSD trap()
 *   B) pcb_onfault offset is not +0xb0 on PS5
 *
 * v19 strategy:
 *   Phase 1: Try onfault at +0xb0 with non-NULL fault address
 *            (0xdead000000001000 — avoids hypervisor NULL guard)
 *   If phase 1 crashes, phase 2 won't run (next iteration).
 *
 *   Actually, we try MULTIPLE offsets in sequence, one at a time.
 *   Each attempt: write recovery addr to pcb+offset, trigger fault,
 *   if recovery fires → found it. If not, clear and try next offset.
 *
 *   But we can't "try and fail" - a failed onfault = panic.
 *   So instead: write recovery addr to ALL likely offsets at once.
 *   Since the whole region from +0x40 to +0xf8 is zero (fresh thread),
 *   writing to safe offsets simultaneously is OK.
 *
 *   Safe offsets (not loaded by context switch on running thread):
 *     +0x78..+0xa0 = debug registers (not auto-loaded)
 *     +0xa8 = initial_fpucw (16-bit, we'll overwrite but it's a fresh thread)
 *     +0xb0 = pcb_onfault (FreeBSD 11 standard)
 *     +0xb8..+0x100 = pcb_flags, pcb_save area pointers, etc.
 *
 *   We'll write to offsets +0xa8, +0xb0, +0xb8, +0xc0, +0xc8, +0xd0
 *   Then trigger fault with non-NULL address.
 *   After recovery, check which offset was the real onfault.
 *
 * Output layout:
 *   [0x00] magic|status
 *   [0x08] kdata_base
 *   [0x10] ktext_base
 *   [0x18] curthread
 *   [0x20] pcb_ptr
 *   [0x28] onfault_test_result (1=worked)
 *   [0x30] recovery_label_addr
 *   [0x38] winning_onfault_offset
 *   [0x40] fault_address_used
 *   [0x48] sentinel
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
    for (int i = 0; i < 14; i++)
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

    /* Non-NULL fault address (avoids potential hypervisor NULL guard) */
    uint64_t fault_addr = 0xdead000000001000ULL;
    out[8] = fault_addr;

    /*
     * Write recovery address to multiple candidate onfault offsets.
     * PCB region +0x40..+0xf8 is all zeros (confirmed by v17 dump).
     *
     * We try offsets: +0xa8, +0xb0, +0xb8, +0xc0, +0xc8, +0xd0
     * After recovery, we probe which offset was consumed/cleared by
     * the fault handler (the kernel clears onfault after use, or we
     * can check which ones still have our value).
     *
     * UNSAFE to write: +0x40(fsbase), +0x48(gsbase), +0x50(kgsbase),
     *   +0x68(cr3) — these get loaded on context switch
     */
    __asm__ volatile(
        /* Get recovery label address */
        "lea 1f(%%rip), %%r9\n"

        /* Store recovery_label to out[6] */
        "movq %%r9, (%[out6])\n"

        /* Write recovery addr to candidate offsets */
        "movq %%r9, 0xa8(%[pcb])\n"
        "movq %%r9, 0xb0(%[pcb])\n"
        "movq %%r9, 0xb8(%[pcb])\n"
        "movq %%r9, 0xc0(%[pcb])\n"
        "movq %%r9, 0xc8(%[pcb])\n"
        "movq %%r9, 0xd0(%[pcb])\n"

        /* Trigger fault: read from non-NULL unmapped address */
        "movq %[faddr], %%rax\n"
        "movq (%%rax), %%rax\n"

        /* If we get here, fault didn't trigger onfault */
        "movq $0, (%[result])\n"
        "jmp 2f\n"

        /* Recovery point */
        "1:\n"
        /* We landed here via onfault! */
        "movq $1, (%[result])\n"

        "2:\n"
        :
        : [pcb] "r"(pcb_ptr),
          [result] "r"(&out[5]),
          [out6] "r"(&out[6]),
          [faddr] "r"(fault_addr)
        : "rax", "r9", "memory"
    );

    if (out[5] == 1) {
        /* Recovery worked! Now find which offset was the real onfault.
         * The kernel fault handler reads pcb_onfault and jumps to it.
         * It might or might not clear the field. Check which offsets
         * still have our recovery addr vs which were cleared.
         *
         * Re-read pcb pointer safely */
        __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
        pcb_ptr = *(volatile uint64_t*)(curthread + TD_PCB_OFF);
        volatile uint64_t* pcb = (volatile uint64_t*)pcb_ptr;

        uint64_t recovery_addr = out[6];
        uint64_t winning_offset = 0;

        /* Check each offset - the real onfault may have been cleared
         * by the trap handler, or it may still contain our value.
         * We need to check and clean up all of them. */
        int offsets[] = {0xa8, 0xb0, 0xb8, 0xc0, 0xc8, 0xd0};
        for (int i = 0; i < 6; i++) {
            volatile uint64_t* slot = (volatile uint64_t*)((uint8_t*)pcb + offsets[i]);
            uint64_t val = *slot;
            *slot = 0;  /* Clean up */

            /* The real onfault was used by the fault handler.
             * In FreeBSD, trap_pfault does NOT clear pcb_onfault,
             * it just sets tf_rip = pcb_onfault. So all offsets
             * should still have our value. But the REAL onfault is
             * the one the handler actually read. We can't distinguish
             * this way. Instead, we'll do a second test: write to
             * only one offset at a time and see if it works. */
        }

        /* For now, just report success and that multi-offset worked */
        out[7] = 0xFFFF;  /* placeholder - need single-offset test */
    }

    /* Clean up: zero all candidate offsets */
    {
        __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
        pcb_ptr = *(volatile uint64_t*)(curthread + TD_PCB_OFF);
        volatile uint64_t* pcb_bytes = (volatile uint64_t*)pcb_ptr;
        /* Clear +0xa8 through +0xd0 */
        for (int off = 0xa8; off <= 0xd0; off += 8) {
            *(volatile uint64_t*)((uint8_t*)pcb_bytes + off) = 0;
        }
    }

    /* Sentinel */
    out[9] = 0xdeadbeefcafe0019ULL;

    /* Signal done */
    if (out[5] == 1)
        out[0] = ((uint64_t)0x0002 << 32) | MAGIC_SPVT;  /* onfault worked! */
    else
        out[0] = ((uint64_t)0x0001 << 32) | MAGIC_SPVT;  /* no onfault */

    return 0;
}
