/*
 * msrpm_probe — PS5 HV MSRPM (MSR Protection Map) scanner
 *
 * Probes which MSRs the hypervisor intercepts vs. allows from guest ring 0.
 * Hooks IDT vector 13 (#GP) to safely catch faults on intercepted MSRs.
 *
 * NOTE: pcb_onfault does NOT work for #GP — FreeBSD's trap handler only
 * checks pcb_onfault for #PF (page faults). For #GP (T_PROTFLT), it goes
 * straight to trap_fatal(). So we hook the IDT instead.
 *
 * CRITICAL TARGET: MSR 0xC0010020 (AMD PATCH_LOADER)
 *   If writable → EntrySign (CVE-2024-56161) is viable on PS5
 *   → Can load custom microcode → Neuter HV at CPU level
 *
 * Also probes:
 *   - 0xC0010000-0xC001003F: AMD-specific MSRs (missing from public MSRPM dump)
 *   - 0xC0011030-0xC001103B: IBS (Instruction-Based Sampling) MSRs
 *     (leaked HV physical addresses in Project Zero KVM escape)
 *   - 0x200-0x277: MTRRs (confirmed unprotected in partial dump)
 *   - 0xC0000080-0xC0000084: EFER/STAR/LSTAR/CSTAR/SFMASK
 *
 * Kldload kernel module — runs as kthread in ring 0.
 * Output via kthread_args readback buffer (2304 bytes = 288 uint64_t slots).
 */

#include <stdint.h>

/* ===================================================================
 * IDT gate descriptor (16 bytes on amd64)
 * =================================================================== */

struct idt_gate {
    uint16_t off_lo;
    uint16_t selector;
    uint8_t  ist;
    uint8_t  type_attr;
    uint16_t off_mid;
    uint32_t off_hi;
    uint32_t reserved;
} __attribute__((packed));

/* ===================================================================
 * #GP fault recovery via IDT hooking
 *
 * We install a custom #GP handler (vector 13) that checks our
 * gp_recovery_rip global. If set, it redirects execution there
 * (like pcb_onfault but for #GP). If not set, it jumps to the
 * original kernel #GP handler.
 *
 * The custom handler is written in asm and lives in .text so it's
 * executable alongside the rest of the payload.
 * =================================================================== */

/* Globals used by the asm #GP handler */
static volatile uint64_t gp_recovery_rip;
static volatile uint64_t gp_recovery_rsp;
static volatile int gp_faulted;
static volatile uint64_t orig_gp_handler;
static volatile uint64_t msr_read_val;

/*
 * Custom #GP handler (vector 13).
 * CPU pushes: [error_code] [rip] [cs] [rflags] [rsp] [ss]
 *
 * If gp_recovery_rip is set:
 *   - Clear it, set gp_faulted=1
 *   - Overwrite saved RIP with recovery address
 *   - Restore saved RSP
 *   - Skip error code, iretq to recovery
 * If gp_recovery_rip is 0:
 *   - Jump to original kernel #GP handler
 */
__attribute__((naked)) static void custom_gp_handler(void)
{
    __asm__(
        /*
         * Stack on entry (CPU pushed for #GP, which has error code):
         *   (%rsp)    = error code
         *   8(%rsp)   = saved RIP
         *   16(%rsp)  = saved CS
         *   24(%rsp)  = saved RFLAGS
         *   32(%rsp)  = saved RSP
         *   40(%rsp)  = saved SS
         *
         * We push rax, so offsets shift by +8:
         *   (%rsp)    = saved rax
         *   8(%rsp)   = error code
         *   16(%rsp)  = saved RIP
         *   24(%rsp)  = saved CS
         *   32(%rsp)  = saved RFLAGS
         *   40(%rsp)  = saved RSP
         *   48(%rsp)  = saved SS
         */
        "pushq %rax\n\t"
        "movq gp_recovery_rip(%rip), %rax\n\t"
        "testq %rax, %rax\n\t"
        "jz .Lchain_original\n\t"

        /* Recovery: overwrite saved RIP with recovery address */
        "movq %rax, 16(%rsp)\n\t"
        "movq $0, gp_recovery_rip(%rip)\n\t"
        "movl $1, gp_faulted(%rip)\n\t"

        /* Restore RSP in the iret frame */
        "movq gp_recovery_rsp(%rip), %rax\n\t"
        "movq %rax, 40(%rsp)\n\t"

        "popq %rax\n\t"
        "addq $8, %rsp\n\t"                /* skip error code */
        "iretq\n\t"

        /* Chain to original handler — restore rax and jump */
        ".Lchain_original:\n\t"
        "popq %rax\n\t"
        "jmpq *orig_gp_handler(%rip)\n\t"
    );
}

/* ===================================================================
 * IDT manipulation helpers
 * =================================================================== */

static inline uint64_t idt_gate_addr(struct idt_gate *g)
{
    return (uint64_t)g->off_lo |
           ((uint64_t)g->off_mid << 16) |
           ((uint64_t)g->off_hi << 32);
}

static inline void idt_gate_set_addr(volatile struct idt_gate *g, uint64_t addr)
{
    g->off_lo  = (uint16_t)(addr);
    g->off_mid = (uint16_t)(addr >> 16);
    g->off_hi  = (uint32_t)(addr >> 32);
}

/* ===================================================================
 * Safe MSR probing using IDT hook
 * =================================================================== */

static int safe_rdmsr(uint32_t msr)
{
    gp_faulted = 0;
    msr_read_val = 0;

    __asm__ volatile(
        /* Arm recovery */
        "leaq 1f(%%rip), %%rax\n\t"
        "movq %%rax, gp_recovery_rip(%%rip)\n\t"
        "movq %%rsp, gp_recovery_rsp(%%rip)\n\t"

        /* Attempt rdmsr */
        "rdmsr\n\t"

        /* Success: combine edx:eax → 64-bit and store */
        "shlq $32, %%rdx\n\t"
        "orq %%rax, %%rdx\n\t"
        "movq %%rdx, msr_read_val(%%rip)\n\t"

        /* Clear recovery (no longer needed) */
        "movq $0, gp_recovery_rip(%%rip)\n\t"

        "1:\n\t"   /* Recovery lands here (or falls through on success) */
        :
        : "c"(msr)
        : "rax", "rdx", "memory", "cc"
    );

    return gp_faulted == 0;
}

static int safe_wrmsr(uint32_t msr, uint64_t val)
{
    gp_faulted = 0;

    uint32_t lo = (uint32_t)val;
    uint32_t hi = (uint32_t)(val >> 32);

    __asm__ volatile(
        /* Arm recovery */
        "leaq 1f(%%rip), %%rax\n\t"
        "movq %%rax, gp_recovery_rip(%%rip)\n\t"
        "movq %%rsp, gp_recovery_rsp(%%rip)\n\t"

        /* Restore ecx for MSR number (clobbered by leaq) */
        "movl %[msrnum], %%ecx\n\t"

        /* Attempt wrmsr */
        "wrmsr\n\t"

        /* Clear recovery */
        "movq $0, gp_recovery_rip(%%rip)\n\t"

        "1:\n\t"
        :
        : "a"(lo), "d"(hi), [msrnum] "r"(msr)
        : "ecx", "memory", "cc"
    );

    return gp_faulted == 0;
}

/* ===================================================================
 * Entry point
 * =================================================================== */

typedef struct {
    uint64_t kdata_base;
    uint32_t fw_ver;
} kproc_args;

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    volatile uint64_t* out = (volatile uint64_t*)args;
    volatile uint32_t* out32 = (volatile uint32_t*)args;

    /* Clear output buffer */
    for (int i = 0; i < 288; i++)
        out[i] = 0;

    /* Write header */
    out32[0] = 0x4D535250;  /* "MSRP" */
    out32[1] = 0xAAAA;      /* in-progress */
    out[1] = kdata_base;

    /* Get curthread (for diagnostics) */
    uint64_t curthread;
    __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
    out[2] = curthread;

    /* =========================================================
     * Install IDT #GP hook
     * ========================================================= */

    struct {
        uint16_t limit;
        uint64_t base;
    } __attribute__((packed)) idtr;
    __asm__ volatile("sidt %0" : "=m"(idtr));

    volatile struct idt_gate *idt = (volatile struct idt_gate *)idtr.base;
    volatile struct idt_gate *gp_entry = &idt[13];

    /* Save original #GP handler address */
    orig_gp_handler = (uint64_t)gp_entry->off_lo |
                      ((uint64_t)gp_entry->off_mid << 16) |
                      ((uint64_t)gp_entry->off_hi << 32);

    /* Save original gate for restoration */
    struct idt_gate saved_gp;
    __builtin_memcpy(&saved_gp, (void *)gp_entry, sizeof(saved_gp));

    out[3] = orig_gp_handler;  /* store for diagnostics */
    out[9] = idtr.base;        /* IDT base for diagnostics */

    /* Install our handler, keeping same selector/IST/type_attr */
    uint64_t hook_addr = (uint64_t)&custom_gp_handler;
    out[10] = hook_addr;  /* our handler addr for diagnostics */

    /* Disable interrupts while patching IDT */
    __asm__ volatile("cli");

    idt_gate_set_addr(gp_entry, hook_addr);

    __asm__ volatile("sti");

    gp_recovery_rip = 0;
    gp_faulted = 0;

    /* =========================================================
     * MSR probing
     * ========================================================= */

    int total_probed = 0;
    int total_read_ok = 0;
    int total_write_ok = 0;
    int result_idx = 16;  /* Start writing results at slot 16 */

    #define RECORD_RESULT(msr_num, rd_ok, wr_ok, rd_val) do { \
        if (result_idx < 280) { \
            out[result_idx] = ((uint64_t)(msr_num) << 32) | \
                              ((uint64_t)(rd_ok) << 16) | \
                              ((uint64_t)(wr_ok) << 8) | \
                              ((rd_ok) ? 0x01 : 0x00); \
            result_idx++; \
            if (rd_ok) { \
                out[result_idx] = rd_val; \
                result_idx++; \
            } \
        } \
        total_probed++; \
        if (rd_ok) total_read_ok++; \
        if (wr_ok) total_write_ok++; \
    } while(0)

    /* =================================================================
     * PRIORITY 1: MSR 0xC0010020 — AMD PATCH_LOADER (EntrySign target)
     * ================================================================= */

    {
        uint32_t msr = 0xC0010020;
        int rd = safe_rdmsr(msr);
        uint64_t rd_val = rd ? msr_read_val : 0;

        int wr = safe_wrmsr(msr, 0);

        out[7] = ((uint64_t)rd << 32) | (uint64_t)wr;
        out[8] = rd_val;

        RECORD_RESULT(msr, rd, wr, rd_val);
    }

    /* =================================================================
     * PRIORITY 2: Nearby AMD-specific MSRs (0xC0010000-0xC001003F)
     * ================================================================= */

    for (uint32_t msr = 0xC0010000; msr <= 0xC001003F; msr++) {
        if (msr == 0xC0010020) continue;

        int rd = safe_rdmsr(msr);
        uint64_t rd_val = rd ? msr_read_val : 0;

        int wr = 0;
        if (msr == 0xC0010010 ||  /* SYSCFG */
            msr == 0xC0010015 ||  /* HWCR */
            msr == 0xC0010030 ||  /* CPU_NAME_STRING */
            msr == 0xC001001F) {  /* NB_CFG */
            if (rd)
                wr = safe_wrmsr(msr, rd_val);
            else
                wr = 2;
        } else {
            wr = 2;
        }

        RECORD_RESULT(msr, rd, wr, rd_val);
    }

    /* =================================================================
     * PRIORITY 3: IBS MSRs (0xC0011030-0xC001103B)
     * ================================================================= */

    for (uint32_t msr = 0xC0011030; msr <= 0xC001103B; msr++) {
        int rd = safe_rdmsr(msr);
        uint64_t rd_val = rd ? msr_read_val : 0;
        RECORD_RESULT(msr, rd, 2, rd_val);
    }

    /* =================================================================
     * PRIORITY 4: EFER / STAR / LSTAR / CSTAR / SFMASK
     * ================================================================= */

    for (uint32_t msr = 0xC0000080; msr <= 0xC0000084; msr++) {
        int rd = safe_rdmsr(msr);
        uint64_t rd_val = rd ? msr_read_val : 0;

        int wr = 2;
        if (msr == 0xC0000080) {
            if (rd) {
                uint64_t test_val = rd_val ^ (1ULL << 16);
                wr = safe_wrmsr(msr, test_val);
                if (wr) {
                    int rd2 = safe_rdmsr(msr);
                    if (rd2) {
                        uint64_t new_val = msr_read_val;
                        if (result_idx < 280) {
                            out[result_idx] = new_val;
                            result_idx++;
                        }
                        safe_wrmsr(msr, rd_val);
                    }
                }
            }
        }

        RECORD_RESULT(msr, rd, wr, rd_val);
    }

    /* =================================================================
     * PRIORITY 5: MTRR MSRs
     * ================================================================= */

    uint32_t mtrr_msrs[] = {
        0x200, 0x201,
        0x250,
        0x258, 0x259,
        0x268, 0x269,
        0x277,
        0x2FF,
    };

    for (int i = 0; i < (int)(sizeof(mtrr_msrs)/sizeof(mtrr_msrs[0])); i++) {
        uint32_t msr = mtrr_msrs[i];
        int rd = safe_rdmsr(msr);
        uint64_t rd_val = rd ? msr_read_val : 0;

        int wr = 2;
        if (rd)
            wr = safe_wrmsr(msr, rd_val);

        RECORD_RESULT(msr, rd, wr, rd_val);
    }

    /* =================================================================
     * PRIORITY 6: VM_HSAVE_PA (0xC0010117)
     * ================================================================= */

    {
        uint32_t msr = 0xC0010117;
        int rd = safe_rdmsr(msr);
        uint64_t rd_val = rd ? msr_read_val : 0;
        int wr = 2;
        if (rd)
            wr = safe_wrmsr(msr, rd_val);
        RECORD_RESULT(msr, rd, wr, rd_val);
    }

    /* =================================================================
     * PRIORITY 7: Performance counter MSRs
     * ================================================================= */

    uint32_t perf_msrs[] = {
        0xC0010200, 0xC0010201,
        0xC0010202, 0xC0010203,
        0xC0010204, 0xC0010205,
    };

    for (int i = 0; i < (int)(sizeof(perf_msrs)/sizeof(perf_msrs[0])); i++) {
        uint32_t msr = perf_msrs[i];
        int rd = safe_rdmsr(msr);
        uint64_t rd_val = rd ? msr_read_val : 0;
        RECORD_RESULT(msr, rd, 2, rd_val);
    }

    /* =========================================================
     * Restore original IDT #GP handler
     * ========================================================= */

    __asm__ volatile("cli");
    __builtin_memcpy((void *)gp_entry, &saved_gp, sizeof(saved_gp));
    __asm__ volatile("sti");

    /* =========================================================
     * Write summary
     * ========================================================= */

    out[4] = (uint64_t)total_probed;
    out[5] = (uint64_t)total_read_ok;
    out[6] = (uint64_t)total_write_ok;

    /* Completion */
    out32[1] = 0x0001;  /* success */
    out[287] = 0xdeadbeefcafe0099ULL;  /* sentinel */

    return 0;
}
