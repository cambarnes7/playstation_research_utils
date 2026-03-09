/*
 * msrpm_probe — PS5 HV MSRPM (MSR Protection Map) scanner
 *
 * Probes which MSRs the hypervisor intercepts vs. allows from guest ring 0.
 *
 * Uses LIDT to swap in a private IDT copy with a custom #GP handler.
 * pcb_onfault does NOT work for #GP — FreeBSD only checks it for #PF.
 * Direct IDT modification freezes the PS5 (HV protects IDT page via NPT).
 * LIDT loads a new IDT pointer without touching the protected page.
 *
 * CRITICAL TARGET: MSR 0xC0010020 (AMD PATCH_LOADER)
 *   If writable → EntrySign (CVE-2024-56161) is viable on PS5
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

struct idtr {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed));

/* ===================================================================
 * #GP fault recovery via LIDT + custom handler
 *
 * We copy the entire IDT to a stack buffer, patch entry #13 (#GP)
 * with our custom handler, and LIDT to swap it in. After probing,
 * LIDT restores the original. This avoids writing to the HV-protected
 * IDT page.
 * =================================================================== */

static volatile uint64_t gp_recovery_rip;
static volatile uint64_t gp_recovery_rsp;
static volatile int gp_faulted;
static volatile uint64_t orig_gp_handler_addr;
static volatile uint64_t msr_read_val;

__attribute__((naked)) static void custom_gp_handler(void)
{
    __asm__(
        /*
         * Stack on #GP entry (CPU pushes error code):
         *   (%rsp)    = error code
         *   8(%rsp)   = saved RIP
         *   16(%rsp)  = saved CS
         *   24(%rsp)  = saved RFLAGS
         *   32(%rsp)  = saved RSP
         *   40(%rsp)  = saved SS
         *
         * After our push rax:
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
        "addq $8, %rsp\n\t"       /* skip error code */
        "iretq\n\t"

        /* Chain to original handler */
        ".Lchain_original:\n\t"
        "popq %rax\n\t"
        "jmpq *orig_gp_handler_addr(%rip)\n\t"
    );
}

/* ===================================================================
 * IDT helpers
 * =================================================================== */

static inline uint64_t idt_gate_get_addr(struct idt_gate *g)
{
    return (uint64_t)g->off_lo |
           ((uint64_t)g->off_mid << 16) |
           ((uint64_t)g->off_hi << 32);
}

static inline void idt_gate_set_addr(struct idt_gate *g, uint64_t addr)
{
    g->off_lo  = (uint16_t)(addr);
    g->off_mid = (uint16_t)(addr >> 16);
    g->off_hi  = (uint32_t)(addr >> 32);
}

/* ===================================================================
 * Safe MSR probing
 * =================================================================== */

static int safe_rdmsr(uint32_t msr)
{
    gp_faulted = 0;
    msr_read_val = 0;

    __asm__ volatile(
        "leaq 1f(%%rip), %%rax\n\t"
        "movq %%rax, gp_recovery_rip(%%rip)\n\t"
        "movq %%rsp, gp_recovery_rsp(%%rip)\n\t"

        "rdmsr\n\t"

        "shlq $32, %%rdx\n\t"
        "orq %%rax, %%rdx\n\t"
        "movq %%rdx, msr_read_val(%%rip)\n\t"
        "movq $0, gp_recovery_rip(%%rip)\n\t"

        "1:\n\t"
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
        "leaq 1f(%%rip), %%rax\n\t"
        "movq %%rax, gp_recovery_rip(%%rip)\n\t"
        "movq %%rsp, gp_recovery_rsp(%%rip)\n\t"

        "movl %[msrnum], %%ecx\n\t"
        "wrmsr\n\t"

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

    uint64_t curthread;
    __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
    out[2] = curthread;

    /* =========================================================
     * LIDT approach: copy IDT, patch #GP, swap in, probe, swap back
     * ========================================================= */

    struct idtr orig_idtr;
    __asm__ volatile("sidt %0" : "=m"(orig_idtr));

    out[3] = orig_idtr.base;
    out[9] = (uint64_t)orig_idtr.limit;

    /* Stack-allocate a copy of the full IDT (256 entries × 16 bytes = 4KB) */
    struct idt_gate new_idt[256] __attribute__((aligned(16)));

    uint64_t copy_size = orig_idtr.limit + 1;
    if (copy_size > sizeof(new_idt))
        copy_size = sizeof(new_idt);

    /* Copy original IDT */
    volatile uint8_t *dst = (volatile uint8_t *)new_idt;
    volatile uint8_t *src = (volatile uint8_t *)orig_idtr.base;
    for (uint64_t i = 0; i < copy_size; i++)
        dst[i] = src[i];

    /* Save original #GP handler address */
    orig_gp_handler_addr = idt_gate_get_addr(&new_idt[13]);
    out[10] = orig_gp_handler_addr;

    /* Patch entry #13 in our copy */
    uint64_t hook_addr = (uint64_t)&custom_gp_handler;
    idt_gate_set_addr(&new_idt[13], hook_addr);
    out[11] = hook_addr;

    /* Prepare new IDTR pointing to our copy */
    struct idtr new_idtr;
    new_idtr.limit = orig_idtr.limit;
    new_idtr.base = (uint64_t)new_idt;

    /* Swap IDT: cli → lidt new → sti */
    __asm__ volatile("cli; lidt %0; sti" : : "m"(new_idtr) : "memory");

    /* Mark that IDT swap succeeded */
    out[12] = 0x4C494454;  /* "LIDT" — marker that we got past lidt */

    gp_recovery_rip = 0;
    gp_faulted = 0;

    /* =========================================================
     * MSR probing
     * ========================================================= */

    int total_probed = 0;
    int total_read_ok = 0;
    int total_write_ok = 0;
    int result_idx = 16;

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

    /* PRIORITY 1: MSR 0xC0010020 — AMD PATCH_LOADER */
    {
        uint32_t msr = 0xC0010020;
        int rd = safe_rdmsr(msr);
        uint64_t rd_val = rd ? msr_read_val : 0;
        int wr = safe_wrmsr(msr, 0);

        out[7] = ((uint64_t)rd << 32) | (uint64_t)wr;
        out[8] = rd_val;
        RECORD_RESULT(msr, rd, wr, rd_val);
    }

    /* PRIORITY 2: AMD-specific MSRs (0xC0010000-0xC001003F) */
    for (uint32_t msr = 0xC0010000; msr <= 0xC001003F; msr++) {
        if (msr == 0xC0010020) continue;

        int rd = safe_rdmsr(msr);
        uint64_t rd_val = rd ? msr_read_val : 0;

        int wr = 0;
        if (msr == 0xC0010010 || msr == 0xC0010015 ||
            msr == 0xC0010030 || msr == 0xC001001F) {
            if (rd)
                wr = safe_wrmsr(msr, rd_val);
            else
                wr = 2;
        } else {
            wr = 2;
        }
        RECORD_RESULT(msr, rd, wr, rd_val);
    }

    /* PRIORITY 3: IBS MSRs (0xC0011030-0xC001103B) */
    for (uint32_t msr = 0xC0011030; msr <= 0xC001103B; msr++) {
        int rd = safe_rdmsr(msr);
        uint64_t rd_val = rd ? msr_read_val : 0;
        RECORD_RESULT(msr, rd, 2, rd_val);
    }

    /* PRIORITY 4: EFER/STAR/LSTAR/CSTAR/SFMASK */
    for (uint32_t msr = 0xC0000080; msr <= 0xC0000084; msr++) {
        int rd = safe_rdmsr(msr);
        uint64_t rd_val = rd ? msr_read_val : 0;

        int wr = 2;
        if (msr == 0xC0000080 && rd) {
            uint64_t test_val = rd_val ^ (1ULL << 16);
            wr = safe_wrmsr(msr, test_val);
            if (wr) {
                int rd2 = safe_rdmsr(msr);
                if (rd2 && result_idx < 280) {
                    out[result_idx] = msr_read_val;
                    result_idx++;
                }
                safe_wrmsr(msr, rd_val);
            }
        }
        RECORD_RESULT(msr, rd, wr, rd_val);
    }

    /* PRIORITY 5: MTRR MSRs */
    uint32_t mtrr_msrs[] = {
        0x200, 0x201, 0x250, 0x258, 0x259,
        0x268, 0x269, 0x277, 0x2FF,
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

    /* PRIORITY 6: VM_HSAVE_PA (0xC0010117) */
    {
        uint32_t msr = 0xC0010117;
        int rd = safe_rdmsr(msr);
        uint64_t rd_val = rd ? msr_read_val : 0;
        int wr = 2;
        if (rd)
            wr = safe_wrmsr(msr, rd_val);
        RECORD_RESULT(msr, rd, wr, rd_val);
    }

    /* PRIORITY 7: Performance counter MSRs */
    uint32_t perf_msrs[] = {
        0xC0010200, 0xC0010201, 0xC0010202,
        0xC0010203, 0xC0010204, 0xC0010205,
    };
    for (int i = 0; i < (int)(sizeof(perf_msrs)/sizeof(perf_msrs[0])); i++) {
        uint32_t msr = perf_msrs[i];
        int rd = safe_rdmsr(msr);
        uint64_t rd_val = rd ? msr_read_val : 0;
        RECORD_RESULT(msr, rd, 2, rd_val);
    }

    /* =========================================================
     * Restore original IDT
     * ========================================================= */

    __asm__ volatile("cli; lidt %0; sti" : : "m"(orig_idtr) : "memory");

    /* =========================================================
     * Write summary
     * ========================================================= */

    out[4] = (uint64_t)total_probed;
    out[5] = (uint64_t)total_read_ok;
    out[6] = (uint64_t)total_write_ok;

    out32[1] = 0x0001;  /* success */
    out[287] = 0xdeadbeefcafe0099ULL;

    return 0;
}
