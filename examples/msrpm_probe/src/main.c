/*
 * msrpm_probe — PS5 HV MSRPM (MSR Protection Map) scanner
 *
 * Probes which MSRs the hypervisor intercepts vs. allows from guest ring 0.
 *
 * Uses kstuff's int 179 (kmemcpy) to patch IDT entry #13 with our custom
 * #GP handler. int 179 goes through the kelf's page tables where the IDT
 * page is mapped RW. Direct writes to the IDT freeze because the page is
 * RO in the standard guest page tables. LIDT is intercepted by the HV.
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

/* ===================================================================
 * kstuff_memcpy — write to memory via kelf's page tables (int 179)
 *
 * r0gdb/kstuff installs an int 179 handler that does rep movsb under
 * the kelf's CR3, which maps the IDT page as RW.
 * Calling convention: rdi=dst, rsi=src, rcx=count.
 * rax is used to save/restore rbp across the interrupt.
 * =================================================================== */

static void kstuff_memcpy(void *dst, const void *src, uint64_t count)
{
    __asm__ volatile(
        "movq %%rbp, %%rax\n\t"
        "int $179\n\t"
        "movq %%rax, %%rbp\n\t"
        :
        : "D"(dst), "S"(src), "c"(count)
        : "rax", "rdx", "r8", "r9", "r10", "r11", "memory", "cc"
    );
}

/* ===================================================================
 * #GP fault recovery via custom IDT handler
 * =================================================================== */

static volatile uint64_t gp_recovery_rip;
static volatile uint64_t gp_recovery_rsp;
static volatile int gp_faulted;
static volatile uint64_t orig_gp_handler_addr;
static volatile uint64_t msr_read_val;
static volatile uint64_t exec_code_base;
static volatile uint64_t exec_code_end;
static volatile uint64_t gp_handler_entries;   /* debug: times handler was entered */
static volatile uint64_t gp_handler_recovered; /* debug: times recovery succeeded */
static volatile uint64_t gp_handler_chained;   /* debug: times chained to kelf */

__attribute__((naked)) static void custom_gp_handler(void)
{
    __asm__(
        /*
         * IST stack frame on #GP entry (error code pushed by CPU):
         *   (%rsp)    = error code
         *   8(%rsp)   = saved RIP
         *   16(%rsp)  = saved CS
         *   24(%rsp)  = saved RFLAGS
         *   32(%rsp)  = saved RSP  (our kthread stack)
         *   40(%rsp)  = saved SS
         *
         * After push rax:
         *   (%rsp)    = saved rax
         *   8(%rsp)   = error code
         *   16(%rsp)  = saved RIP
         *   ...
         */
        "pushq %rax\n\t"

        /* Debug: count handler entries */
        "incq gp_handler_entries(%rip)\n\t"

        /* Check faulting RIP is within our exec_code range */
        "movq 16(%rsp), %rax\n\t"       /* saved RIP */
        "cmpq exec_code_base(%rip), %rax\n\t"
        "jb .Lchain_original\n\t"
        "cmpq exec_code_end(%rip), %rax\n\t"
        "jae .Lchain_original\n\t"

        /* Check recovery is armed */
        "movq gp_recovery_rip(%rip), %rax\n\t"
        "testq %rax, %rax\n\t"
        "jz .Lchain_original\n\t"

        /* Recovery: redirect iretq to our recovery label */
        "movq %rax, 16(%rsp)\n\t"
        "movq $0, gp_recovery_rip(%rip)\n\t"
        "movl $1, gp_faulted(%rip)\n\t"
        "incq gp_handler_recovered(%rip)\n\t"

        /* Restore RSP in the iret frame (back to kthread stack) */
        "movq gp_recovery_rsp(%rip), %rax\n\t"
        "movq %rax, 40(%rsp)\n\t"

        "popq %rax\n\t"
        "addq $8, %rsp\n\t"       /* skip error code */
        "iretq\n\t"

        /* Chain to kstuff's kelf handler for unrelated #GP */
        ".Lchain_original:\n\t"
        "incq gp_handler_chained(%rip)\n\t"
        "popq %rax\n\t"
        "jmpq *orig_gp_handler_addr(%rip)\n\t"
    );
}

/* ===================================================================
 * IDT helpers
 * =================================================================== */

static inline uint64_t idt_gate_get_addr(volatile struct idt_gate *g)
{
    return (uint64_t)g->off_lo |
           ((uint64_t)g->off_mid << 16) |
           ((uint64_t)g->off_hi << 32);
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
     * Read IDT via sidt (always readable)
     * ========================================================= */

    uint16_t idt_limit;
    uint64_t idt_base;
    {
        struct { uint16_t limit; uint64_t base; } __attribute__((packed)) idtr;
        __asm__ volatile("sidt %0" : "=m"(idtr));
        idt_limit = idtr.limit;
        idt_base = idtr.base;
    }

    out[3] = idt_base;
    out[9] = (uint64_t)idt_limit;

    /*
     * out[4] = progress step counter (visible in generic readback)
     * out[5] = last diagnostic value for current step
     * out[6] = secondary diagnostic
     * out[7] = PATCH_LOADER result (written during probing)
     *
     * Steps: 1=sidt, 2=idt179_read, 3=int179_test, 4=idt13_saved,
     *        5=idt_patched, 6=probing, 7=idt_restored, 8=done
     */
    out[4] = 1;  /* step 1: sidt done */

    /* =========================================================
     * Test int 179 (kstuff_memcpy) with a safe copy first
     * ========================================================= */

    /* Read IDT entry 179 to verify it has a handler */
    volatile struct idt_gate *idt179 = (volatile struct idt_gate *)(idt_base + 179 * 16);
    uint64_t int179_handler = idt_gate_get_addr(idt179);
    out[10] = int179_handler;
    out[11] = (uint64_t)idt179->type_attr;
    out[4] = 2;  /* step 2: idt179 read */
    out[5] = int179_handler;

    /* If IDT entry 179 is not present (P bit = bit 7 of type_attr), skip */
    if (!(idt179->type_attr & 0x80)) {
        out32[1] = 0xDEAD;  /* int 179 not present */
        out[287] = 0xdeadbeefcafe0099ULL;
        return 0;
    }

    /* Safe test: copy a known value within our output buffer */
    uint64_t test_val = 0x494E5431373921ULL;  /* "INT179!" */
    kstuff_memcpy(&out[12], &test_val, 8);

    /* Verify the copy worked */
    if (out[12] != test_val) {
        out32[1] = 0xBEEF;  /* int 179 copy failed */
        out[5] = out[12];   /* what we got instead */
        out[287] = 0xdeadbeefcafe0099ULL;
        return 0;
    }
    out[4] = 3;  /* step 3: int179 test passed */

    /* =========================================================
     * Patch IDT entry #13 using int 179 (kelf page tables)
     * ========================================================= */

    volatile struct idt_gate *idt13 = (volatile struct idt_gate *)(idt_base + 13 * 16);

    /* Save current IDT entry 13 (kstuff's kelf handler) */
    struct idt_gate saved_idt13;
    {
        volatile uint8_t *s = (volatile uint8_t *)idt13;
        uint8_t *d = (uint8_t *)&saved_idt13;
        for (int i = 0; i < 16; i++)
            d[i] = s[i];
    }

    orig_gp_handler_addr = idt_gate_get_addr(&saved_idt13);
    out[13] = orig_gp_handler_addr;
    out[14] = (uint64_t)saved_idt13.ist;
    out[4] = 4;  /* step 4: idt13 saved */
    out[5] = orig_gp_handler_addr;

    /* Build our replacement entry: same selector/type/IST, our handler addr */
    struct idt_gate new_idt13 = saved_idt13;
    uint64_t hook_addr = (uint64_t)&custom_gp_handler;
    new_idt13.off_lo  = (uint16_t)(hook_addr);
    new_idt13.off_mid = (uint16_t)(hook_addr >> 16);
    new_idt13.off_hi  = (uint32_t)(hook_addr >> 32);

    out[15] = hook_addr;

    /* Set exec_code range for the handler's RIP check.
     * Only #GP with faulting RIP inside our code gets recovery.
     * Other CPUs' #GP (kstuff syscall hook etc.) chains to kelf. */
    exec_code_base = (uint64_t)&module_start;
    exec_code_end = exec_code_base + 0x1000;  /* generous upper bound */
    out[16] = exec_code_base;
    out[17] = exec_code_end;

    gp_recovery_rip = 0;
    gp_faulted = 0;

    /* Disable interrupts, patch IDT via int 179 */
    __asm__ volatile("cli" ::: "memory");
    kstuff_memcpy((void *)idt13, &new_idt13, 16);
    __asm__ volatile("sti" ::: "memory");

    out[4] = 5;  /* step 5: IDT patched */
    out[5] = hook_addr;

    /* Verify IDT patch took effect by reading back */
    {
        uint64_t readback_addr = idt_gate_get_addr(idt13);
        out[6] = readback_addr;
        if (readback_addr != hook_addr) {
            /* IDT write didn't stick — HV may protect IDT writes.
             * DO NOT probe MSRs (would send #GP to kelf without recovery). */
            out32[1] = 0xF00D;  /* IDT patch failed */
            out[287] = 0xdeadbeefcafe0099ULL;
            return 0;
        }
    }

    /* =========================================================
     * Self-test: trigger a #GP with out-of-range MSR (0xDEAD0000)
     * This MSR is outside the AMD MSRPM bitmap ranges, so rdmsr
     * causes a direct #GP (no hypervisor interception).
     * ========================================================= */

    gp_handler_entries = 0;
    gp_handler_recovered = 0;
    gp_handler_chained = 0;

    out[4] = 0x60;  /* step 0x60: starting #GP self-test */

    int gp_test = safe_rdmsr(0xDEAD0000);
    /* gp_test should be 0 (faulted) if handler works */

    out[4] = 0x61;  /* step 0x61: #GP self-test returned */
    out[5] = (uint64_t)gp_test;
    out[6] = gp_handler_entries;
    out[7] = gp_handler_recovered;

    if (!gp_faulted || gp_handler_recovered == 0) {
        /* Handler didn't fire or didn't recover → something's wrong.
         * Restore IDT and abort. */
        __asm__ volatile("cli" ::: "memory");
        kstuff_memcpy((void *)idt13, &saved_idt13, 16);
        __asm__ volatile("sti" ::: "memory");

        out32[1] = 0xFA17;  /* "FAIL" - #GP handler test failed */
        out[287] = 0xdeadbeefcafe0099ULL;
        return 0;
    }

    out[4] = 6;  /* step 6: #GP handler verified, starting probes */

    /* =========================================================
     * MSR probing
     * ========================================================= */

    int total_probed = 0;
    int total_read_ok = 0;
    int total_write_ok = 0;
    int result_idx = 24;  /* start results at out[24] */

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

        out[21] = ((uint64_t)rd << 32) | (uint64_t)wr;
        out[22] = rd_val;
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
     * Restore IDT entry #13 (kstuff's kelf handler) via int 179
     * ========================================================= */

    out[4] = 7;  /* step 7: probing done, restoring IDT */

    __asm__ volatile("cli" ::: "memory");
    kstuff_memcpy((void *)idt13, &saved_idt13, 16);
    __asm__ volatile("sti" ::: "memory");

    /* =========================================================
     * Write summary
     * ========================================================= */

    out[18] = (uint64_t)total_probed;
    out[19] = (uint64_t)total_read_ok;
    out[20] = (uint64_t)total_write_ok;

    out[4] = 8;  /* step 8: complete */
    out[5] = (uint64_t)total_probed;
    out[6] = (uint64_t)total_read_ok;
    out[7] = (uint64_t)total_write_ok;

    out32[1] = 0x0001;  /* success */
    out[287] = 0xdeadbeefcafe0099ULL;

    return 0;
}
