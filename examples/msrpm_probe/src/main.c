/*
 * msrpm_probe — PS5 HV MSRPM (MSR Protection Map) scanner
 *
 * Probes which MSRs the hypervisor intercepts vs. allows from guest ring 0.
 * Uses pcb_onfault to safely catch #GP faults on intercepted MSRs.
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
 * Sources:
 *   - EntrySign: https://github.com/google/security-research/security/advisories/GHSA-4xq7-4mgh-gp6w
 *   - zentool: https://github.com/google/security-research/blob/master/pocs/cpus/entrysign/zentool/README.md
 *   - PS5 MSRPM: https://www.psdevwiki.com/ps5/Hypervisor
 *   - Partial dump: https://gist.github.com/Cryptogenic/83235b4cf4315500cb3146ed6d978ad0
 *   - IBS leak: https://googleprojectzero.blogspot.com/2021/06/an-epyc-escape-case-study-of-kvm.html
 *   - AMD SVM MSRPM: http://www.0x04.net/doc/amd/33047.pdf (three ranges: 0-0x1FFF, 0xC0000000-0xC0001FFF, 0xC0010000-0xC0011FFF)
 *
 * Kldload kernel module — runs as kthread in ring 0.
 * Output via kthread_args readback buffer (2304 bytes = 288 uint64_t slots).
 */

#include <stdint.h>

/* ===================================================================
 * Offsets (FW 4.03, confirmed)
 * =================================================================== */
#define TD_PCB        0x3f8
#define PCB_ONFAULT   0x108

/* ===================================================================
 * MSR access primitives
 * =================================================================== */

static inline uint64_t do_rdmsr(uint32_t msr)
{
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static inline void do_wrmsr(uint32_t msr, uint64_t val)
{
    uint32_t lo = (uint32_t)val;
    uint32_t hi = (uint32_t)(val >> 32);
    __asm__ volatile("wrmsr" : : "c"(msr), "a"(lo), "d"(hi));
}

/* ===================================================================
 * pcb_onfault-based safe MSR probing
 *
 * When the HV intercepts an MSR access, it injects #GP into the guest.
 * pcb_onfault catches this: kernel's trap handler checks onfault before
 * panicking and jumps to recovery if set.
 *
 * This is the same mechanism used in pivot_scan_safe for safe memory reads.
 * =================================================================== */

static volatile uint64_t saved_rsp_msr;
static volatile uint64_t onfault_ptr_msr;  /* &(td_pcb->pcb_onfault) */
static volatile int msr_fault_flag;
static volatile uint64_t msr_read_val;

/*
 * Try to read an MSR. Returns 1 on success, 0 on #GP.
 * Value stored in msr_read_val on success.
 */
static int safe_rdmsr(uint32_t msr)
{
    msr_fault_flag = 0;
    msr_read_val = 0;

    __asm__ volatile(
        /* Arm pcb_onfault with recovery label */
        "movq onfault_ptr_msr(%%rip), %%r14\n\t"
        "leaq 2f(%%rip), %%rcx\n\t"
        "movq %%rcx, (%%r14)\n\t"           /* pcb_onfault = &recovery */
        "movq %%rsp, saved_rsp_msr(%%rip)\n\t"

        /* Attempt rdmsr (ecx already set by constraint) */
        "rdmsr\n\t"

        /* Success: combine edx:eax → 64-bit and store */
        "shlq $32, %%rdx\n\t"
        "orq %%rax, %%rdx\n\t"
        "movq %%rdx, msr_read_val(%%rip)\n\t"

        /* Clear onfault */
        "movq onfault_ptr_msr(%%rip), %%r14\n\t"
        "movq $0, (%%r14)\n\t"
        "jmp 1f\n\t"

        /* Fault recovery (label 2) — #GP lands here */
        "2:\n\t"
        "movq saved_rsp_msr(%%rip), %%rsp\n\t"
        "movl $1, msr_fault_flag(%%rip)\n\t"

        "1:\n\t"
        :
        : "c"(msr)
        : "rax", "rdx", "r14", "memory", "cc"
    );

    return msr_fault_flag == 0;
}

/*
 * Try to write an MSR. Returns 1 on success, 0 on #GP.
 * For PATCH_LOADER (0xC0010020), we write a dummy value first (address 0)
 * to test if the write is intercepted without actually loading microcode.
 *
 * IMPORTANT: A successful wrmsr to 0xC0010020 with address=0 should be
 * harmless (no valid microcode header at address 0). But to be safe,
 * the write_test_val should be chosen carefully.
 */
static int safe_wrmsr(uint32_t msr, uint64_t val)
{
    msr_fault_flag = 0;

    uint32_t lo = (uint32_t)val;
    uint32_t hi = (uint32_t)(val >> 32);

    __asm__ volatile(
        /* Arm pcb_onfault */
        "movq onfault_ptr_msr(%%rip), %%r14\n\t"
        "leaq 2f(%%rip), %%rcx\n\t"
        "movq %%rcx, (%%r14)\n\t"
        "movq %%rsp, saved_rsp_msr(%%rip)\n\t"

        /* Restore ecx for MSR number (clobbered by leaq above) */
        "movl %[msrnum], %%ecx\n\t"

        /* Attempt wrmsr */
        "wrmsr\n\t"

        /* Success — clear onfault */
        "movq onfault_ptr_msr(%%rip), %%r14\n\t"
        "movq $0, (%%r14)\n\t"
        "jmp 1f\n\t"

        /* Fault recovery */
        "2:\n\t"
        "movq saved_rsp_msr(%%rip), %%rsp\n\t"
        "movl $1, msr_fault_flag(%%rip)\n\t"

        "1:\n\t"
        :
        : "a"(lo), "d"(hi), [msrnum] "r"(msr)
        : "ecx", "r14", "memory", "cc"
    );

    return msr_fault_flag == 0;
}

/* ===================================================================
 * Result encoding
 *
 * Each probed MSR gets a 32-bit result packed as:
 *   [31:16] = MSR number (low 16 bits — sufficient for ranges we probe)
 *   [15:12] = reserved
 *   [11:8]  = write result (0=GP, 1=OK, 2=skipped)
 *   [7:4]   = read result  (0=GP, 1=OK)
 *   [3:0]   = MSR range id (0=AMD_specific, 1=IBS, 2=MTRR, 3=EFER_range)
 * =================================================================== */

#define RESULT(msr_lo, wr, rd, range) \
    (((uint32_t)(msr_lo) << 16) | ((wr) << 8) | ((rd) << 4) | (range))

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

    /* Get curthread and PCB */
    uint64_t curthread;
    __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
    uint64_t td_pcb = *(volatile uint64_t*)(curthread + TD_PCB);

    /* Set up onfault pointer */
    onfault_ptr_msr = td_pcb + PCB_ONFAULT;

    /* Clear output buffer */
    for (int i = 0; i < 288; i++)
        out[i] = 0;

    /* Write header */
    out32[0] = 0x4D535250;  /* "MSRP" */
    out32[1] = 0xAAAA;      /* in-progress */
    out[1] = kdata_base;
    out[2] = curthread;
    out[3] = td_pcb;

    /*
     * Slot layout:
     *   [0]     magic | status
     *   [1]     kdata_base
     *   [2]     curthread
     *   [3]     td_pcb
     *   [4]     total MSRs probed
     *   [5]     total READ_OK
     *   [6]     total WRITE_OK
     *   [7]     MSR 0xC0010020 result (THE KEY RESULT)
     *   [8]     MSR 0xC0010020 read value (if readable)
     *   [9-15]  reserved
     *   [16..] result entries (packed as uint32_t pairs in uint64_t slots)
     */

    int total_probed = 0;
    int total_read_ok = 0;
    int total_write_ok = 0;
    int result_idx = 16;  /* Start writing results at slot 16 */

    /* Helper to record a result */
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
     *
     * This is THE critical test. If writable, we can load custom
     * microcode on this Zen 2 CPU and neuter the hypervisor.
     * ================================================================= */

    {
        uint32_t msr = 0xC0010020;
        int rd = safe_rdmsr(msr);
        uint64_t rd_val = rd ? msr_read_val : 0;

        /*
         * For the write test, use value 0 (null pointer).
         * Even if the write succeeds, address 0 won't contain a valid
         * microcode patch header, so the CPU should reject the update
         * at the microcode validation stage (after signature check).
         *
         * If #GP → HV intercepted the wrmsr → EntrySign blocked
         * If no #GP → write reached the CPU → EntrySign is viable
         */
        int wr = safe_wrmsr(msr, 0);

        out[7] = ((uint64_t)rd << 32) | (uint64_t)wr;
        out[8] = rd_val;

        RECORD_RESULT(msr, rd, wr, rd_val);
    }

    /* =================================================================
     * PRIORITY 2: Nearby AMD-specific MSRs (0xC0010000-0xC001003F)
     *
     * These are in the MSRPM's third range but NOT in the public dump.
     * Any unprotected MSR here is interesting.
     * ================================================================= */

    for (uint32_t msr = 0xC0010000; msr <= 0xC001003F; msr++) {
        if (msr == 0xC0010020) continue;  /* Already probed above */

        int rd = safe_rdmsr(msr);
        uint64_t rd_val = rd ? msr_read_val : 0;

        /* Only test writes on selected interesting MSRs */
        int wr = 0;
        if (msr == 0xC0010010 ||  /* SYSCFG */
            msr == 0xC0010015 ||  /* HWCR */
            msr == 0xC0010030 ||  /* CPU_NAME_STRING */
            msr == 0xC001001F) {  /* NB_CFG */
            /* Read-back write: write the same value we just read */
            if (rd)
                wr = safe_wrmsr(msr, rd_val);
            else
                wr = 2;  /* skipped — can't read-back */
        } else {
            wr = 2;  /* skipped */
        }

        RECORD_RESULT(msr, rd, wr, rd_val);
    }

    /* =================================================================
     * PRIORITY 3: IBS MSRs (0xC0011030-0xC001103B)
     *
     * Project Zero used IBS to leak host physical addresses in KVM escape.
     * IBS doesn't respect virtualization context — physical addresses
     * returned are always HPAs (host physical), not GPAs.
     * If readable, these could leak HV memory layout.
     * ================================================================= */

    for (uint32_t msr = 0xC0011030; msr <= 0xC001103B; msr++) {
        int rd = safe_rdmsr(msr);
        uint64_t rd_val = rd ? msr_read_val : 0;
        RECORD_RESULT(msr, rd, 2, rd_val);  /* write skipped */
    }

    /* =================================================================
     * PRIORITY 4: EFER / STAR / LSTAR / CSTAR / SFMASK
     * (0xC0000080-0xC0000084)
     *
     * EFER is known to be "masked" (not #GP, but bits silently dropped).
     * Verify this and check STAR/LSTAR write behavior.
     * ================================================================= */

    for (uint32_t msr = 0xC0000080; msr <= 0xC0000084; msr++) {
        int rd = safe_rdmsr(msr);
        uint64_t rd_val = rd ? msr_read_val : 0;

        int wr = 2;  /* skipped by default */
        if (msr == 0xC0000080) {
            /* EFER: try writing current value with bit 16 (xotext) flipped */
            if (rd) {
                uint64_t test_val = rd_val ^ (1ULL << 16);
                wr = safe_wrmsr(msr, test_val);
                /* Read back to see if the bit actually changed */
                if (wr) {
                    int rd2 = safe_rdmsr(msr);
                    if (rd2) {
                        uint64_t new_val = msr_read_val;
                        /* Store the delta in the next slot */
                        if (result_idx < 280) {
                            out[result_idx] = new_val;
                            result_idx++;
                        }
                        /* Restore original EFER */
                        safe_wrmsr(msr, rd_val);
                    }
                }
            }
        }

        RECORD_RESULT(msr, rd, wr, rd_val);
    }

    /* =================================================================
     * PRIORITY 5: MTRR MSRs (0x200-0x277)
     * Confirmed unprotected for read in partial MSRPM dump.
     * Check write access — MTRRs control memory caching attributes.
     * ================================================================= */

    /* Just probe a few key MTRRs, not all 120 */
    uint32_t mtrr_msrs[] = {
        0x200, 0x201,  /* MTRR_PHYSBASE0/MASK0 */
        0x250,         /* MTRR_FIX64K_00000 */
        0x258, 0x259,  /* MTRR_FIX16K */
        0x268, 0x269,  /* MTRR_FIX4K */
        0x277,         /* last in range */
        0x2FF,         /* MTRR_DEF_TYPE (also unprotected per dump) */
    };

    for (int i = 0; i < (int)(sizeof(mtrr_msrs)/sizeof(mtrr_msrs[0])); i++) {
        uint32_t msr = mtrr_msrs[i];
        int rd = safe_rdmsr(msr);
        uint64_t rd_val = rd ? msr_read_val : 0;

        /* Test write with read-back value (safe — no functional change) */
        int wr = 2;
        if (rd)
            wr = safe_wrmsr(msr, rd_val);

        RECORD_RESULT(msr, rd, wr, rd_val);
    }

    /* =================================================================
     * PRIORITY 6: VM_HSAVE_PA (0xC0010117)
     * Controls where host state is saved during VMRUN.
     * If writable from guest, it's a direct HV escape vector.
     * (Almost certainly intercepted, but worth checking.)
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
     * PMC not properly virtualized until Zen 5.
     * On Zen 2, may leak cross-VM information.
     * ================================================================= */

    uint32_t perf_msrs[] = {
        0xC0010200,  /* PERF_CTL0 */
        0xC0010201,  /* PERF_CTR0 */
        0xC0010202,  /* PERF_CTL1 */
        0xC0010203,  /* PERF_CTR1 */
        0xC0010204,  /* PERF_CTL2 */
        0xC0010205,  /* PERF_CTR2 */
    };

    for (int i = 0; i < (int)(sizeof(perf_msrs)/sizeof(perf_msrs[0])); i++) {
        uint32_t msr = perf_msrs[i];
        int rd = safe_rdmsr(msr);
        uint64_t rd_val = rd ? msr_read_val : 0;
        RECORD_RESULT(msr, rd, 2, rd_val);
    }

    /* =================================================================
     * Write summary
     * ================================================================= */

    out[4] = (uint64_t)total_probed;
    out[5] = (uint64_t)total_read_ok;
    out[6] = (uint64_t)total_write_ok;

    /* Completion */
    out32[1] = 0x0001;  /* success */
    out[287] = 0xdeadbeefcafe0099ULL;  /* sentinel */

    return 0;
}
