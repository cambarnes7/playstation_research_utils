/*
 * msrpm_probe — PS5 HV MSR accessibility scanner
 *
 * Reads MSRs directly via rdmsr (no IDT patching needed).
 * The PS5 hypervisor intercepts all rdmsr via #VMEXIT:
 *   - Emulated MSRs: rdmsr succeeds, value returned
 *   - Blocked MSRs:  HV terminates the VM (no #GP injected)
 *
 * Strategy: read known-safe MSRs first (EFER, LSTAR, etc.),
 * store results after each read. Try target MSR (PATCH_LOADER)
 * LAST. If the VM dies, readback still has all previous results
 * and out[4] shows which MSR killed the VM.
 *
 * CRITICAL TARGET: MSR 0xC0010020 (AMD PATCH_LOADER)
 *   If writable → EntrySign (CVE-2024-56161) is viable on PS5
 *
 * Kldload kernel module — runs as kthread in ring 0.
 * Output via kthread_args readback buffer (2304 bytes = 288 uint64_t slots).
 *
 * Output layout (generic readback shows out[0]-out[7]):
 *   out[0]  = magic "MSRP" (low32) | status (high32)
 *   out[1]  = kdata_base
 *   out[2]  = curthread
 *   out[3]  = MSRs successfully read (count)
 *   out[4]  = last MSR attempted (if VM dies, this is the killer)
 *   out[5]  = last MSR value read
 *   out[6]  = PATCH_LOADER result: 0=not reached, 1=readable, 2=writable
 *   out[7]  = PATCH_LOADER value (if readable)
 *
 *   out[8..N] = per-MSR results: [MSR_NUM | flags], [value if readable]
 */

#include <stdint.h>

/* ===================================================================
 * Inline rdmsr/wrmsr — direct execution, no fault recovery
 * =================================================================== */

static inline uint64_t rdmsr(uint32_t msr)
{
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static inline void wrmsr(uint32_t msr, uint64_t val)
{
    uint32_t lo = (uint32_t)val;
    uint32_t hi = (uint32_t)(val >> 32);
    __asm__ volatile("wrmsr" : : "c"(msr), "a"(lo), "d"(hi));
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

    int count = 0;        /* MSRs successfully read */
    int result_idx = 8;   /* results start at out[8] */

    /*
     * Macro: attempt rdmsr, store result, update visible progress.
     * If the HV kills us, out[4] shows which MSR and out[3] shows
     * how many succeeded before it.
     */
    #define TRY_RDMSR(msr_num) do { \
        out[4] = (uint64_t)(msr_num); \
        uint64_t _val = rdmsr(msr_num); \
        out[5] = _val; \
        if (result_idx < 280) { \
            out[result_idx++] = ((uint64_t)(msr_num) << 32) | 0x01; \
            out[result_idx++] = _val; \
        } \
        count++; \
        out[3] = (uint64_t)count; \
    } while(0)

    /* =========================================================
     * TIER 1: Guaranteed-safe MSRs (kernel uses these normally)
     * ========================================================= */

    TRY_RDMSR(0xC0000080);  /* EFER */
    TRY_RDMSR(0xC0000081);  /* STAR */
    TRY_RDMSR(0xC0000082);  /* LSTAR */
    TRY_RDMSR(0xC0000083);  /* CSTAR */
    TRY_RDMSR(0xC0000084);  /* SFMASK */
    TRY_RDMSR(0xC0000100);  /* FSBASE */
    TRY_RDMSR(0xC0000101);  /* GSBASE */
    TRY_RDMSR(0xC0000102);  /* KGSBASE */
    TRY_RDMSR(0x0000001B);  /* APIC_BASE */

    /* =========================================================
     * TIER 2: AMD MSRs read by state_capture module
     * ========================================================= */

    TRY_RDMSR(0xC0010010);  /* SYSCFG */
    TRY_RDMSR(0xC001001D);  /* TOP_MEM */
    TRY_RDMSR(0xC001001E);  /* TOP_MEM2 */
    TRY_RDMSR(0xC0010114);  /* VM_CR */
    TRY_RDMSR(0xC0010117);  /* VM_HSAVE_PA */

    /* =========================================================
     * TIER 3: Common AMD MSRs (might work, might kill VM)
     * ========================================================= */

    TRY_RDMSR(0xC0010015);  /* HWCR */
    TRY_RDMSR(0xC0010111);  /* SMM_BASE */
    TRY_RDMSR(0xC0010112);  /* SMM_ADDR */
    TRY_RDMSR(0xC0010113);  /* SMM_MASK */
    TRY_RDMSR(0xC0010140);  /* OSVW_ID_LEN */
    TRY_RDMSR(0xC0010141);  /* OSVW_STATUS */

    /* Microcode version (read-only, should be safe) */
    TRY_RDMSR(0xC0010021);  /* PATCH_LEVEL — microcode revision */

    /* =========================================================
     * TIER 4: MTRR and other architectural MSRs
     * ========================================================= */

    TRY_RDMSR(0x00000277);  /* PAT */
    TRY_RDMSR(0x000002FF);  /* MTRR_DEF_TYPE */
    TRY_RDMSR(0x000000FE);  /* MTRR_CAP */
    TRY_RDMSR(0x00000200);  /* MTRR_PHYS_BASE0 */
    TRY_RDMSR(0x00000201);  /* MTRR_PHYS_MASK0 */
    TRY_RDMSR(0x00000250);  /* MTRR_FIX64K */
    TRY_RDMSR(0x00000174);  /* SYSENTER_CS */
    TRY_RDMSR(0x00000175);  /* SYSENTER_ESP */
    TRY_RDMSR(0x00000176);  /* SYSENTER_EIP */

    /* =========================================================
     * TIER 5: Performance counters (likely intercepted)
     * ========================================================= */

    TRY_RDMSR(0xC0010200);  /* PERF_CTL0 */
    TRY_RDMSR(0xC0010201);  /* PERF_CTR0 */
    TRY_RDMSR(0xC0010202);  /* PERF_CTL1 */
    TRY_RDMSR(0xC0010203);  /* PERF_CTR1 */

    /* =========================================================
     * TIER 6: IBS MSRs (Instruction-Based Sampling)
     * ========================================================= */

    TRY_RDMSR(0xC0011030);  /* IBS_FETCH_CTL */
    TRY_RDMSR(0xC0011031);  /* IBS_FETCH_LINADDR */
    TRY_RDMSR(0xC0011032);  /* IBS_FETCH_PHYSADDR */
    TRY_RDMSR(0xC0011033);  /* IBS_OP_CTL */
    TRY_RDMSR(0xC0011034);  /* IBS_OP_RIP */
    TRY_RDMSR(0xC0011035);  /* IBS_OP_DATA */

    /* =========================================================
     * TIER 7: THE TARGET — PATCH_LOADER (EntrySign)
     * This is LAST because it's most likely to kill the VM.
     * If we get here, out[3] already has all tier 1-6 results.
     * ========================================================= */

    out[4] = 0xC0010020;  /* mark: attempting PATCH_LOADER */

    uint64_t patch_loader_val = rdmsr(0xC0010020);

    /* If we survived, PATCH_LOADER is readable! */
    out[6] = 1;  /* readable */
    out[7] = patch_loader_val;

    if (result_idx < 280) {
        out[result_idx++] = ((uint64_t)0xC0010020 << 32) | 0x01;
        out[result_idx++] = patch_loader_val;
    }
    count++;
    out[3] = (uint64_t)count;
    out[5] = patch_loader_val;

    /* Try writing PATCH_LOADER (the real EntrySign test) */
    out[4] = 0xC0010020 | (1ULL << 48);  /* mark: attempting WRMSR */

    wrmsr(0xC0010020, 0);  /* write zero (safe: just clears load request) */

    /* If we survived, PATCH_LOADER is writable! */
    out[6] = 2;  /* writable */

    /* Read back to confirm */
    uint64_t readback_val = rdmsr(0xC0010020);
    if (result_idx < 280) {
        out[result_idx++] = ((uint64_t)0xC0010020 << 32) | 0x03;
        out[result_idx++] = readback_val;
    }

    /* =========================================================
     * Done
     * ========================================================= */

    out32[1] = 0x0001;  /* success */
    out[287] = 0xdeadbeefcafe0099ULL;

    return 0;
}
