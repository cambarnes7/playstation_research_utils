#include <stdint.h>

/*
 * PS5 Suspend Register Capture (kstuff payload)
 *
 * TWO PHASES in one payload:
 *
 * Phase 1 — REGISTER CAPTURE (normal operation):
 *   Hooks apic_ops[2] with a kdata capture stub.
 *   Waits ~200ms for natural kernel calls to apic_ops[2].
 *   Captures up to 4 full register snapshots (RAX-R15, RSP, RFLAGS).
 *   Restores original apic_ops[2] when done capturing.
 *
 * Phase 2 — SUSPEND ARMING:
 *   Overwrites apic_ops[2] with nop_ret (ktext, safe).
 *   Writes sentinel markers to kdata for post-resume verification.
 *   User enters rest mode after this completes.
 *   After resume: run this payload again (or KTST restore mode) to check state.
 *
 * The register captures from Phase 1 tell us what the CPU state looks like
 * when apic_ops[2] is called. Key info for stack pivot selection:
 *   - Which register holds a pointer to apic_ops table (PIVOT CANDIDATE)
 *   - Which registers hold ktext/kdata/kernel heap pointers
 *   - Which registers are stable across calls
 *
 * Output layout (uint64_t indices):
 *   [0]   magic(32) "SRCP" | status(32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   apic_ops_addr
 *   [4]   orig_xapic_mode
 *   [5]   capture_count(32) | hooked_slot(32)
 *   [6..33]  apic_ops table dump (28 slots)
 *   [34]  nop_ret_addr
 *   [35]  capture_stub_addr
 *   [36..103] register captures: 4 × 17 uint64_t
 *             each capture: RAX,RBX,RCX,RDX,RSI,RDI,RBP,R8-R15,RSP,RFLAGS
 *   [104] sentinel = 0xdeadbeefcafe0005
 *   [105..120] kdata suspend markers (16 values for post-resume check)
 *   [121] second_sentinel = 0xfeedface00000005
 *   [122] apic_ops[2] armed value (nop_ret or restore target)
 *   [123] apic_ops[2] readback after arming
 */

#define MAGIC_SRCP       0x53524350  /* "SRCP" */

/* FW 4.03 offsets */
#define APIC_OPS_OFF_FROM_KTEXT  0x1934AC8
#define OFF_NOP_RET       (-0x9d20ca)  /* just 'ret' in ktext */

#define MAX_CAPTURES 4

typedef struct {
    uint64_t kdata_base;
    uint32_t fw_ver;
} kproc_args;

/* ── Global state for capture stub ── */
static volatile uint64_t orig_func;
static volatile uint32_t cap_count;
static volatile uint64_t caps[MAX_CAPTURES][17]; /* 16 regs + rflags */

/*
 * capture_stub: naked function that intercepts apic_ops[2] calls.
 *
 * When the kernel calls apic_ops[2], execution comes here.
 * We save all 16 GP registers + RFLAGS into caps[cap_count],
 * increment cap_count, then tail-call the original function
 * so the kernel gets the expected return value.
 *
 * This runs from kdata (NX cleared by kldload) during normal operation.
 * It will NOT work during suspend (kdata is NX during suspend).
 */
__attribute__((naked, used))
static void capture_stub(void)
{
    __asm__ volatile(
        /* Save two scratch regs + flags */
        "pushq %%rax\n\t"
        "pushq %%rbx\n\t"
        "pushfq\n\t"

        /* Check if we have room */
        "leaq cap_count(%%rip), %%rax\n\t"
        "movl (%%rax), %%eax\n\t"
        "cmpl %[max_cap], %%eax\n\t"
        "jge 2f\n\t"         /* skip capture if full */

        /* RBX = &caps[cap_count] = caps + cap_count * 136 */
        "leaq caps(%%rip), %%rbx\n\t"
        "movl %%eax, %%eax\n\t"        /* zero-extend */
        "imulq $136, %%rax, %%rax\n\t" /* 17 * 8 = 136 */
        "addq %%rax, %%rbx\n\t"

        /* Save registers. Stack is: [rflags][rbx_orig][rax_orig][ret_addr]... */

        /* Recover original RAX (3rd from top: skip rflags+rbx = 16 bytes) */
        "movq 16(%%rsp), %%rax\n\t"
        "movq %%rax, 0*8(%%rbx)\n\t"   /* caps[n][0] = RAX */

        /* Recover original RBX (2nd from top: skip rflags = 8 bytes) */
        "movq 8(%%rsp), %%rax\n\t"
        "movq %%rax, 1*8(%%rbx)\n\t"   /* caps[n][1] = RBX */

        "movq %%rcx, 2*8(%%rbx)\n\t"   /* RCX */
        "movq %%rdx, 3*8(%%rbx)\n\t"   /* RDX */
        "movq %%rsi, 4*8(%%rbx)\n\t"   /* RSI */
        "movq %%rdi, 5*8(%%rbx)\n\t"   /* RDI */
        "movq %%rbp, 6*8(%%rbx)\n\t"   /* RBP */
        "movq %%r8,  7*8(%%rbx)\n\t"   /* R8  */
        "movq %%r9,  8*8(%%rbx)\n\t"   /* R9  */
        "movq %%r10, 9*8(%%rbx)\n\t"   /* R10 */
        "movq %%r11, 10*8(%%rbx)\n\t"  /* R11 */
        "movq %%r12, 11*8(%%rbx)\n\t"  /* R12 */
        "movq %%r13, 12*8(%%rbx)\n\t"  /* R13 */
        "movq %%r14, 13*8(%%rbx)\n\t"  /* R14 */
        "movq %%r15, 14*8(%%rbx)\n\t"  /* R15 */

        /* RSP at entry = current RSP + 24 (we pushed rax+rbx+rflags = 3*8) */
        "leaq 24(%%rsp), %%rax\n\t"
        "movq %%rax, 15*8(%%rbx)\n\t"  /* RSP */

        /* RFLAGS (top of stack) */
        "movq (%%rsp), %%rax\n\t"
        "movq %%rax, 16*8(%%rbx)\n\t"  /* RFLAGS */

        /* Increment capture count */
        "leaq cap_count(%%rip), %%rax\n\t"
        "incl (%%rax)\n\t"

        "2:\n\t"
        /* Restore flags and scratch regs */
        "popfq\n\t"
        "popq %%rbx\n\t"
        "popq %%rax\n\t"

        /* Tail-call original function (preserves all regs + return addr) */
        "jmpq *orig_func(%%rip)\n\t"
        :
        : [max_cap] "i"(MAX_CAPTURES)
        : "memory"
    );
}

static inline uint64_t rdmsr(uint32_t msr)
{
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

/* Busy-wait delay. ~200ms at typical PS5 clock speeds. */
static void delay_ms(uint64_t ms)
{
    /* pause is ~10-140 cycles; at ~3GHz, 3M cycles/ms.
     * With pause ~40 cycles avg: ~75K iters/ms */
    volatile uint64_t count = ms * 75000;
    while (count--) {
        __asm__ volatile("pause");
    }
}

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    volatile uint64_t* out = (volatile uint64_t*)args;
    volatile uint32_t* out32 = (volatile uint32_t*)args;

    /* Zero output (fit within 4KB kthread_args allocation) */
    for (int i = 0; i < 124; i++)
        out[i] = 0;

    /* Compute addresses */
    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;
    uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFF_FROM_KTEXT;
    uint64_t nop_ret = kdata_base + OFF_NOP_RET;

    volatile uint64_t* apic_table = (volatile uint64_t*)apic_ops_addr;

    /* Write header */
    out32[0] = MAGIC_SRCP;
    out32[1] = 0;           /* status: initializing */
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = apic_ops_addr;

    /* Save original xapic_mode pointer */
    uint64_t original = apic_table[2];
    out[4] = original;

    /* Dump full apic_ops table (28 slots) */
    for (int i = 0; i < 28; i++)
        out[6 + i] = apic_table[i];

    out[34] = nop_ret;
    out[35] = (uint64_t)capture_stub;

    /* Initialize capture state */
    orig_func = original;
    cap_count = 0;
    for (int i = 0; i < MAX_CAPTURES; i++)
        for (int j = 0; j < 17; j++)
            caps[i][j] = 0;

    /* ════════════════════════════════════════════
     * PHASE 1: REGISTER CAPTURE
     *
     * Hook apic_ops[2] → capture_stub (kdata, executable).
     * Wait for natural kernel calls. Each call captures
     * the full register snapshot, then tail-calls the original.
     * ════════════════════════════════════════════ */
    out32[1] = 0xAAAA;  /* status: capturing */

    /* Install capture hook */
    apic_table[2] = (uint64_t)capture_stub;

    /* Wait ~200ms for natural kernel calls */
    delay_ms(200);

    /* Unhook — restore original to stop capturing */
    apic_table[2] = original;

    /* Copy capture count + results to output */
    uint32_t count = cap_count;
    out32[10] = count;          /* [5] low 32: capture_count */
    out32[11] = 2;              /* [5] high 32: hooked_slot = 2 */

    for (uint32_t c = 0; c < count && c < MAX_CAPTURES; c++)
        for (int r = 0; r < 17; r++)
            out[36 + c * 17 + r] = caps[c][r];

    /* ════════════════════════════════════════════
     * PHASE 2: ARM FOR SUSPEND
     *
     * Overwrite apic_ops[2] with nop_ret (ktext address).
     * Write sentinel markers to kdata for post-resume check.
     *
     * After this completes:
     *   1. User enters rest mode (suspend)
     *   2. Kernel calls apic_ops[2] during suspend → hits nop_ret → safe return
     *   3. Resume from rest mode
     *   4. Run reader payload to verify kdata markers + apic_ops state
     * ════════════════════════════════════════════ */

    /* Write sentinel markers to kdata */
    for (int i = 0; i < 16; i++)
        out[105 + i] = 0xDEAD000000000000ULL | (uint64_t)(i + 1);

    out[121] = 0xfeedface00000005ULL;

    /* Arm apic_ops[2] with nop_ret */
    apic_table[2] = nop_ret;

    /* Verify write */
    uint64_t readback = apic_table[2];
    out[122] = nop_ret;     /* what we wrote */
    out[123] = readback;    /* what we read back */

    if (readback == nop_ret) {
        out32[1] = 1;       /* status: armed for suspend */
    } else {
        apic_table[2] = original;  /* restore on failure */
        out32[1] = 0xFF;   /* status: error */
    }

    out[104] = 0xdeadbeefcafe0005ULL;  /* sentinel */

    return 0;
}
