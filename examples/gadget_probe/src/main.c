#include <stdint.h>

/*
 * PS5 Gadget Probe (kstuff payload)
 *
 * Blind gadget discovery for ktext. Tests a single candidate address
 * per run to determine what instruction bytes are there.
 *
 * Two probe modes:
 *
 * MODE 0 — "pop_ret" probe:
 *   Tests if candidate_addr is a `pop REG; ret` (2 bytes: XX C3).
 *   Sets up a known stack: [marker_value, nop_ret].
 *   Calls candidate via ROP: ret → candidate → pops marker into REG → ret → nop_ret → resume.
 *   After resume, reads all registers to see which one got the marker.
 *   Result: which register the pop targets (or "not a pop;ret").
 *
 * MODE 1 — "pivot" probe:
 *   Tests if candidate_addr is `xchg rsp, rax; ret` or `push rax; pop rsp; ret`.
 *   Sets RAX = address of a chain buffer [nop_ret, nop_ret, resume_addr].
 *   Calls candidate via ROP.
 *   If pivot: RSP swaps to chain buffer → chains through nop_rets → hits resume.
 *   If not pivot: candidate does something else → likely thread dies or takes wrong path.
 *   We use two distinct resume points to distinguish pivot vs normal return.
 *
 * Configuration (change these #defines and rebuild):
 *   PROBE_MODE:   0 = pop_ret, 1 = pivot
 *   TARGET_OFFSET: offset from kdata_base (negative = ktext)
 *
 * Output layout (uint64_t indices):
 *   [0]  magic(32) "GPRB" | status(32)
 *   [1]  kdata_base
 *   [2]  ktext_base
 *   [3]  candidate_addr
 *   [4]  probe_mode(32) | result_code(32)
 *   [5]  captured register that got the marker (mode 0)
 *        OR pivot_detected flag (mode 1)
 *   [6..21] all 16 captured register values
 *
 * Result codes:
 *   0 = not started
 *   0xAAAA = in progress (thread died)
 *   1 = completed, check register captures
 *   2 = pivot detected (mode 1 only)
 */

/* ═══ CONFIGURATION — CHANGE THESE (or override via -D flags) ═══ */
#ifndef PROBE_MODE
#define PROBE_MODE     0            /* 0=pop_ret, 1=pivot */
#endif
#ifndef TARGET_OFFSET
#define TARGET_OFFSET  (-0x9cf991)  /* default: justreturn-1 */
#endif
/* ════════════════════════════════════════════════════════════════ */

#define MAGIC_GPRB       0x47505242  /* "GPRB" */
#define STATUS_NONE      0x0000
#define STATUS_TRYING    0xAAAA
#define STATUS_DONE      0x0001
#define STATUS_PIVOT     0x0002

/* FW 4.03 offsets */
#define OFF_WRMSR_RET     (-0x9d20cc)
#define OFF_NOP_RET       (OFF_WRMSR_RET + 2)

#define MARKER_VALUE     0xBEEF0000CAFE4242ULL

typedef struct {
    uint64_t kdata_base;
    uint32_t fw_ver;
} kproc_args;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t status;
    uint64_t kdata_base;
    uint64_t ktext_base;
    uint64_t candidate_addr;
    uint32_t probe_mode;
    uint32_t result_code;
    uint64_t marker_reg_id;  /* which register got the marker (mode 0) */
    uint64_t regs[16];       /* rax,rbx,rcx,rdx,rsi,rdi,rbp,r8..r15,rsp */
} probe_result_t;

static inline uint64_t rdmsr(uint32_t msr)
{
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

/* ── Probe data ── */
static volatile uint64_t saved_regs[16];
static volatile uint64_t saved_rsp;
static volatile uint64_t resume_normal;  /* resume if candidate returned normally */
static volatile uint64_t resume_pivot;   /* resume if pivot was detected */
static volatile uint64_t got_pivot;      /* set to 1 if pivot path taken */

/*
 * capture_stub: naked function placed after the candidate returns.
 * Saves all register values, restores RSP, jumps to resume_normal.
 */
__attribute__((naked, used))
static void capture_stub(void)
{
    __asm__ volatile(
        "pushq %%rax\n\t"
        "pushq %%rbx\n\t"

        "leaq saved_regs(%%rip), %%rax\n\t"

        "movq %%rcx, 2*8(%%rax)\n\t"
        "movq %%rdx, 3*8(%%rax)\n\t"
        "movq %%rsi, 4*8(%%rax)\n\t"
        "movq %%rdi, 5*8(%%rax)\n\t"
        "movq %%rbp, 6*8(%%rax)\n\t"
        "movq %%r8,  7*8(%%rax)\n\t"
        "movq %%r9,  8*8(%%rax)\n\t"
        "movq %%r10, 9*8(%%rax)\n\t"
        "movq %%r11, 10*8(%%rax)\n\t"
        "movq %%r12, 11*8(%%rax)\n\t"
        "movq %%r13, 12*8(%%rax)\n\t"
        "movq %%r14, 13*8(%%rax)\n\t"
        "movq %%r15, 14*8(%%rax)\n\t"

        /* Recover original RBX */
        "movq (%%rsp), %%rbx\n\t"
        "movq %%rbx, 1*8(%%rax)\n\t"

        /* Recover original RAX */
        "movq 8(%%rsp), %%rbx\n\t"
        "movq %%rbx, 0*8(%%rax)\n\t"

        /* Save entry RSP (before our two pushes) */
        "leaq 16(%%rsp), %%rbx\n\t"
        "movq %%rbx, 15*8(%%rax)\n\t"

        /* Restore RSP and jump to normal resume */
        "movq saved_rsp(%%rip), %%rsp\n\t"
        "jmpq *resume_normal(%%rip)\n\t"
        ::: "memory"
    );
}

/*
 * pivot_landing: naked function for pivot detection.
 * If the candidate pivoted RSP to our chain buffer, the chain
 * routes through nop_rets and lands here.
 * Sets got_pivot=1, restores RSP, jumps to resume_pivot.
 */
__attribute__((naked, used))
static void pivot_landing(void)
{
    __asm__ volatile(
        "movq $1, got_pivot(%%rip)\n\t"
        "movq saved_rsp(%%rip), %%rsp\n\t"
        "jmpq *resume_pivot(%%rip)\n\t"
        ::: "memory"
    );
}

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;

    uint64_t nop_ret = kdata_base + OFF_NOP_RET;
    uint64_t candidate = kdata_base + TARGET_OFFSET;

    probe_result_t* out = (probe_result_t*)args;
    out->magic = MAGIC_GPRB;
    out->status = STATUS_NONE;
    out->kdata_base = kdata_base;
    out->ktext_base = ktext_base;
    out->candidate_addr = candidate;
    out->probe_mode = PROBE_MODE;
    out->result_code = STATUS_NONE;
    out->marker_reg_id = 0;

    for (int i = 0; i < 16; i++)
        out->regs[i] = 0;

    got_pivot = 0;

    out->status = STATUS_TRYING;

#if PROBE_MODE == 0
    /* ════════════════════════════════════════════
     * MODE 0: pop_ret probe
     *
     * Build a ROP stack:
     *   stk[0] = candidate_addr     (ret pops this → jump to candidate)
     *   stk[1] = MARKER_VALUE       (candidate's pop consumes this)
     *   stk[2] = capture_stub addr  (candidate's ret jumps here)
     *
     * If candidate is `pop REG; ret`:
     *   - REG = MARKER_VALUE
     *   - ret → capture_stub
     *   - capture_stub records all registers
     *
     * If candidate is `REX.W + something; ...`:
     *   - Executes some other instruction(s)
     *   - May still hit a ret eventually → capture_stub
     *   - Or may crash → thread dies, result_code stays TRYING
     * ════════════════════════════════════════════ */

    uint64_t* stk = (uint64_t*)((uint8_t*)args + 0x800);
    stk[0] = candidate;
    stk[1] = MARKER_VALUE;
    stk[2] = (uint64_t)capture_stub;
    stk[3] = nop_ret;  /* safety: extra ret in case candidate pops 2 values */
    stk[4] = (uint64_t)capture_stub;

    __asm__ volatile(
        "leaq 1f(%%rip), %%rax\n\t"
        "movq %%rax, resume_normal(%%rip)\n\t"
        "movq %%rsp, saved_rsp(%%rip)\n\t"
        "movq %[chain], %%rsp\n\t"
        "retq\n\t"
        "1:\n\t"
        :
        : [chain] "r"(stk)
        : "rax", "memory", "cc"
    );

    /* We survived — copy results */
    out->result_code = STATUS_DONE;

    /* Check which register (if any) holds the marker */
    out->marker_reg_id = 0xFF; /* none found */
    for (int i = 0; i < 16; i++) {
        out->regs[i] = saved_regs[i];
        if (saved_regs[i] == MARKER_VALUE)
            out->marker_reg_id = i;
    }

#elif PROBE_MODE == 1
    /* ════════════════════════════════════════════
     * MODE 1: pivot probe
     *
     * Set RAX = &pivot_chain (a buffer with [nop_ret, nop_ret, pivot_landing]).
     * Build a ROP stack:
     *   stk[0] = candidate_addr     (ret pops this → jump to candidate)
     *   stk[1] = capture_stub addr  (if candidate just rets normally)
     *
     * If candidate is `xchg rsp, rax; ret`:
     *   - RSP ↔ RAX: RSP = &pivot_chain, RAX = old RSP
     *   - ret → pops pivot_chain[0] = nop_ret → ret
     *   - → pops pivot_chain[1] = nop_ret → ret
     *   - → pops pivot_chain[2] = pivot_landing
     *   - pivot_landing sets got_pivot=1, resumes
     *
     * If candidate is NOT a pivot:
     *   - Eventually rets → capture_stub → normal resume
     * ════════════════════════════════════════════ */

    /* Pivot chain buffer: what RSP will point to if pivot succeeds */
    uint64_t* pivot_chain = (uint64_t*)((uint8_t*)args + 0xA00);
    pivot_chain[0] = nop_ret;
    pivot_chain[1] = nop_ret;
    pivot_chain[2] = (uint64_t)pivot_landing;

    /* ROP entry stack */
    uint64_t* stk = (uint64_t*)((uint8_t*)args + 0x800);
    stk[0] = candidate;
    stk[1] = (uint64_t)capture_stub;  /* fallback if not a pivot */
    stk[2] = nop_ret;
    stk[3] = (uint64_t)capture_stub;

    __asm__ volatile(
        /* Set both resume targets */
        "leaq 1f(%%rip), %%rax\n\t"
        "movq %%rax, resume_normal(%%rip)\n\t"
        "leaq 2f(%%rip), %%rax\n\t"
        "movq %%rax, resume_pivot(%%rip)\n\t"

        "movq %%rsp, saved_rsp(%%rip)\n\t"

        /* Load RAX with pivot chain address (the controlled buffer) */
        "movq %[pchain], %%rax\n\t"

        /* Pivot RSP to ROP entry stack */
        "movq %[chain], %%rsp\n\t"

        /* Start: ret → candidate */
        "retq\n\t"

        /* Normal resume (candidate was not a pivot) */
        "1:\n\t"
        "jmp 3f\n\t"

        /* Pivot resume (candidate WAS a pivot) */
        "2:\n\t"

        "3:\n\t"
        :
        : [chain] "r"(stk), [pchain] "r"(pivot_chain)
        : "rax", "memory", "cc"
    );

    if (got_pivot) {
        out->result_code = STATUS_PIVOT;
        out->marker_reg_id = 1; /* pivot detected */
    } else {
        out->result_code = STATUS_DONE;
        out->marker_reg_id = 0; /* not a pivot */
        for (int i = 0; i < 16; i++)
            out->regs[i] = saved_regs[i];
    }

#endif

    out->status = STATUS_DONE;
    return 0;
}
