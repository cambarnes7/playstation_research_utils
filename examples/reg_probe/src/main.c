#include <stdint.h>

/*
 * PS5 Register Probe v2 (kstuff payload)
 *
 * Hooks apic_ops[2] (xapic_mode) with a transparent shim that captures
 * all register values at the KERNEL'S natural call entry point, then
 * calls the original.
 *
 * v2 change: Instead of calling xapic_mode ourselves (which captures
 * OUR register context), we install the hook and WAIT for the kernel
 * to naturally call xapic_mode (via timer interrupt, scheduler, etc.).
 * This captures the actual register state during LAPIC operations,
 * which is what we need for stack pivot gadget selection.
 *
 * The probe captures up to 4 calls to see if registers are stable.
 *
 * Output layout:
 *   [0x000] uint32_t magic = 0x52454750 ("REGP")
 *   [0x004] uint32_t status (1=success, 0=timeout)
 *   [0x008] uint64_t kdata_base
 *   [0x010] uint64_t ktext_base
 *   [0x018] uint64_t apic_ops_table_addr
 *   [0x020] uint64_t original_xapic_mode
 *   [0x028] uint32_t call_count (how many captures)
 *   [0x02C] uint32_t pad
 *
 *   Per-call captures (4 captures × 17 uint64 = 544 bytes):
 *   [0x030] capture[0]: rax rbx rcx rdx rsi rdi rbp r8 r9 r10 r11 r12 r13 r14 r15 rsp rflags
 *   [0x0B8] capture[1]: ...
 *   [0x140] capture[2]: ...
 *   [0x1C8] capture[3]: ...
 *
 *   [0x250] uint64_t sentinel = 0xdeadbeefcafe0002
 */

#define MAGIC_REGP       0x52454750  /* "REGP" */
#define APIC_OPS_OFFSET  0x1934AC8   /* from ktext_base on FW 4.03 */
#define MAX_CAPTURES     4
#define REGS_PER_CAPTURE 17          /* 16 GPRs + RFLAGS */

typedef struct {
    uint64_t kdata_base;
    uint32_t fw_ver;
} kproc_args;

/* ── Shared state between probe_stub and module_start ── */
static volatile uint64_t capture_buf[MAX_CAPTURES * REGS_PER_CAPTURE];
static volatile int capture_count;
static volatile uint64_t orig_func;

/*
 * Probe stub — installed as apic_ops[2].
 *
 * Naked function: no prologue/epilogue.
 * Saves all registers to capture_buf[capture_count * 17], increments count,
 * then tail-calls original xapic_mode.
 *
 * After MAX_CAPTURES, stops capturing (just calls original).
 */
__attribute__((naked, used))
static void probe_stub(void)
{
    __asm__ volatile(
        /* Save two temporaries */
        "pushq %%rax\n\t"
        "pushq %%rbx\n\t"

        /* Check if we've captured enough */
        "movl capture_count(%%rip), %%eax\n\t"
        "cmpl %[max], %%eax\n\t"
        "jge 1f\n\t"  /* skip capture if full */

        /* RBX = &capture_buf[count * 17] */
        "leaq capture_buf(%%rip), %%rbx\n\t"
        "imulq $136, %%rax, %%rax\n\t"  /* 17 * 8 = 136 */
        "addq %%rax, %%rbx\n\t"

        /* Save registers that aren't clobbered */
        "movq %%rcx, 2*8(%%rbx)\n\t"
        "movq %%rdx, 3*8(%%rbx)\n\t"
        "movq %%rsi, 4*8(%%rbx)\n\t"
        "movq %%rdi, 5*8(%%rbx)\n\t"
        "movq %%rbp, 6*8(%%rbx)\n\t"
        "movq %%r8,  7*8(%%rbx)\n\t"
        "movq %%r9,  8*8(%%rbx)\n\t"
        "movq %%r10, 9*8(%%rbx)\n\t"
        "movq %%r11, 10*8(%%rbx)\n\t"
        "movq %%r12, 11*8(%%rbx)\n\t"
        "movq %%r13, 12*8(%%rbx)\n\t"
        "movq %%r14, 13*8(%%rbx)\n\t"
        "movq %%r15, 14*8(%%rbx)\n\t"

        /* Save entry RSP (before our two pushes) = rsp + 16 */
        "leaq 16(%%rsp), %%rax\n\t"
        "movq %%rax, 15*8(%%rbx)\n\t"

        /* Save RFLAGS */
        "pushfq\n\t"
        "popq %%rax\n\t"
        "movq %%rax, 16*8(%%rbx)\n\t"

        /* Recover original RAX from stack and save */
        "movq 8(%%rsp), %%rax\n\t"    /* original RAX (pushed second) */
        "movq %%rax, 0*8(%%rbx)\n\t"

        /* Recover original RBX from stack and save */
        "movq (%%rsp), %%rax\n\t"     /* original RBX (pushed first, now at top) */
        "movq %%rax, 1*8(%%rbx)\n\t"

        /* Increment capture count */
        "movl capture_count(%%rip), %%eax\n\t"
        "incl %%eax\n\t"
        "movl %%eax, capture_count(%%rip)\n\t"

        "1:\n\t"
        /* Restore temporaries */
        "popq %%rbx\n\t"
        "popq %%rax\n\t"

        /* Tail-call original xapic_mode */
        "jmpq *orig_func(%%rip)\n\t"
        :
        : [max] "i"(MAX_CAPTURES)
        : "memory"
    );
}

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    volatile uint64_t* out = (volatile uint64_t*)args;

    /* Zero output area */
    for (int i = 0; i < 80; i++)
        out[i] = 0;

    /* rdmsr LSTAR */
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"((uint32_t)0xC0000082));
    uint64_t lstar = ((uint64_t)hi << 32) | lo;
    uint64_t ktext_base = lstar - 0x294218;
    uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFFSET;

    /* Write header */
    volatile uint32_t* out32 = (volatile uint32_t*)args;
    out32[0] = MAGIC_REGP;
    out32[1] = 0;  /* status: not yet done */
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = apic_ops_addr;

    /* Read original apic_ops[2] */
    volatile uint64_t* apic_slot2 = (volatile uint64_t*)(apic_ops_addr + 0x10);
    uint64_t original = *apic_slot2;
    orig_func = original;
    out[4] = original;

    /* Initialize capture state */
    capture_count = 0;
    for (int i = 0; i < MAX_CAPTURES * REGS_PER_CAPTURE; i++)
        capture_buf[i] = 0;

    /* Install probe stub */
    *apic_slot2 = (uint64_t)probe_stub;

    /*
     * Wait for the kernel to naturally call xapic_mode.
     * LAPIC operations happen frequently during timer interrupts,
     * IPIs, and scheduler activity. Spin for up to ~2 seconds
     * (roughly ~200M iterations at kernel speed).
     */
    for (volatile int i = 0; i < 200000000 && capture_count < MAX_CAPTURES; i++) {
        /* spin */
    }

    /* Restore original immediately */
    *apic_slot2 = original;

    /* Copy results to output */
    out32[10] = (uint32_t)capture_count;  /* at offset 0x28 */
    out32[11] = 0;  /* pad */

    /* Copy capture data starting at offset 0x30 (slot 6) */
    int n = capture_count;
    if (n > MAX_CAPTURES) n = MAX_CAPTURES;

    for (int c = 0; c < n; c++) {
        for (int r = 0; r < REGS_PER_CAPTURE; r++) {
            out[6 + c * REGS_PER_CAPTURE + r] = capture_buf[c * REGS_PER_CAPTURE + r];
        }
    }

    /* Sentinel */
    int sentinel_slot = 6 + MAX_CAPTURES * REGS_PER_CAPTURE;
    out[sentinel_slot] = 0xdeadbeefcafe0002ULL;

    /* Done */
    out32[1] = (n > 0) ? 1 : 0;

    return 0;
}
