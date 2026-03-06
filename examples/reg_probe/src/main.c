#include <stdint.h>

/*
 * PS5 Register Probe (kstuff payload)
 *
 * Hooks apic_ops[2] (xapic_mode) with a transparent shim that captures
 * all register values at the call entry point, then calls the original.
 *
 * Purpose: Determine which register (if any) holds the apic_ops table
 * address when xapic_mode is called. This tells us which pivot gadget
 * to use (e.g., xchg rsp, rax vs xchg rsp, rdi).
 *
 * The probe runs during normal operation (not suspend/resume) since
 * our code is in NX-cleared kernel heap. We call through the apic_ops
 * dispatch using memory-indirect call to match the kernel's pattern.
 *
 * Output layout:
 *   [0x000] uint32_t magic = 0x52454750 ("REGP")
 *   [0x004] uint32_t status (1=success)
 *   [0x008] uint64_t kdata_base
 *   [0x010] uint64_t ktext_base
 *   [0x018] uint64_t apic_ops_table_addr
 *   [0x020] uint64_t xapic_mode_result (return value from original)
 *   [0x028] uint64_t regs[16]:
 *     [0x028] RAX   [0x030] RBX   [0x038] RCX   [0x040] RDX
 *     [0x048] RSI   [0x050] RDI   [0x058] RBP   [0x060] R8
 *     [0x068] R9    [0x070] R10   [0x078] R11   [0x080] R12
 *     [0x088] R13   [0x090] R14   [0x098] R15   [0x0A0] RSP
 *
 * Total: 0xA8 = 168 bytes (fits in 512-byte readback)
 */

#define MAGIC_REGP       0x52454750  /* "REGP" */
#define APIC_OPS_OFFSET  0x1934AC8   /* from ktext_base */

typedef struct {
    uint64_t kdata_base;
    uint32_t fw_ver;
} kproc_args;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t status;
    uint64_t kdata_base;
    uint64_t ktext_base;
    uint64_t apic_ops_addr;
    uint64_t xapic_result;
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rsi, rdi, rbp, r8;
    uint64_t r9, r10, r11, r12;
    uint64_t r13, r14, r15, rsp;
} probe_result_t;

static inline uint64_t rdmsr(uint32_t msr)
{
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

/* ── Probe data (in .bss, same pages as code, NX-cleared) ── */
static volatile uint64_t saved_regs[16];  /* register capture buffer */
static volatile uint64_t orig_func;       /* original xapic_mode address */

/*
 * Probe stub — installed as apic_ops[2].
 *
 * Naked function: no prologue/epilogue.
 * Saves all registers to saved_regs[], then jumps to original
 * xapic_mode (return address is already on stack from caller's `call`).
 */
__attribute__((naked, used))
static void probe_stub(void)
{
    __asm__ volatile(
        /* Save two temporaries on stack */
        "pushq %%rax\n\t"
        "pushq %%rbx\n\t"

        /* RAX = &saved_regs */
        "leaq saved_regs(%%rip), %%rax\n\t"

        /* Save registers that aren't clobbered */
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

        /* Recover original RBX from stack and save */
        "movq (%%rsp), %%rbx\n\t"
        "movq %%rbx, 1*8(%%rax)\n\t"

        /* Recover original RAX from stack and save */
        "movq 8(%%rsp), %%rbx\n\t"
        "movq %%rbx, 0*8(%%rax)\n\t"

        /* Save entry RSP (before our two pushes) = rsp + 16 */
        "leaq 16(%%rsp), %%rbx\n\t"
        "movq %%rbx, 15*8(%%rax)\n\t"

        /* Restore temporaries */
        "popq %%rbx\n\t"
        "popq %%rax\n\t"

        /* Tail-call original xapic_mode (return addr still on stack) */
        "jmpq *orig_func(%%rip)\n\t"
        ::: "memory"
    );
}

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;
    uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFFSET;

    /* Prepare output */
    probe_result_t* out = (probe_result_t*)args;
    out->magic = MAGIC_REGP;
    out->status = 0;
    out->kdata_base = kdata_base;
    out->ktext_base = ktext_base;
    out->apic_ops_addr = apic_ops_addr;

    /* Read and save original apic_ops[2] */
    volatile uint64_t* apic_slot2 = (volatile uint64_t*)(apic_ops_addr + 0x10);
    uint64_t original = *apic_slot2;
    orig_func = original;

    /* Install probe stub */
    uint64_t stub_addr = (uint64_t)probe_stub;
    *apic_slot2 = stub_addr;

    /*
     * Call xapic_mode through the apic_ops dispatch.
     *
     * Use memory-indirect call: call [table + 0x10]
     * This matches how the kernel's LAPIC code likely dispatches,
     * so register state at the call site should be representative.
     *
     * The register holding table_addr tells us our pivot register.
     */
    int result;
    __asm__ volatile(
        "callq *0x10(%[table])\n\t"
        : "=a"(result)
        : [table] "r"(apic_ops_addr)
        : "memory", "cc", "rcx", "rdx", "rsi", "rdi",
          "r8", "r9", "r10", "r11"
    );

    /* Restore original apic_ops[2] immediately */
    *apic_slot2 = original;

    /* Copy captured registers to output */
    out->xapic_result = (uint64_t)(uint32_t)result;
    out->rax  = saved_regs[0];
    out->rbx  = saved_regs[1];
    out->rcx  = saved_regs[2];
    out->rdx  = saved_regs[3];
    out->rsi  = saved_regs[4];
    out->rdi  = saved_regs[5];
    out->rbp  = saved_regs[6];
    out->r8   = saved_regs[7];
    out->r9   = saved_regs[8];
    out->r10  = saved_regs[9];
    out->r11  = saved_regs[10];
    out->r12  = saved_regs[11];
    out->r13  = saved_regs[12];
    out->r14  = saved_regs[13];
    out->r15  = saved_regs[14];
    out->rsp  = saved_regs[15];

    out->status = 1;

    return 0;
}
