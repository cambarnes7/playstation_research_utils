#include <stdint.h>

/*
 * smart_pivot_scan — Danger-zone-aware ktext pivot gadget scanner
 *
 * MEMORY LAYOUT FIX (v2):
 * kldload allocates exec_code = malloc(binary_size) which gives ONE page (4096).
 * The .bss section lives right after the binary in the same allocation, so
 * total (code + bss) MUST fit in 4096 bytes.
 *
 * v1 had ~6500 bytes of .bss (func_list[512], safe_buf[2048], entry_stk, etc.)
 * which overflowed the page → instant kernel panic on any batch > 0.
 *
 * v2 fixes:
 *   - safe_buf[2048] eliminated — replaced with pointer to unused kthread_args
 *     tail (bytes 2304..4095), filled with nop_ret addresses at runtime
 *   - func_list reduced to static [96] (768 bytes) — sysent dropped (bad probes)
 *   - .bss now ~1132 bytes: func_list[96]=768, entry_stk[32]=256, rest=108
 *   - Total VMA (code+rodata+bss) ≈ 3856, fits in single 4096-byte page
 *
 * v2.1 fix: func_list CANNOT go on stack — kernel thread stack may be small
 *   (4-8KB), and 4KB array + frame + asm clobber saves = instant overflow.
 *
 * v3: EPILOGUE PROBING — probe backwards from function boundaries instead
 *   of forwards from function starts. Function epilogues are safe (pop/ret),
 *   while function bodies have hardware access, privileged ops, etc.
 *   Pivot gadgets (48 94 C3, 50 5C C3, etc.) all end with C3 (ret),
 *   and functions end with ret, so gadgets are at -3/-4 from ret.
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
 *   [9]  found_pattern_context (8 bytes before pivot via return-value inference)
 *   Per function probed (starting at index 10, 3 uint64_t each):
 *     [10+i*3+0]  function entry address
 *     [10+i*3+1]  probed_count | (survived_count << 16) | (skipped_count << 32)
 *     [10+i*3+2]  last_probed_offset | (status << 32)
 *
 * Max functions: (2304/8 - 10) / 3 = 89
 */

#ifndef SCAN_BATCH
#define SCAN_BATCH     0
#endif
#ifndef BATCH_SIZE
#define BATCH_SIZE     8
#endif
#ifndef PROBE_DEPTH
#define PROBE_DEPTH    16  /* bytes before each function boundary to probe */
#endif

#define MAGIC_SPVT     0x53505654  /* "SPVT" */
#define KTEXT_SIZE     0xC00000    /* 12MB */
#define HEADER_SLOTS   10
#define MAX_FUNCS      89
#define ENTRY_STK_SIZE 32

/* ── FW 4.03 known ktext offsets ── */

/* Danger zones: ktext regions containing privileged instructions.
 * kdata-relative negative offsets (same as kstuff DEF format).
 * Each entry: { kdata_relative_offset, exclusion_radius }
 */
typedef struct {
    int64_t  kdata_offset;  /* negative = ktext */
    int32_t  radius;        /* bytes to exclude on each side */
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
    { 0, 0 }              /* sentinel */
};

/* Known ktext function entry points from kstuff (kdata-relative negative offsets) */
static const int64_t known_ktext_funcs[] = {
    -0x99002a,   /* rep_movsb_pop_rbp_ret */
    -0x9908e0,   /* copyin */
    -0x990990,   /* copyout */
    -0x6824c0,   /* sceSblServiceMailbox */
    -0x8a5c40,   /* sceSblAuthMgrSmIsLoadable2 */
    -0x631ea9,   /* mdbg_call_fix */
    -0x802311,   /* syscall_before */
    -0xa9b00,    /* malloc */
    -0x8a54cd,   /* loadSelfSegment_epilogue */
    -0x8a52c3,   /* decryptSelfBlock_epilogue */
    -0x8a47d2,   /* decryptMultipleSelfBlocks_epilogue */
    -0x8ed940,   /* sceSblServiceCryptAsync */
    -0x479d60,   /* crypt_message_resolve */
    -0x9cf990,   /* justreturn */
    -0xc1ed0,    /* kmem_alloc */
    -0x35ebf0,   /* kproc_create */
    -0x90ac61,   /* mprotect_fix_start */
    -0x2cd31d,   /* mmap_self_fix_1_start */
    -0x1df2ce,   /* mmap_self_fix_2_start */
    -0x85a312,   /* aslr_fix_start */
    -0x6c2989,   /* sigaction_fix_start */
    -0x8a58bc,   /* sceSblServiceMailbox_lr_verifyHeader */
    -0x8a5541,   /* sceSblServiceMailbox_lr_loadSelfSegment */
    -0x8a5014,   /* sceSblServiceMailbox_lr_decryptSelfBlock */
    -0x8a488c,   /* sceSblServiceMailbox_lr_decryptMultipleSelfBlocks */
    -0x8a5cbe,   /* sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize */
    -0x94a7f0,   /* sceSblServiceMailbox_lr_verifySuperBlock */
    -0x94ada4,   /* sceSblServiceMailbox_lr_sceSblPfsClearKey_1 */
    -0x94ad2e,   /* sceSblServiceMailbox_lr_sceSblPfsClearKey_2 */
    -0x94aaa0,   /* sceSblPfsSetKeys */
    -0x21020,    /* panic */
    -0x2cc918,   /* loadSelfSegment_watchpoint */
    0            /* sentinel */
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

/* ── Small .bss globals referenced by inline asm (RIP-relative) ── */
static volatile uint64_t scan_saved_rsp;
static volatile uint64_t scan_resume_normal;
static volatile uint64_t scan_resume_pivot;
static volatile int scan_got_pivot;
static volatile uint64_t scan_candidate;

/* Pointer to safe memory region (set at runtime to kthread_args tail) */
static volatile uint64_t safe_addr;

/* Pivot chain: where RSP goes if candidate pivots */
static volatile uint64_t pivot_chain[8];

/* Entry stack: [candidate, resume, resume, resume, ...] */
static volatile uint64_t entry_stk[ENTRY_STK_SIZE];

/* Total .bss: 8+8+8+4+8+8+64+256 = ~364 bytes */

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

/* Check if an address falls in a danger zone */
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

/* Simple insertion sort */
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

    /* nop_ret = wrmsr_ret + 2 in ktext (just a bare ret instruction) */
    uint64_t nop_ret = kdata_base + (-0x9d20cc) + 2;

    volatile uint64_t* out = (volatile uint64_t*)args;

    /* Clear output buffer (first 2304 bytes = 288 uint64_t slots) */
    for (int i = 0; i < 2304/8; i++)
        out[i] = 0;

    out[0] = ((uint64_t)0xAAAA << 32) | MAGIC_SPVT;
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = (uint64_t)SCAN_BATCH | ((uint64_t)BATCH_SIZE << 16) |
             ((uint64_t)PROBE_DEPTH << 32);

    /*
     * Set up safe memory region.
     * kthread_args is a 4KB (0x1000) malloc. Output uses bytes 0..2303.
     * Bytes 2304..4095 are unused — perfect as a safe dereference target.
     * Fill it with nop_ret addresses so any "call [reg]" or "jmp [reg+off]"
     * that hits this region returns safely.
     */
    volatile uint64_t* safe_region = (volatile uint64_t*)((uint8_t*)args + 2304);
    int safe_slots = (4096 - 2304) / 8;  /* = 224 slots = 1792 bytes */
    for (int i = 0; i < safe_slots; i++)
        safe_region[i] = nop_ret;
    /* Point safe_addr to the middle of the safe region for max displacement coverage */
    safe_addr = (uint64_t)((uint8_t*)args + 2304 + 896);

    /*
     * Build sorted list of function entry points to probe.
     * STATIC — must fit in .bss within the single malloc page.
     * 96 entries * 8 bytes = 768 bytes. Total .bss ≈ 3856, fits in 4096.
     *
     * Sources: known kstuff offsets (~32) + IDT unique (~20) + apic_ops (~15).
     * Sysent excluded: syscall handlers are complex functions with locks,
     * hardware access, etc. — bad probe candidates that kill threads.
     */
    static uint64_t func_list[96];
    int n_funcs = 0;

    /* Add known kstuff ktext functions */
    for (int i = 0; known_ktext_funcs[i] != 0; i++) {
        uint64_t addr = kdata_base + known_ktext_funcs[i];
        if (addr >= ktext_base && addr < ktext_end && n_funcs < 96)
            func_list[n_funcs++] = addr;
    }

    /* Add IDT handlers */
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
            if (!dup)
                func_list[n_funcs++] = handler;
        }
    }

    /* Add apic_ops entries (28 entries at kdata+0x1656b0) */
    volatile uint64_t* apic_ops = (volatile uint64_t*)(kdata_base + 0x1656b0);
    for (int i = 0; i < 28 && n_funcs < 96; i++) {
        uint64_t fn = apic_ops[i];
        if (fn >= ktext_base && fn < ktext_end) {
            int dup = 0;
            for (int j = 0; j < n_funcs; j++)
                if (func_list[j] == fn) { dup = 1; break; }
            if (!dup)
                func_list[n_funcs++] = fn;
        }
    }

    /* Sort */
    sort_u64(func_list, n_funcs);

    /* Select batch */
    int batch_start = SCAN_BATCH * BATCH_SIZE;
    int batch_end = batch_start + BATCH_SIZE;
    if (batch_start >= n_funcs) {
        out[0] = ((uint64_t)0xFFFF << 32) | MAGIC_SPVT;  /* past end */
        out[4] = n_funcs;  /* total functions available */
        return 0;
    }
    if (batch_end > n_funcs)
        batch_end = n_funcs;

    /* Set up pivot chain (where RSP goes if pivot works) */
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

        /* EPILOGUE PROBING: probe backwards from the NEXT function boundary.
         *
         * Why: probing forwards from function starts executes arbitrary
         * mid-function code (hardware access, privileged ops) → thread death.
         *
         * Function epilogues are safe: they're just pop/ret sequences.
         * The pivot gadgets we want (48 94 C3, 50 5C C3, etc.) all end
         * with C3 (ret), and functions end with ret. So gadgets would be
         * at offsets -3 or -4 from a function's final ret instruction.
         *
         * Probe: next_func - 1, next_func - 2, ..., next_func - depth
         * where next_func - 1 is likely ret (C3) itself — extremely safe.
         */
        if (fi + 1 >= n_funcs)
            continue;  /* no next function = can't determine boundary */

        uint64_t next_func = func_list[fi + 1];
        int64_t gap = next_func - func_entry;
        if (gap <= 0 || gap > 0x10000)
            continue;  /* skip unreasonable gaps */

        int depth = PROBE_DEPTH;
        if (depth > (int)gap)
            depth = (int)gap;

        /* Record function entry (the boundary we're probing toward) */
        if (func_slot + 2 < 2304/8) {
            out[func_slot + 0] = next_func;  /* boundary address */
            out[func_slot + 1] = 0;
            out[func_slot + 2] = 0;
        }

        /* Probe backwards: off=1 means next_func-1, off=2 means next_func-2, etc. */
        for (int off = 1; off <= depth; off++) {
            uint64_t candidate = next_func - off;

            /* Check danger zone exclusion */
            if (is_dangerous(candidate, kdata_base)) {
                func_skipped++;
                total_skipped++;
                continue;
            }

            func_probed++;
            total_probed++;

            /* Update progress */
            out[4] = total_probed;
            if (func_slot + 2 < 2304/8) {
                out[func_slot + 2] = (uint64_t)off | ((uint64_t)0xBBBB << 32);
            }

            scan_got_pivot = 0;
            scan_candidate = candidate;

            __asm__ volatile(
                /* Set resume targets */
                "leaq 1f(%%rip), %%rcx\n\t"
                "movq %%rcx, scan_resume_normal(%%rip)\n\t"
                "leaq 2f(%%rip), %%rcx\n\t"
                "movq %%rcx, scan_resume_pivot(%%rip)\n\t"

                /* Fill entry_stk[1..31] with normal resume address */
                "leaq entry_stk(%%rip), %%rdx\n\t"
                "leaq 1f(%%rip), %%rcx\n\t"
                ".set j, 1\n\t"
                ".rept 31\n\t"
                "movq %%rcx, (j*8)(%%rdx)\n\t"
                ".set j, j+1\n\t"
                ".endr\n\t"

                /* Save RSP */
                "movq %%rsp, scan_saved_rsp(%%rip)\n\t"

                /* Load candidate from memory into entry_stk[0] */
                "movq scan_candidate(%%rip), %%rcx\n\t"
                "leaq entry_stk(%%rip), %%rdx\n\t"
                "movq %%rcx, (%%rdx)\n\t"

                /* === REGISTER SAFETY ===
                 * Set ALL registers (except RAX, RSP) to safe_addr.
                 * safe_addr points to the middle of the kthread_args tail
                 * region (filled with nop_ret addresses), giving ~896 bytes
                 * in each direction for [reg+displacement] accesses. */
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

                /* Clear direction flag */
                "cld\n\t"

                /* RAX = pivot_chain (the controlled buffer for RSP pivot) */
                "leaq pivot_chain(%%rip), %%rax\n\t"

                /* Switch RSP to entry stack and go */
                "leaq entry_stk(%%rip), %%rsp\n\t"
                "retq\n\t"

                /* Normal resume: candidate returned without pivoting */
                "1:\n\t"
                "movq scan_saved_rsp(%%rip), %%rsp\n\t"
                "jmp 3f\n\t"

                /* Pivot resume: candidate DID pivot RSP to our buffer! */
                "2:\n\t"
                "movq scan_saved_rsp(%%rip), %%rsp\n\t"

                "3:\n\t"
                ::: "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                    "rbp", "memory", "cc"
            );

            if (scan_got_pivot) {
                /* FOUND A PIVOT GADGET! */
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

        /* Record per-function stats */
        if (func_slot + 2 < 2304/8) {
            out[func_slot + 1] = (uint64_t)func_probed |
                                 ((uint64_t)func_survived << 16) |
                                 ((uint64_t)func_skipped << 32);
            out[func_slot + 2] = (uint64_t)depth |
                                 ((uint64_t)0x0001 << 32);
        }
    }

    /* Completed batch, no pivot found */
    out[0] = ((uint64_t)0x0001 << 32) | MAGIC_SPVT;
    out[4] = total_probed;
    out[5] = total_survived;
    out[6] = total_skipped;

    return 0;
}
