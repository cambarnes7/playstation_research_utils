#include <stdint.h>

/*
 * state_capture v5.1 — Pure read-only, ZERO function calls
 *
 * v5 proved: Mode 0x5 (no calls, no kdata writes) doesn't crash.
 * v5 also proved: calling rdmsr_start crashes (Mode 0x4 instant panic).
 *
 * Key insight: we can read ALL MSRs directly via rdmsr inline asm!
 * We already proved rdmsr(LSTAR) works from kproc context in v5.
 * No need to call any kernel function at all.
 *
 * v5.1 captures in a single safe mode:
 * - All interesting MSRs via inline rdmsr
 * - CR0, CR3, CR4 via inline mov
 * - GDT, IDT base+limit via sgdt/sidt
 * - td_pcb dump (direct memory read of our thread's PCB)
 * - GSBASE per-CPU structure dump (struct pcpu exploration)
 *
 * Workflow:
 *   1. Mode 0x5: capture CPU state + per-CPU structure
 *   2. Analyze struct pcpu to find pointers to suspend infrastructure
 *   3. Follow pointer chains to locate susppcbs
 *
 * Mode (via fw_ver):
 *   0x5: SCAN — full CPU state capture + per-CPU dump (288 slots)
 *   0x6: DUMP — deep td_pcb dump (256 qwords = 2KB)
 *
 * Output layout (uint64_t indices, 288 slots = 2304 bytes):
 *
 * Mode 0x5 (SCAN):
 *   [0]   magic(lo32) | status(hi32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   lstar
 *   [4]   cr3
 *   [5]   gsbase
 *   [6]   curthread
 *   [7]   td_pcb
 *   --- Per-CPU structure (struct pcpu at GSBASE) ---
 *   [8..63]  56 qwords from GSBASE (0x1C0 bytes of struct pcpu)
 *            NOTE: debug readback limit = 64 qwords (0x200 bytes)
 *   [287] end marker (beyond readback, but confirms execution)
 *
 * Mode 0x6 (DUMP):
 *   [0]   magic | status
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   lstar
 *   [4]   cr3
 *   [5]   curthread
 *   [6]   td_pcb
 *   --- curthread struct dump ---
 *   [20..147]  curthread[0x00..0x3FF] (128 qwords = 1024 bytes)
 *   --- td_pcb dump (proven safe at 0x200) ---
 *   [160..223] td_pcb[0x00..0x1FF] (64 qwords = 512 bytes)
 *   [287] end marker
 */

#define MAGIC_SCAP       0x53434150

/* MSR numbers */
#define MSR_EFER         0xC0000080
#define MSR_STAR         0xC0000081
#define MSR_LSTAR        0xC0000082
#define MSR_CSTAR        0xC0000083
#define MSR_SFMASK       0xC0000084
#define MSR_FSBASE       0xC0000100
#define MSR_GSBASE       0xC0000101
#define MSR_KGSBASE      0xC0000102

#define LSTAR_OFFSET     0x294218
#define TD_PCB           0x3f8

typedef struct {
    uint64_t kdata_base;
    uint32_t fw_ver;
} kproc_args;

typedef struct {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed)) dt_reg;

static inline uint64_t rdmsr(uint32_t msr)
{
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t read_cr0(void)
{
    uint64_t v;
    __asm__ volatile("movq %%cr0, %0" : "=r"(v));
    return v;
}

static inline uint64_t read_cr3(void)
{
    uint64_t v;
    __asm__ volatile("movq %%cr3, %0" : "=r"(v));
    return v;
}

static inline uint64_t read_cr4(void)
{
    uint64_t v;
    __asm__ volatile("movq %%cr4, %0" : "=r"(v));
    return v;
}

static inline uint64_t read8(uint64_t addr)
{
    return *(volatile uint64_t *)addr;
}

int module_start(kproc_args *args)
{
    uint64_t kdata_base = args->kdata_base;
    uint32_t mode = args->fw_ver;
    volatile uint64_t *out = (volatile uint64_t *)args;
    volatile uint32_t *out32 = (volatile uint32_t *)args;

    uint64_t lstar = rdmsr(MSR_LSTAR);
    uint64_t ktext_base = lstar - LSTAR_OFFSET;
    uint64_t cr3 = read_cr3();

    if (mode == 0x5) {
        /* ============================================================
         * MODE 0x5: SCAN — Full CPU state + per-CPU structure dump
         *
         * ZERO function calls. ZERO writes to kdata.
         * Reads all MSRs and CRs directly via inline asm.
         * Dumps struct pcpu at GSBASE to map per-CPU infrastructure.
         * ============================================================ */
        /* Pack into 64 qwords (debug readback limit = 0x200 bytes).
         * Slots 0-7: header + key values
         * Slots 8-63: per-CPU struct dump (56 qwords = 0x1C0 bytes)
         */
        for (int i = 0; i < 288; i++) out[i] = 0;

        out[1] = kdata_base;
        out[2] = ktext_base;
        out[3] = lstar;
        out[4] = cr3;

        uint64_t gsbase = rdmsr(MSR_GSBASE);
        out[5] = gsbase;

        uint64_t curthread;
        __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
        out[6] = curthread;

        uint64_t td_pcb = 0;
        if (curthread)
            td_pcb = read8(curthread + TD_PCB);
        out[7] = td_pcb;

        /* Per-CPU structure: 56 qwords (0x1C0 bytes) from GSBASE */
        for (int i = 0; i < 56; i++)
            out[8 + i] = read8(gsbase + i * 8);

        out32[0] = MAGIC_SCAP;
        out32[1] = 0x0005;
        out[287] = 0xdeadbeefcafe0050ULL;
        return 0;
    }

    if (mode == 0x6) {
        /* ============================================================
         * MODE 0x6: DUMP — curthread struct + td_pcb
         *
         * td_pcb is at the top of a kernel stack page — reading beyond
         * ~0x200 bytes hits a guard page and panics (v5.1 learned this).
         *
         * Instead: dump the curthread struct (large slab allocation,
         * safe to read ~0x400 bytes) plus td_pcb (0x200, proven safe).
         * ============================================================ */
        for (int i = 0; i < 288; i++) out[i] = 0;

        out[1] = kdata_base;
        out[2] = ktext_base;
        out[3] = lstar;
        out[4] = cr3;

        uint64_t curthread;
        __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
        out[5] = curthread;

        uint64_t td_pcb = 0;
        if (curthread)
            td_pcb = read8(curthread + TD_PCB);
        out[6] = td_pcb;

        /* Dump curthread struct: 128 qwords = 0x400 bytes */
        if (curthread) {
            for (int i = 0; i < 128; i++)
                out[20 + i] = read8(curthread + i * 8);
        }

        /* Dump td_pcb: 64 qwords = 0x200 bytes (proven safe) */
        if (td_pcb) {
            for (int i = 0; i < 64; i++)
                out[160 + i] = read8(td_pcb + i * 8);
        }

        out32[0] = MAGIC_SCAP;
        out32[1] = (curthread && td_pcb) ? 0x0006 : 0x00FD;
        out[287] = 0xdeadbeefcafe0060ULL;
        return 0;
    }

    /* Unknown mode */
    for (int i = 0; i < 64; i++) out[i] = 0;
    out[1] = kdata_base;
    out[2] = ktext_base;
    out32[0] = MAGIC_SCAP;
    out32[1] = 0x00FF;
    out[63] = 0xdeadbeefcafe00FFULL;
    return 0;
}
