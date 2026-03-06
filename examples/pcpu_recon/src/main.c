#include <stdint.h>

/*
 * pcpu_recon v2 — Per-CPU / thread / stack reconnaissance + offset scanner
 *
 * v2 CHANGES:
 *   - Added thread struct offset scanner: scans idle thread struct from
 *     offset 0x200 to 0x400 looking for values that look like kernel
 *     stack addresses (in 0xFFFFFF80xxxxxxxx range, near pcb_rsp).
 *     This helps find the correct td_kstack offset on PS5.
 *   - Uses PCB-based stack dump as fallback when td_kstack is 0
 *   - Dumps 32 qwords around idle thread's pcb_rsp for stack context
 *
 * Output layout (uint64_t indices):
 *   [0]   magic "PCPU" (0x50435055) | status(32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   pcpu_array_addr
 *
 *   --- pcpu[0] fields ---
 *   [4]   pc_curthread
 *   [5]   pc_idlethread
 *   [6]   pc_fpcurthread
 *   [7]   pc_curpcb
 *
 *   --- curthread info ---
 *   [8]   curthread->td_kstack (may be 0 if offset wrong)
 *   [9]   curthread->td_kstack_pages
 *   [10]  curthread->td_pcb
 *   [11]  curthread->td_proc
 *   [12..15] curthread->td_name (first 32 bytes)
 *
 *   --- idlethread info ---
 *   [16]  idlethread->td_kstack (may be 0 if offset wrong)
 *   [17]  idlethread->td_kstack_pages
 *   [18]  idlethread->td_pcb
 *   [19]  idlethread->td_proc
 *   [20..23] idlethread->td_name (first 32 bytes)
 *
 *   --- curthread PCB (saved context) ---
 *   [24]  pcb_rsp
 *   [25]  pcb_rbp
 *   [26]  pcb_rip
 *   [27]  pcb_rbx
 *   [28]  pcb_r12
 *   [29]  pcb_flags
 *
 *   --- idlethread PCB ---
 *   [30]  pcb_rsp
 *   [31]  pcb_rbp
 *   [32]  pcb_rip
 *   [33]  pcb_rbx
 *   [34]  pcb_flags
 *
 *   --- Current debug register values ---
 *   [35]  DR0
 *   [36]  DR1
 *   [37]  DR2
 *   [38]  DR3
 *   [39]  DR6
 *   [40]  DR7
 *
 *   --- Current live RSP, RBP ---
 *   [41]  current RSP
 *   [42]  current RBP
 *
 *   --- Stack dump: 32 qwords around idle pcb_rsp ---
 *   [43..74] 128 bytes below pcb_rsp .. 128 bytes above pcb_rsp
 *
 *   [75]  sentinel 0xdeadbeefcafe0022
 *
 *   --- Extra pcpu fields ---
 *   [76]  pc_rsp0
 *   [77]  pc_cpuid
 *   [78]  pc_curpmap
 *   [79]  pc_scratch_rsp
 *
 *   --- Thread struct offset scan (idle thread) ---
 *   Scans offsets 0x200..0x3F0 (step 8) for kernel stack-like addresses.
 *   Reports up to 16 "hits" (values in 0xFFFFFF80xxxxxxxx range).
 *   [80]  number of hits found
 *   [81..112] pairs: (offset, value) for each hit (16 max = 32 slots)
 *
 *   [113] idle pcb_rsp (for reference during analysis)
 *   [114] idle pcb_rbp
 *
 *   [120] sentinel 0xdeadbeefcafe0033
 */

#define MAGIC_PCPU       0x50435055  /* "PCPU" */

/* FW 4.03 pcpu_array offset from kdata_base */
#define PCPU_ARRAY_OFF   0x64d2280

/* pcpu field offsets */
#define PC_CURTHREAD     0x00
#define PC_IDLETHREAD    0x08
#define PC_FPCURTHREAD   0x10
#define PC_CURPCB        0x18
#define PC_CURPMAP       0x20
#define PC_TSSP          0x28
#define PC_COMMONTSSP    0x30
#define PC_RSP0          0x38
#define PC_SCRATCH_RSP   0x40
#define PC_CPUID         0x48

/* thread field offsets */
#define TD_PROC          0x008
#define TD_NAME          0x290
#define TD_PCB           0x3f8
#define TD_KSTACK        0x2a8
#define TD_KSTACK_PAGES  0x2b0

/* PCB field offsets */
#define PCB_R15          0x00
#define PCB_R14          0x08
#define PCB_R13          0x10
#define PCB_R12          0x18
#define PCB_RBP          0x20
#define PCB_RSP          0x28
#define PCB_RBX          0x30
#define PCB_RIP          0x38
#define PCB_FLAGS        0x100

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

static inline uint32_t read4(uint64_t addr)
{
    return *(volatile uint32_t*)addr;
}

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;
    volatile uint64_t* out = (volatile uint64_t*)args;
    volatile uint32_t* out32 = (volatile uint32_t*)args;

    /* Zero output */
    for (int i = 0; i < 280; i++)
        out[i] = 0;

    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;

    /* Header */
    out32[0] = MAGIC_PCPU;
    out32[1] = 0xAAAA;
    out[1] = kdata_base;
    out[2] = ktext_base;

    /* pcpu[0] base address */
    uint64_t pcpu0 = kdata_base + PCPU_ARRAY_OFF;
    out[3] = pcpu0;

    /* Read pcpu[0] fields */
    uint64_t curthread  = read8(pcpu0 + PC_CURTHREAD);
    uint64_t idlethread = read8(pcpu0 + PC_IDLETHREAD);
    uint64_t fpcurthread = read8(pcpu0 + PC_FPCURTHREAD);
    uint64_t curpcb     = read8(pcpu0 + PC_CURPCB);
    uint64_t rsp0       = read8(pcpu0 + PC_RSP0);
    uint32_t cpuid      = read4(pcpu0 + PC_CPUID);

    out[4] = curthread;
    out[5] = idlethread;
    out[6] = fpcurthread;
    out[7] = curpcb;

    /* Extra pcpu fields */
    out[76] = rsp0;
    out[77] = cpuid;
    out[78] = read8(pcpu0 + PC_CURPMAP);
    out[79] = read8(pcpu0 + PC_SCRATCH_RSP);

    /* ── curthread info ── */
    if (curthread) {
        out[8]  = read8(curthread + TD_KSTACK);
        out[9]  = read8(curthread + TD_KSTACK_PAGES);
        out[10] = read8(curthread + TD_PCB);
        out[11] = read8(curthread + TD_PROC);
        out[12] = read8(curthread + TD_NAME);
        out[13] = read8(curthread + TD_NAME + 8);
        out[14] = read8(curthread + TD_NAME + 16);
        out[15] = read8(curthread + TD_NAME + 24);
    }

    /* ── idlethread info ── */
    if (idlethread) {
        out[16] = read8(idlethread + TD_KSTACK);
        out[17] = read8(idlethread + TD_KSTACK_PAGES);
        out[18] = read8(idlethread + TD_PCB);
        out[19] = read8(idlethread + TD_PROC);
        out[20] = read8(idlethread + TD_NAME);
        out[21] = read8(idlethread + TD_NAME + 8);
        out[22] = read8(idlethread + TD_NAME + 16);
        out[23] = read8(idlethread + TD_NAME + 24);
    }

    /* ── curthread PCB ── */
    uint64_t cur_pcb_addr = curthread ? read8(curthread + TD_PCB) : 0;
    if (cur_pcb_addr) {
        out[24] = read8(cur_pcb_addr + PCB_RSP);
        out[25] = read8(cur_pcb_addr + PCB_RBP);
        out[26] = read8(cur_pcb_addr + PCB_RIP);
        out[27] = read8(cur_pcb_addr + PCB_RBX);
        out[28] = read8(cur_pcb_addr + PCB_R12);
        out[29] = read8(cur_pcb_addr + PCB_FLAGS);
    }

    /* ── idlethread PCB ── */
    uint64_t idle_pcb_addr = idlethread ? read8(idlethread + TD_PCB) : 0;
    if (idle_pcb_addr) {
        out[30] = read8(idle_pcb_addr + PCB_RSP);
        out[31] = read8(idle_pcb_addr + PCB_RBP);
        out[32] = read8(idle_pcb_addr + PCB_RIP);
        out[33] = read8(idle_pcb_addr + PCB_RBX);
        out[34] = read8(idle_pcb_addr + PCB_FLAGS);
    }

    /* ── Current debug register values ── */
    uint64_t dr_val;
    __asm__ volatile("mov %%dr0, %0" : "=r"(dr_val));
    out[35] = dr_val;
    __asm__ volatile("mov %%dr1, %0" : "=r"(dr_val));
    out[36] = dr_val;
    __asm__ volatile("mov %%dr2, %0" : "=r"(dr_val));
    out[37] = dr_val;
    __asm__ volatile("mov %%dr3, %0" : "=r"(dr_val));
    out[38] = dr_val;
    __asm__ volatile("mov %%dr6, %0" : "=r"(dr_val));
    out[39] = dr_val;
    __asm__ volatile("mov %%dr7, %0" : "=r"(dr_val));
    out[40] = dr_val;

    /* ── Current live RSP, RBP ── */
    uint64_t rsp_val, rbp_val;
    __asm__ volatile("mov %%rsp, %0" : "=r"(rsp_val));
    __asm__ volatile("mov %%rbp, %0" : "=r"(rbp_val));
    out[41] = rsp_val;
    out[42] = rbp_val;

    /* ── Stack dump around idle thread's pcb_rsp ── */
    uint64_t idle_pcb_rsp = idle_pcb_addr ? read8(idle_pcb_addr + PCB_RSP) : 0;
    uint64_t idle_pcb_rbp = idle_pcb_addr ? read8(idle_pcb_addr + PCB_RBP) : 0;

    if (idle_pcb_rsp >= 0xFFFF800000000000ULL) {
        /* Dump 32 qwords: 16 below pcb_rsp and 16 above (256 bytes total) */
        uint64_t dump_start = idle_pcb_rsp - 128;
        for (int i = 0; i < 32; i++) {
            out[43 + i] = read8(dump_start + (i * 8));
        }
    }

    out[75] = 0xdeadbeefcafe0022ULL;

    /* ── Thread struct offset scanner ──
     * Scan idle thread struct for values that look like kernel stack addresses.
     * We look for values in 0xFFFFFF80xxxxxxxx range (direct map kernel addrs)
     * that are page-aligned or near pcb_rsp, to find the real td_kstack offset. */
    out[113] = idle_pcb_rsp;
    out[114] = idle_pcb_rbp;

    if (idlethread) {
        int hit_count = 0;
        /* Scan from offset 0x200 to 0x3F0 in steps of 8 */
        for (uint64_t off = 0x200; off < 0x3F8 && hit_count < 16; off += 8) {
            uint64_t val = read8(idlethread + off);
            /* Check if this looks like a kernel direct-map address
             * (0xFFFFFF80xxxxxxxx) and is page-aligned (potential kstack) */
            if ((val & 0xFFFFFF0000000000ULL) == 0xFFFFFF0000000000ULL) {
                out[81 + hit_count * 2] = off;       /* offset in thread struct */
                out[81 + hit_count * 2 + 1] = val;   /* value at that offset */
                hit_count++;
            }
        }
        out[80] = hit_count;
    }

    out[120] = 0xdeadbeefcafe0033ULL;

    /* Success */
    out32[1] = 0x0001;

    return 0;
}
