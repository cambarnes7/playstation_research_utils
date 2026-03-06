#include <stdint.h>

/*
 * pcpu_recon — Per-CPU / thread / stack reconnaissance
 *
 * Dumps critical kernel structures needed for the suspend ROP chain:
 *   1. pcpu[0] fields: curthread, idlethread, curpcb
 *   2. Thread fields: td_kstack, td_pcb, td_name
 *   3. Stack address ranges for both curthread and idlethread
 *   4. PCB fields: pcb_rsp, pcb_rbp, pcb_flags (includes PCB_DBREGS)
 *   5. Debug register current values (DR0-DR3, DR6, DR7)
 *
 * This tells us:
 *   - Where the idle thread's kernel stack is (used during suspend/resume)
 *   - What the PCB saved RSP is (approximate resume stack pointer)
 *   - Whether debug registers are currently set
 *
 * All reads are from kdata — completely safe, no ktext access.
 *
 * FreeBSD 11 amd64 structure offsets (PS5 FW 4.03):
 *   pcpu size: ~0x480 (per-cpu struct)
 *   Key pcpu fields:
 *     pc_curthread:   +0x0   (struct thread *)
 *     pc_idlethread:  +0x10  (struct thread *)
 *     pc_curpcb:      +0x18  (struct pcb *)
 *     pc_cpuid:       +0x34  (u_int)
 *     pc_curpmap:     +0x258 (struct pmap *)
 *
 *   Key thread fields (from kek.asm structs.inc):
 *     td_proc:        +0x008 (struct proc *)
 *     td_name:        +0x290 (char[MAXCOMLEN+1])
 *     td_pcb:         +0x3f8 (struct pcb *)
 *     td_kstack:      +0x2a8 (vm_offset_t) — kernel stack base
 *     td_kstack_pages:+0x2b0 (int) — stack size in pages
 *     td_retval:      +0x408 (register_t[2])
 *
 *   Key PCB fields:
 *     pcb_r15-r12:    +0x00..+0x18
 *     pcb_rbp:        +0x20
 *     pcb_rsp:        +0x28
 *     pcb_rbx:        +0x30
 *     pcb_rip:        +0x38
 *     pcb_fsbase:     +0x40
 *     pcb_gsbase:     +0x48
 *     pcb_flags:      +0x100
 *     pcb_dr0..dr7:   +0x110..+0x140
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
 *   [6]   pc_curpcb
 *   [7]   pc_cpuid (32-bit, zero-extended)
 *
 *   --- curthread info ---
 *   [8]   curthread->td_kstack (kernel stack base)
 *   [9]   curthread->td_kstack_pages
 *   [10]  curthread->td_pcb
 *   [11]  curthread->td_proc
 *   [12..15] curthread->td_name (first 32 bytes)
 *
 *   --- idlethread info ---
 *   [16]  idlethread->td_kstack
 *   [17]  idlethread->td_kstack_pages
 *   [18]  idlethread->td_pcb
 *   [19]  idlethread->td_proc
 *   [20..23] idlethread->td_name (first 32 bytes)
 *
 *   --- curthread PCB (saved context) ---
 *   [24]  pcb_rsp (saved RSP during last context switch)
 *   [25]  pcb_rbp
 *   [26]  pcb_rip
 *   [27]  pcb_rbx
 *   [28]  pcb_r12..r15 packed or individual
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
 *   [35]  DR0 (read via mov rax, dr0)
 *   [36]  DR1
 *   [37]  DR2
 *   [38]  DR3
 *   [39]  DR6
 *   [40]  DR7
 *
 *   --- Current live RSP, RBP ---
 *   [41]  current RSP (for stack location reference)
 *   [42]  current RBP
 *
 *   --- Stack dump: 32 qwords from idle thread's stack top ---
 *   [43..74] idle_kstack + (pages*4096) - 256 .. - 0
 *
 *   [75]  sentinel 0xdeadbeefcafe0022
 */

#define MAGIC_PCPU       0x50435055  /* "PCPU" */

/* FW 4.03 pcpu_array offset from kdata_base */
#define PCPU_ARRAY_OFF   0x64d2280
#define PCPU_SIZE        0x480

/* pcpu field offsets (FreeBSD 11 amd64) */
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
#define PCB_DR0          0x110
#define PCB_DR1          0x118
#define PCB_DR2          0x120
#define PCB_DR3          0x128
#define PCB_DR6          0x130
#define PCB_DR7          0x138

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

    /* Extra pcpu fields at indices 76-79 (after sentinel) */
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
        /* thread name (first 32 bytes) */
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
        /* thread name */
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
        out[28] = read8(cur_pcb_addr + PCB_R12);  /* r12 */
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

    /* ── Current live RSP, RBP (for reference) ── */
    uint64_t rsp_val, rbp_val;
    __asm__ volatile("mov %%rsp, %0" : "=r"(rsp_val));
    __asm__ volatile("mov %%rbp, %0" : "=r"(rbp_val));
    out[41] = rsp_val;
    out[42] = rbp_val;

    /* ── Dump top of idle thread's kernel stack ── */
    if (idlethread) {
        uint64_t idle_kstack = read8(idlethread + TD_KSTACK);
        uint64_t idle_pages  = read8(idlethread + TD_KSTACK_PAGES);
        if (idle_kstack && idle_pages) {
            /* Stack top = kstack + pages * PAGE_SIZE */
            uint64_t stack_top = idle_kstack + idle_pages * 4096;
            /* Dump 32 qwords (256 bytes) from top of stack */
            for (int i = 0; i < 32; i++) {
                uint64_t addr = stack_top - 256 + (i * 8);
                out[43 + i] = read8(addr);
            }
        }
    }

    out[75] = 0xdeadbeefcafe0022ULL;

    /* Success */
    out32[1] = 0x0001;

    return 0;
}
