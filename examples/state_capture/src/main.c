#include <stdint.h>

/*
 * state_capture v6 — Complete CPU state snapshot
 *
 * v5.1 proved: inline rdmsr, mov crN, sgdt, sidt, gs:N all work from kproc.
 * v5.1 also mapped struct pcpu (56 qwords from GSBASE).
 *
 * v6 captures ALL remaining CPU registers in a single run:
 * - Control registers: CR0, CR2, CR3, CR4
 * - Standard MSRs: EFER, STAR, LSTAR, CSTAR, SFMASK, FSBASE, GSBASE, KGSBASE
 * - AMD MSRs: SYSCFG, TOP_MEM, TOP_MEM2, VM_CR, VM_HSAVE_PA
 * - Debug registers: DR0-DR3, DR6, DR7
 * - XCR0 via xgetbv
 * - GDT/IDT base+limit via sgdt/sidt
 *
 * AMD MSRs (SYSCFG, VM_CR, VM_HSAVE_PA) may #GP if trapped by hypervisor.
 * Strategy: attempt all in one run. If panic, rebuild without them.
 *
 * Mode (via fw_ver):
 *   0x5: CPUSTATE — complete CPU register snapshot (64 qwords)
 *   0x6: DUMP — curthread struct + td_pcb dump
 *   0x7: SCAN — kdata scanner (find susppcbs)
 *         bits 5-6: filter (00=heap ptr, 01=CR3 exact, 10=CR0 exact)
 *         bit 7: broaden ptr filter to 0xffff???? (only when bits 5-6=00)
 *         bits 8-31: scan page (each page = 4MB)
 *
 * Output layout (uint64_t indices, 64 qwords = 0x200 bytes readback limit):
 *
 * Mode 0x5 (CPUSTATE):
 *   [0]   magic(lo32) | status(hi32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   lstar
 *   [4]   cr3
 *   [5]   gsbase
 *   [6]   curthread
 *   [7]   td_pcb
 *   --- Control registers ---
 *   [8]   cr0
 *   [9]   cr2   (last page fault address)
 *   [10]  cr4
 *   --- Standard MSRs ---
 *   [11]  efer
 *   [12]  star
 *   [13]  cstar
 *   [14]  sfmask
 *   [15]  fsbase
 *   [16]  kgsbase
 *   --- Extended state ---
 *   [17]  xcr0  (xgetbv ecx=0)
 *   --- Debug registers ---
 *   [18]  dr0
 *   [19]  dr1
 *   [20]  dr2
 *   [21]  dr3
 *   [22]  dr6   (debug status)
 *   [23]  dr7   (debug control)
 *   --- Descriptor tables ---
 *   [24]  gdt_base
 *   [25]  gdt_limit (lo16)
 *   [26]  idt_base
 *   [27]  idt_limit (lo16)
 *   --- AMD-specific MSRs (may #GP if HV-trapped) ---
 *   [28]  syscfg    (0xC0010010)
 *   [29]  top_mem   (0xC001001A)
 *   [30]  top_mem2  (0xC001001D)
 *   [31]  vm_cr     (0xC0010114) — SVM lock/disable bits
 *   [32]  vm_hsave_pa (0xC0010117) — HV host save area phys addr
 *   --- Per-CPU summary (first 5 fields from GSBASE) ---
 *   [33]  pc_curthread  (GSBASE+0x00)
 *   [34]  pc_idlethread (GSBASE+0x08)
 *   [35]  pc_fpcurthread(GSBASE+0x10)
 *   [36]  pc_curpcb     (GSBASE+0x20)
 *   [37]  pc_cpuid      (GSBASE+0x34, hi32) | pc_switchticks (lo32)
 *   [38..62] reserved (zero)
 *   [63]  end marker
 *
 * Mode 0x6 (DUMP): unchanged from v5.1
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

/* AMD-specific MSRs */
#define MSR_SYSCFG       0xC0010010
#define MSR_TOP_MEM      0xC001001A
#define MSR_TOP_MEM2     0xC001001D
#define MSR_VM_CR        0xC0010114
#define MSR_VM_HSAVE_PA  0xC0010117

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

static inline uint64_t read_cr2(void)
{
    uint64_t v;
    __asm__ volatile("movq %%cr2, %0" : "=r"(v));
    return v;
}

static inline uint64_t read_cr4(void)
{
    uint64_t v;
    __asm__ volatile("movq %%cr4, %0" : "=r"(v));
    return v;
}

static inline uint64_t read_xcr0(void)
{
    uint32_t lo, hi;
    __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t read_dr0(void)
{
    uint64_t v;
    __asm__ volatile("movq %%db0, %0" : "=r"(v));
    return v;
}

static inline uint64_t read_dr1(void)
{
    uint64_t v;
    __asm__ volatile("movq %%db1, %0" : "=r"(v));
    return v;
}

static inline uint64_t read_dr2(void)
{
    uint64_t v;
    __asm__ volatile("movq %%db2, %0" : "=r"(v));
    return v;
}

static inline uint64_t read_dr3(void)
{
    uint64_t v;
    __asm__ volatile("movq %%db3, %0" : "=r"(v));
    return v;
}

static inline uint64_t read_dr6(void)
{
    uint64_t v;
    __asm__ volatile("movq %%db6, %0" : "=r"(v));
    return v;
}

static inline uint64_t read_dr7(void)
{
    uint64_t v;
    __asm__ volatile("movq %%db7, %0" : "=r"(v));
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
         * MODE 0x5: CPUSTATE — Complete CPU register snapshot
         *
         * ZERO function calls. ZERO writes to kdata.
         * All 64 qwords fit within debug readback limit (0x200 bytes).
         *
         * Includes AMD MSRs (SYSCFG, VM_CR, VM_HSAVE_PA) which may
         * #GP if trapped by the hypervisor. If this run panics,
         * rebuild with AMD MSRs commented out.
         * ============================================================ */
        for (int i = 0; i < 288; i++) out[i] = 0;

        /* [1-4] Header: base addresses */
        out[1] = kdata_base;
        out[2] = ktext_base;
        out[3] = lstar;
        out[4] = cr3;

        /* [5-7] Thread context */
        uint64_t gsbase = rdmsr(MSR_GSBASE);
        out[5] = gsbase;

        uint64_t curthread;
        __asm__ volatile("movq %%gs:0, %0" : "=r"(curthread));
        out[6] = curthread;

        uint64_t td_pcb = 0;
        if (curthread)
            td_pcb = read8(curthread + TD_PCB);
        out[7] = td_pcb;

        /* [8-10] Control registers */
        out[8]  = read_cr0();
        out[9]  = read_cr2();
        out[10] = read_cr4();

        /* [11-16] Standard MSRs */
        out[11] = rdmsr(MSR_EFER);
        out[12] = rdmsr(MSR_STAR);
        out[13] = rdmsr(MSR_CSTAR);
        out[14] = rdmsr(MSR_SFMASK);
        out[15] = rdmsr(MSR_FSBASE);
        out[16] = rdmsr(MSR_KGSBASE);

        /* [17] Extended state */
        out[17] = read_xcr0();

        /* [18-23] Debug registers */
        out[18] = read_dr0();
        out[19] = read_dr1();
        out[20] = read_dr2();
        out[21] = read_dr3();
        out[22] = read_dr6();
        out[23] = read_dr7();

        /* [24-27] Descriptor tables */
        dt_reg gdt, idt;
        __asm__ volatile("sgdt %0" : "=m"(gdt));
        __asm__ volatile("sidt %0" : "=m"(idt));
        out[24] = gdt.base;
        out[25] = gdt.limit;
        out[26] = idt.base;
        out[27] = idt.limit;

        /* [28-32] AMD-specific MSRs — CONFIRMED #GP (panic in v6 first run)
         * The hypervisor traps these. Left as zero.
         * TODO: test individually to find which specific MSR(s) trap. */
        /* out[28] = rdmsr(MSR_SYSCFG);      — #GP trapped */
        /* out[29] = rdmsr(MSR_TOP_MEM);      — #GP trapped */
        /* out[30] = rdmsr(MSR_TOP_MEM2);     — #GP trapped */
        /* out[31] = rdmsr(MSR_VM_CR);        — #GP trapped */
        /* out[32] = rdmsr(MSR_VM_HSAVE_PA);  — #GP trapped */

        /* [33-37] Per-CPU summary (key fields from struct pcpu at GSBASE) */
        out[33] = read8(gsbase + 0x00);  /* pc_curthread */
        out[34] = read8(gsbase + 0x08);  /* pc_idlethread */
        out[35] = read8(gsbase + 0x10);  /* pc_fpcurthread */
        out[36] = read8(gsbase + 0x20);  /* pc_curpcb */
        out[37] = read8(gsbase + 0x30);  /* pc_switchticks(lo32) | pc_cpuid(hi32) */

        /* [38-62] reserved */

        out32[0] = MAGIC_SCAP;
        out32[1] = 0x0005;
        out[63] = 0xdeadbeefcafe0050ULL;
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

    if ((mode & 0x07) == 0x7) {
        /* ============================================================
         * MODE 0x7: kdata scanner
         *
         * Scans kdata for qwords matching a configurable filter.
         * Used to find susppcbs and other kernel structures.
         *
         * fw_ver encoding:
         *   bits 0-2:  mode (0x7)
         *   bits 3-4:  unused
         *   bits 5-6:  filter type:
         *     0b00 (0x07): narrow — upper32 == 0xffffff80 (heap PCB ptrs)
         *     0b01 (0x27): CR3 exact — match current CR3 value
         *     0b10 (0x47): CR0 exact — match current CR0 value
         *     0b11 (0x67): MEMDUMP — dump 32 qwords from target address
         *              target = kdata_base + 0x27ed600 + page * 0x100
         *              page=0: dumps PCB candidate at +0x27ed600
         *              page=1: dumps +0x27ed700, etc.
         *   bit 7:     broaden narrow filter to 0xffff???? (heap ptrs)
         *              only applies when bits 5-6 == 0b00
         *   bits 8-31: scan page (each page = 4MB = 0x400000 bytes)
         *
         * CR3 scan (0x27): after rest mode, susppcbs PCBs contain CR3.
         *   Finds pcb_cr3 fields directly in kdata BSS.
         *   fw_ver = 0x27 | (page << 8)
         *
         * CR0 scan (0x47): secondary confirmation — CR0 is constant.
         *   fw_ver = 0x47 | (page << 8)
         *
         * Output layout (288 qwords):
         *   [0]   magic | status
         *   [1]   kdata_base
         *   [2]   ktext_base
         *   [3]   scan_base
         *   [4]   scan_end
         *   [5]   hit_count
         *   [6]   last_scan_addr
         *   [7]   total_scanned | (filter_type << 48)
         *   [8..287] hits: pairs of (address, value), up to 140 hits
         * ============================================================ */
        uint32_t raw_fwver = args->fw_ver;
        uint32_t page = raw_fwver >> 8;
        uint32_t filter_type = (raw_fwver >> 5) & 3;
        uint32_t broad = (raw_fwver >> 7) & 1;

        uint64_t scan_base = kdata_base + (uint64_t)page * 0x400000ULL;
        uint64_t scan_end  = scan_base + 0x400000ULL;

        /* Precompute search targets for exact-value filters */
        uint64_t search_cr3 = cr3;
        uint64_t search_cr0 = read_cr0();

        for (int i = 0; i < 288; i++) out[i] = 0;

        out[1] = kdata_base;
        out[2] = ktext_base;
        out[3] = scan_base;
        out[4] = scan_end;

        /* Use output buffer directly as counters — volatile locals
         * get corrupted by -Os register reuse (v7.0 proved this). */
        out[5] = 0;  /* hit_count */
        out[6] = 0;  /* last_scan_addr */
        out[7] = 0;  /* total_scanned */

        if (filter_type == 3) {
            /* MEMDUMP: dump 32 qwords from target address */
            uint64_t target = kdata_base + 0x27ed600ULL + (uint64_t)page * 0x100ULL;
            out[3] = target;           /* report target address */
            out[4] = target + 0x100;   /* end */
            out[5] = 32;               /* "hit_count" = number of qwords dumped */
            out[6] = target;
            out[7] = ((uint64_t)filter_type << 48) | 32;

            for (int i = 0; i < 32; i++) {
                out[8 + i * 2]     = target + i * 8;  /* address */
                out[8 + i * 2 + 1] = *(volatile uint64_t *)(target + i * 8); /* value */
            }
        } else {
            uint64_t addr;
            for (addr = scan_base; addr < scan_end; addr += 8) {
                uint64_t val = *(volatile uint64_t *)addr;

                int match = 0;
                if (filter_type == 1) {
                    /* CR3 exact match */
                    match = (val == search_cr3);
                } else if (filter_type == 2) {
                    /* CR0 exact match */
                    match = (val == search_cr0);
                } else {
                    /* Pointer pattern filter (original) */
                    uint32_t upper = (uint32_t)(val >> 32);
                    if (broad)
                        match = (upper >> 16) == 0xffff && upper != 0xffffffff;
                    else
                        match = upper == 0xffffff80;
                }

                if (match && out[5] < 140) {
                    uint64_t idx = out[5];
                    out[8 + idx * 2]     = addr;
                    out[8 + idx * 2 + 1] = val;
                    out[5] = idx + 1;
                }
            }

            out[6] = addr - 8;  /* last address scanned */
            out[7] = ((uint64_t)filter_type << 48) | ((addr - scan_base) >> 3);
        }

        out32[0] = MAGIC_SCAP;
        out32[1] = 0x0007;
        out[287] = 0xdeadbeefcafe0070ULL;
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
