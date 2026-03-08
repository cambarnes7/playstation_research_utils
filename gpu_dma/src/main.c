/*
 * gpu_dma — GPU DMA probe and exploit payload for PS5 FW 4.03
 *
 * Phase 0: Probe GNM API accessibility (libSceGnmDriverForNeoMode.sprx)
 * Phase 1: GPU DMA self-test (copy between userspace physical addresses)
 * Phase 2: Kernel address mapping (VA->PA translation for kdata, ktext via
 *          page table walk ONLY — never attempt CPU read of ktext pages)
 * Phase 3: GPU DMA kdata read/write test
 * Phase 4: GPU DMA ktext read attempt (XOM bypass via IOMMU path)
 * Phase 5: PCI/MMIO GPU probe (fallback if GNM unavailable)
 *
 * CRITICAL SAFETY NOTES:
 *   - NEVER read ktext via DMAP or kernel_copyout — causes kernel panic (XOM/NPT)
 *   - NEVER write ktext via CPU — causes kernel panic
 *   - ktext physical addresses can be DERIVED via page table walk without reading
 *   - Only the GPU DMA path (through IOMMU) can potentially bypass XOM
 *
 * Context from psdevwiki.com/ps5/Vulnerabilities:
 *   - GPU DMA to kernel .data: proven technique (flatz, FW 6.00+)
 *   - Uses sceGnmSubmitCommandBuffers + sceGnmSubmitDone from
 *     libSceGnmDriverForNeoMode.sprx (PS4 backwards-compat GNM driver)
 *   - Byepervisor bug #2: system-level debug flag in kdata survives rest mode,
 *     can be set via GPU DMA write to enable HV exploitation
 *   - Hypervisor bypass vulnerability exists for ≤FW 4.51 (we're on 4.03)
 *   - CR0.WP/XOM bypass: possibly unpatched until FW 5.00
 *   - "Without a Hypervisor bypass, limited to data-only attacks"
 *
 * PS5 Payload SDK userspace ELF. Requires kernel R/W via etaHEN.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <ps5/kernel.h>

/* PS5 system calls — available at runtime, not in SDK headers */
int sceKernelLoadStartModule(const char *name, size_t argc, const void *argv,
                             uint32_t flags, void *opt, int *res);
int sceKernelDlsym(int handle, const char *symbol, void **addr);

/* ===================================================================
 * Virtual-to-physical address translation
 * Adapted from usermode_phys_mem/include/dmem.h
 *
 * IMPORTANT: This walks the guest page tables to find the GPA (Guest
 * Physical Address) for a given GVA (Guest Virtual Address). The GPA
 * is what the GPU sees through the IOMMU. The CPU cannot read ktext
 * GPAs (XOM enforcement via NPT), but the GPU DMA engine might be
 * able to if the IOMMU doesn't replicate NPT restrictions.
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
#define PDE_RW_BIT      (1ULL << 1)
#define PDE_NX_BIT      (1ULL << 63)

static uint64_t g_dmap_base;
#define PADDR_TO_DMAP(paddr) ((paddr) + g_dmap_base)

/*
 * Translate virtual address to physical via guest page table walk.
 * This reads page table entries via DMAP (safe — page tables themselves
 * are in kdata, not ktext). Does NOT read the target page content.
 *
 * If pte_flags_out is non-NULL, stores the raw PTE of the leaf entry
 * so the caller can inspect RW/NX/present bits.
 */
static int64_t vaddr_to_paddr(uint64_t vaddr, uint64_t cr3,
                               uint64_t *pte_flags_out) {
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
        if (lv->leaf || (pde & PDE_PS_BIT)) {
            if (pte_flags_out)
                *pte_flags_out = pde;
            return paddr | (vaddr & (lv->size - 1));
        }
    }
    return -3;
}

/* Convenience wrapper without PTE output */
static int64_t va2pa(uint64_t vaddr, uint64_t cr3) {
    return vaddr_to_paddr(vaddr, cr3, NULL);
}

/* ===================================================================
 * Kernel info discovery
 * =================================================================== */

#define PROC_P_VMSPACE   0x200  /* FW 4.03 */
#define APIC_OPS_OFF     0x1656b0
#define PCPU0_OFF        0x64d2280

static int find_proc_pmap(intptr_t proc_kaddr, struct flat_pmap *out) {
    uint64_t vmspace = 0;
    kernel_copyout(proc_kaddr + PROC_P_VMSPACE, &vmspace, 8);
    if (!vmspace) return -1;

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
        printf("[-] Could not find pmap in vmspace\n");
        return -2;
    }

    *dmap_base = pm.pm_pml4 - pm.pm_cr3;
    *cr3 = pm.pm_cr3;
    printf("[+] PML4=%#lx CR3=%#lx DMAP=%#lx\n", pm.pm_pml4, pm.pm_cr3, *dmap_base);
    return 0;
}

/*
 * Find kernel_pmap_store by scanning kdata for its characteristic pattern.
 * Returns kernel CR3 on success, 0 on failure.
 */
static uint64_t find_kernel_cr3(uint64_t kdata_base) {
    uint64_t result = 0;
    struct flat_pmap kpm;

    printf("[*] Scanning kdata for kernel_pmap_store...\n");

    /* Read in larger chunks for efficiency */
    uint8_t *chunk = malloc(0x100000);
    if (!chunk) {
        printf("[-] malloc failed for scan buffer\n");
        return 0;
    }

    for (uint64_t base = 0; base < 0x4000000; base += 0x100000) {
        kernel_copyout(kdata_base + base, chunk, 0x100000);
        for (uint64_t off = 0; off + sizeof(kpm) < 0x100000; off += 8) {
            memcpy(&kpm, chunk + off, sizeof(kpm));
            if (kpm.mtx_flags == 0x1430000 && kpm.mtx_data == 0 &&
                kpm.mtx_lock == 0x4 && kpm.pm_pml4 != 0 &&
                (kpm.pm_pml4 & 0xFFFFFFFF) == (uint32_t)kpm.pm_cr3) {
                result = kpm.pm_cr3;
                printf("[+] kernel_pmap_store at kdata+%#lx  CR3=%#lx\n",
                       base + off, result);
                /* Last match wins (same heuristic as dmap_tests) */
            }
        }
    }
    free(chunk);

    if (!result)
        printf("[-] kernel_pmap_store not found\n");
    return result;
}

/* ===================================================================
 * Phase 0: GNM API Probe
 *
 * The confirmed working approach for GPU DMA on PS5 uses:
 *   sceGnmSubmitCommandBuffers() + sceGnmSubmitDone()
 * from libSceGnmDriverForNeoMode.sprx (PS4-compat GNM driver)
 *
 * This phase determines if these APIs are accessible from our
 * etaHEN payload context (not a game process).
 * =================================================================== */

/* Stored handles/pointers for later phases */
static int g_gnm_handle = -1;
static void *g_gnm_submit = NULL;
static void *g_gnm_done = NULL;

static void phase0_gnm_probe(void) {
    printf("\n=== Phase 0: GNM API Probe ===\n\n");

    /*
     * Priority order based on psdevwiki:
     * 1. libSceGnmDriverForNeoMode.sprx — confirmed to provide
     *    sceGnmSubmitCommandBuffers used in actual GPU DMA exploits
     * 2. libSceGnmDriver.sprx — native PS5 GNM (may need game context)
     * 3. Others as fallback
     */
    const char *libs[] = {
        /* Primary target — confirmed in GPU DMA exploits */
        "libSceGnmDriverForNeoMode.sprx",
        "/system/common/lib/libSceGnmDriverForNeoMode.sprx",
        /* PS5-native GNM */
        "libSceGnmDriver.sprx",
        "/system/common/lib/libSceGnmDriver.sprx",
        /* Alternative names */
        "libSceGraphicsDriver.sprx",
        "/system/common/lib/libSceGraphicsDriver.sprx",
        "libSceGnm.sprx",
        "/system/common/lib/libSceGnm.sprx",
    };

    const char *key_syms[] = {
        "sceGnmSubmitCommandBuffers",
        "sceGnmSubmitDone",
    };

    const char *extra_syms[] = {
        "sceGnmSubmitAndFlipCommandBuffers",
        "sceGnmMapComputeQueue",
        "sceGnmUnmapComputeQueue",
        "sceGnmDingDong",
        "sceGnmIsUserPaEnabled",
        "sceGnmInsertWaitFlipDone",
        "sceGnmGetEqTimeStamp",
    };

    for (int i = 0; i < (int)(sizeof(libs)/sizeof(libs[0])); i++) {
        printf("[*] Loading: %s\n", libs[i]);
        int handle = sceKernelLoadStartModule(libs[i], 0, NULL, 0, NULL, NULL);
        if (handle < 0) {
            printf("    FAIL (error %#x)\n\n", handle);
            continue;
        }
        printf("    OK (handle=%d)\n", handle);

        /* Resolve the two critical functions */
        void *submit = NULL, *done = NULL;
        sceKernelDlsym(handle, "sceGnmSubmitCommandBuffers", &submit);
        sceKernelDlsym(handle, "sceGnmSubmitDone", &done);

        printf("    sceGnmSubmitCommandBuffers: %p %s\n",
               submit, submit ? "FOUND" : "not found");
        printf("    sceGnmSubmitDone:           %p %s\n",
               done, done ? "FOUND" : "not found");

        if (submit && done && g_gnm_handle < 0) {
            g_gnm_handle = handle;
            g_gnm_submit = submit;
            g_gnm_done = done;
            printf("    >>> Using this library as GNM backend <<<\n");
        }

        /* Probe additional symbols */
        for (int j = 0; j < (int)(sizeof(extra_syms)/sizeof(extra_syms[0])); j++) {
            void *addr = NULL;
            if (sceKernelDlsym(handle, extra_syms[j], &addr) == 0 && addr)
                printf("    %s: %p\n", extra_syms[j], addr);
        }
        printf("\n");
    }

    /* Probe support libraries */
    printf("[*] Probing support libraries...\n");
    const char *support[] = {
        "libSceVideoOut.sprx",
        "libSceGpuAddress.sprx",
        "libSceComputeParser.sprx",
    };
    for (int i = 0; i < (int)(sizeof(support)/sizeof(support[0])); i++) {
        int h = sceKernelLoadStartModule(support[i], 0, NULL, 0, NULL, NULL);
        printf("  %s: %s (%d)\n", support[i], h >= 0 ? "OK" : "FAIL", h);
    }

    printf("\n=== Phase 0 Summary ===\n");
    if (g_gnm_submit && g_gnm_done) {
        printf("[+] GNM backend AVAILABLE\n");
        printf("[+] Submit=%p Done=%p\n", g_gnm_submit, g_gnm_done);
        printf("[+] Proceed to Phase 1 (self-test), then Phase 3/4 (GPU DMA ops)\n");
    } else {
        printf("[-] GNM NOT available from this context\n");
        printf("[-] Options:\n");
        printf("    a) Run Phase 5 (PCI/MMIO probe) for direct SDMA approach\n");
        printf("    b) Try from a game process context instead\n");
        printf("    c) Use BD-J if available (GnmUtils.copyPlanesBackgroundToPrimary)\n");
    }
}

/* ===================================================================
 * Phase 1: Physical Address Translation Self-Test
 * =================================================================== */

static void phase1_selftest(uint64_t cr3) {
    printf("\n=== Phase 1: PA Translation Self-Test ===\n\n");

    size_t buf_size = 4096;
    volatile uint32_t *src = mmap(NULL, buf_size, PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    volatile uint32_t *dst = mmap(NULL, buf_size, PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (src == MAP_FAILED || dst == MAP_FAILED) {
        printf("[-] mmap failed\n");
        return;
    }

    /* Fill + fault in pages */
    for (int i = 0; i < (int)(buf_size / 4); i++) {
        src[i] = 0xDEADBEEF;
        dst[i] = 0;
    }

    int64_t src_phys = va2pa((uint64_t)src, cr3);
    int64_t dst_phys = va2pa((uint64_t)dst, cr3);
    printf("[+] src: VA=%p PA=%#lx\n", (void *)src, src_phys);
    printf("[+] dst: VA=%p PA=%#lx\n", (void *)dst, dst_phys);

    if (src_phys < 0 || dst_phys < 0) {
        printf("[-] VA->PA failed\n");
        goto out;
    }

    /* Verify via DMAP round-trip */
    uint32_t check = 0;
    kernel_copyout(PADDR_TO_DMAP(src_phys), &check, 4);
    printf("[*] DMAP(src_phys): %#x %s\n", check,
           check == 0xDEADBEEF ? "OK" : "MISMATCH");

    uint32_t marker = 0xCAFEBABE;
    kernel_copyin(&marker, PADDR_TO_DMAP(dst_phys), 4);
    printf("[*] Wrote %#x via DMAP, dst VA reads: %#x %s\n",
           marker, dst[0], dst[0] == 0xCAFEBABE ? "OK" : "MISMATCH");

    if (check == 0xDEADBEEF && dst[0] == 0xCAFEBABE)
        printf("\n[+] PA translation WORKS. Ready for GPU DMA.\n");

out:
    munmap((void *)src, buf_size);
    munmap((void *)dst, buf_size);
    printf("\n=== Phase 1 Complete ===\n");
}

/* ===================================================================
 * Phase 2: Kernel Address Mapping (SAFE — page table walk only)
 *
 * Translates kernel VAs to physical addresses by walking guest page
 * tables. Reports PTE flags (RW, NX, present) for each mapping.
 *
 * DOES NOT read any ktext content — only reads page table entries
 * which are stored in kdata (safe to read via DMAP).
 * =================================================================== */

static void print_pte_flags(uint64_t pte) {
    printf("present=%d rw=%d nx=%d ps=%d",
           !!(pte & PDE_PRESENT_BIT),
           !!(pte & PDE_RW_BIT),
           !!(pte & PDE_NX_BIT),
           !!(pte & PDE_PS_BIT));
}

static void phase2_address_map(uint64_t proc_cr3,
                                uint64_t ktext_base, uint64_t kdata_base) {
    printf("\n=== Phase 2: Kernel Address Mapping ===\n\n");

    if (!ktext_base || !kdata_base) {
        printf("[-] Need ktext_base and kdata_base.\n");
        printf("    Usage: ./gpu_dma 2 <ktext_base_hex> <kdata_base_hex>\n");
        return;
    }

    printf("[+] ktext_base = %#lx\n", ktext_base);
    printf("[+] kdata_base = %#lx\n", kdata_base);

    /* Find kernel CR3 */
    uint64_t kernel_cr3 = find_kernel_cr3(kdata_base);
    if (!kernel_cr3) {
        printf("[-] Cannot find kernel CR3. Cannot translate kernel VAs.\n");
        return;
    }

    /*
     * Walk page tables for ktext and kdata addresses.
     * This is SAFE — we're reading page table entries (in kdata),
     * not the ktext content itself.
     *
     * The physical addresses we get can be fed to GPU DMA later.
     */
    printf("\n[*] Kernel page table walk results:\n");
    printf("    (Reading PTEs only — NOT reading ktext content)\n\n");

    struct { const char *name; uint64_t va; } targets[] = {
        {"ktext+0x000000",   ktext_base},
        {"ktext+0x001000",   ktext_base + 0x1000},
        {"ktext+0x100000",   ktext_base + 0x100000},
        {"ktext+0x200000",   ktext_base + 0x200000},
        {"ktext+0x294218",   ktext_base + 0x294218},  /* LSTAR handler */
        {"kdata+0x000000",   kdata_base},
        {"kdata+0x100000",   kdata_base + 0x100000},
        {"apic_ops",         kdata_base + APIC_OPS_OFF},
        {"pcpu[0]",          kdata_base + PCPU0_OFF},
    };

    printf("  %-20s %-20s %-20s %s\n", "Name", "VA", "PA", "PTE Flags");
    printf("  %-20s %-20s %-20s %s\n", "----", "--", "--", "---------");

    for (int i = 0; i < (int)(sizeof(targets)/sizeof(targets[0])); i++) {
        uint64_t pte = 0;
        int64_t pa = vaddr_to_paddr(targets[i].va, kernel_cr3, &pte);

        printf("  %-20s %#-20lx ", targets[i].name, targets[i].va);
        if (pa >= 0) {
            printf("%#-20lx ", pa);
            print_pte_flags(pte);
        } else {
            printf("%-20s (error %ld)", "FAILED", pa);
        }
        printf("\n");
    }

    /* Verify kdata translation is correct (safe — kdata is readable) */
    printf("\n[*] kdata DMAP verification (safe — kdata is CPU-readable):\n");
    int64_t kdata_pa = va2pa(kdata_base, kernel_cr3);
    if (kdata_pa >= 0) {
        uint64_t direct = 0, via_dmap = 0;
        kernel_copyout(kdata_base, &direct, 8);
        kernel_copyout(PADDR_TO_DMAP(kdata_pa), &via_dmap, 8);
        printf("    direct read:  %#lx\n", direct);
        printf("    DMAP read:    %#lx\n", via_dmap);
        printf("    match: %s\n", direct == via_dmap ? "YES" : "NO");
    }

    /* Analyze ktext PTE flags */
    printf("\n[*] ktext PTE analysis:\n");
    uint64_t ktext_pte = 0;
    int64_t ktext_pa = vaddr_to_paddr(ktext_base, kernel_cr3, &ktext_pte);
    if (ktext_pa >= 0) {
        printf("    ktext PA: %#lx\n", ktext_pa);
        printf("    Guest PTE: %#lx\n", ktext_pte);
        printf("    present=%d rw=%d user=%d nx=%d ps=%d\n",
               !!(ktext_pte & 1), !!(ktext_pte & 2), !!(ktext_pte & 4),
               !!(ktext_pte & PDE_NX_BIT), !!(ktext_pte & PDE_PS_BIT));
        printf("\n");
        printf("    NOTE: Guest PTE may show ktext as readable/writable.\n");
        printf("    XOM is enforced by the HYPERVISOR's NPT (nested page tables),\n");
        printf("    NOT by the guest page tables. The guest PTE flags are irrelevant\n");
        printf("    for XOM — the HV intercepts the access at the NPT level.\n");
        printf("\n");
        printf("    GPU DMA bypasses the CPU's NPT entirely — the GPU goes through\n");
        printf("    the IOMMU instead. If the IOMMU page tables don't replicate\n");
        printf("    the NPT's XOM restriction, GPU DMA can read ktext.\n");
        printf("\n");
        printf("    >>> DO NOT attempt to read ktext_pa via CPU (DMAP/copyout) <<<\n");
        printf("    >>> That will KERNEL PANIC due to NPT XOM enforcement     <<<\n");
    } else {
        printf("    ktext VA->PA FAILED (error %ld)\n", ktext_pa);
        printf("    ktext may not be in guest page tables at all.\n");
        printf("    The HV may map ktext only in NPT, not guest PT.\n");
    }

    /*
     * Byepervisor bug #2 context:
     * psdevwiki says "System Level debug flag in kernel data segment
     * and not wiped after rest mode". If we find this flag and set it
     * via GPU DMA write, we might enable HV exploitation.
     *
     * The exact offset is unknown — would need to scan kdata for it.
     */
    printf("\n[*] Byepervisor context:\n");
    printf("    psdevwiki reports a 'system-level debug flag' in kdata\n");
    printf("    that survives rest mode and can enable HV exploitation.\n");
    printf("    Setting it via GPU DMA write is a proven technique.\n");
    printf("    Exact kdata offset: UNKNOWN (needs further research).\n");
    printf("    HV bypass vuln exists for ≤FW 4.51 — we're on 4.03.\n");

    printf("\n=== Phase 2 Complete ===\n");
    printf("Physical addresses above can be used as GPU DMA targets.\n");
    printf("Proceed to Phase 3 (GPU DMA kdata test) then Phase 4 (ktext).\n");
}

/* ===================================================================
 * Phase 3: GPU DMA kdata Read/Write Test
 *
 * First real GPU DMA test — target kdata (known-safe to access).
 * Verifies the GPU DMA pipeline works before attempting ktext.
 * =================================================================== */

static void phase3_gpu_dma_kdata(uint64_t proc_cr3,
                                  uint64_t kdata_base) {
    printf("\n=== Phase 3: GPU DMA kdata Test ===\n\n");

    if (!kdata_base) {
        printf("[-] Need kdata_base.\n");
        return;
    }

    if (!g_gnm_submit || !g_gnm_done) {
        printf("[-] GNM not initialized. Run Phase 0 first.\n");
        printf("    (Or if GNM unavailable, need SDMA backend from Phase 5)\n");
        return;
    }

    uint64_t kernel_cr3 = find_kernel_cr3(kdata_base);
    if (!kernel_cr3) {
        printf("[-] Cannot find kernel CR3\n");
        return;
    }

    /* Get physical address of a known kdata location */
    int64_t kdata_pa = va2pa(kdata_base, kernel_cr3);
    if (kdata_pa < 0) {
        printf("[-] kdata VA->PA failed\n");
        return;
    }
    printf("[+] kdata PA: %#lx\n", kdata_pa);

    /* Allocate a receive buffer and get its physical address */
    size_t buf_size = 4096;
    volatile uint64_t *recv = mmap(NULL, buf_size, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (recv == MAP_FAILED) {
        printf("[-] mmap failed\n");
        return;
    }
    memset((void *)recv, 0, buf_size);

    int64_t recv_pa = va2pa((uint64_t)recv, proc_cr3);
    if (recv_pa < 0) {
        printf("[-] recv VA->PA failed\n");
        munmap((void *)recv, buf_size);
        return;
    }
    printf("[+] recv PA: %#lx\n", recv_pa);

    /*
     * Read kdata[0:64] via CPU first, for comparison.
     * (This is safe — kdata is CPU-readable.)
     */
    uint64_t expected[8];
    kernel_copyout(kdata_base, expected, 64);
    printf("[+] kdata[0:64] via CPU:\n");
    for (int i = 0; i < 8; i++)
        printf("    [%d] %#018lx\n", i, expected[i]);

    /*
     * NOW: Submit GPU DMA command buffer to copy:
     *   kdata_pa -> recv_pa (64 bytes)
     *
     * This is where we actually use the GPU.
     * The command buffer format uses PM4 DMA_COPY packets.
     *
     * TODO: Build and submit the actual command buffer.
     * The exact PM4 packet format depends on whether we're using
     * the GFX engine (PM4 Type 3 DMA_DATA packet) or SDMA engine
     * (SDMA linear copy packet).
     *
     * For sceGnmSubmitCommandBuffers, we submit PM4 packets to the
     * GFX command processor. The DMA_DATA packet (opcode 0x50) can
     * perform memory-to-memory copies using physical addresses.
     */

    printf("\n[*] GPU DMA command buffer submission:\n");
    printf("    src_pa  = %#lx (kdata)\n", kdata_pa);
    printf("    dst_pa  = %#lx (recv buffer)\n", recv_pa);
    printf("    size    = 64 bytes\n");

    /*
     * PM4 DMA_DATA packet (Type 3, opcode 0x50):
     *
     *   DWORD 0: header = (3 << 30) | (0x50 << 8) | (count-2)
     *   DWORD 1: control flags
     *            [20]    = 0 (engine_sel: ME)
     *            [21]    = 0 (src_sel: addr = memory address)
     *            [29:28] = 0 (dst_sel: addr = memory address)
     *            [31]    = 0 (raw_wait)
     *   DWORD 2: src_addr_lo
     *   DWORD 3: src_addr_hi
     *   DWORD 4: dst_addr_lo
     *   DWORD 5: dst_addr_hi
     *   DWORD 6: byte_count
     *
     * For GPU-visible physical addresses, we may need to set
     * src_sel/dst_sel to indicate physical (not virtual) addressing.
     * On AMD GCN/RDNA, sel=0 means "use address as-is" which may
     * be a GPU virtual address. For physical, we may need sel=3
     * (GDS) or use SDMA instead.
     *
     * Alternative: Use a compute shader that reads/writes via
     * flat_load/flat_store with physical addresses.
     */

    /* TODO: Actual GPU submission code here */
    printf("\n    [!] GPU command submission NOT YET IMPLEMENTED\n");
    printf("    [!] Need to determine:\n");
    printf("        1. Does sceGnmSubmitCommandBuffers use GPU-virtual or physical addrs?\n");
    printf("        2. If GPU-virtual, how to map kernel physical pages into GPU VA space?\n");
    printf("        3. If neither, need compute shader approach with uncached loads\n");

    munmap((void *)recv, buf_size);
    printf("\n=== Phase 3 Complete ===\n");
}

/* ===================================================================
 * Phase 5: PCI/MMIO GPU Probe (fallback)
 * =================================================================== */

static void phase5_pci_probe(void) {
    printf("\n=== Phase 5: GPU PCI / MMIO Probe ===\n\n");

    uint64_t ecam_candidates[] = { 0xE0000000ULL, 0xF0000000ULL, 0xC0000000ULL };

    for (int e = 0; e < 3; e++) {
        uint64_t ecam = ecam_candidates[e];
        printf("[*] ECAM base %#lx:\n", ecam);

        for (int bus = 0; bus < 3; bus++) {
            for (int dev = 0; dev < 32; dev++) {
                for (int fn = 0; fn < 8; fn++) {
                    uint64_t cfg = ecam + ((uint64_t)bus << 20) +
                                   ((uint64_t)dev << 15) +
                                   ((uint64_t)fn << 12);
                    uint32_t id = 0;
                    kernel_copyout(PADDR_TO_DMAP(cfg), &id, 4);

                    uint16_t vendor = id & 0xFFFF;
                    uint16_t device = id >> 16;
                    if (vendor == 0xFFFF || vendor == 0) continue;

                    printf("  [%d:%02d.%d] %04x:%04x", bus, dev, fn, vendor, device);

                    if (vendor == 0x1002) {
                        printf(" (AMD)");

                        /* Read class code */
                        uint32_t class_rev = 0;
                        kernel_copyout(PADDR_TO_DMAP(cfg + 0x08), &class_rev, 4);
                        uint8_t base_class = (class_rev >> 24) & 0xFF;
                        uint8_t sub_class = (class_rev >> 16) & 0xFF;
                        printf(" class=%02x/%02x", base_class, sub_class);

                        if (base_class == 0x03) {
                            printf(" <-- DISPLAY/GPU");

                            /* Read BARs */
                            for (int bar = 0; bar < 6; bar++) {
                                uint32_t lo = 0, hi = 0;
                                kernel_copyout(PADDR_TO_DMAP(cfg + 0x10 + bar*4), &lo, 4);
                                if ((lo & 0x6) == 0x4 && bar < 5) {
                                    kernel_copyout(PADDR_TO_DMAP(cfg + 0x14 + bar*4), &hi, 4);
                                    uint64_t addr = ((uint64_t)hi << 32) | (lo & ~0xFULL);
                                    printf("\n       BAR%d = %#lx (64-bit)", bar, addr);
                                    bar++; /* skip hi half */
                                } else if (lo & 1) {
                                    printf("\n       BAR%d = %#x (I/O)", bar, lo & ~0x3);
                                } else if (lo) {
                                    printf("\n       BAR%d = %#x (32-bit)", bar, lo & ~0xF);
                                }
                            }
                        }
                    }
                    printf("\n");
                }
            }
        }
        printf("\n");
    }

    printf("=== Phase 5 Complete ===\n");
}

/* ===================================================================
 * Main
 * =================================================================== */

int main(int argc, char *argv[]) {
    printf("=== GPU DMA Probe (PS5 FW 4.03) ===\n");
    printf("=== SAFETY: Will NEVER read ktext via CPU ===\n\n");

    int phase = -1;
    uint64_t ktext_base = 0, kdata_base = 0;

    if (argc > 1) phase = atoi(argv[1]);
    if (argc > 2) ktext_base = strtoull(argv[2], NULL, 16);
    if (argc > 3) kdata_base = strtoull(argv[3], NULL, 16);

    printf("[*] Phase: %d  PID: %d\n", phase, getpid());

    /* Discover DMAP base */
    uint64_t cr3 = 0;
    if (discover_dmap(&g_dmap_base, &cr3) < 0) {
        printf("[-] Cannot discover DMAP. Aborting.\n");
        return 1;
    }

    switch (phase) {
        case 0:
            phase0_gnm_probe();
            break;
        case 1:
            phase1_selftest(cr3);
            break;
        case 2:
            phase2_address_map(cr3, ktext_base, kdata_base);
            break;
        case 3:
            /* Run Phase 0 first to set up GNM, then Phase 3 */
            phase0_gnm_probe();
            phase3_gpu_dma_kdata(cr3, kdata_base);
            break;
        case 4:
            printf("[*] Phase 4: GPU DMA ktext read (XOM bypass)\n");
            printf("    NOT YET IMPLEMENTED — requires Phase 3 success first.\n");
            printf("    Will use GPU DMA to read ktext physical pages via IOMMU.\n");
            break;
        case 5:
            phase5_pci_probe();
            break;
        default:
            printf("Usage: %s <phase> [ktext_base_hex] [kdata_base_hex]\n\n", argv[0]);
            printf("Phases:\n");
            printf("  0: GNM API probe (load libSceGnmDriverForNeoMode, resolve symbols)\n");
            printf("  1: PA translation self-test (verify DMAP round-trip)\n");
            printf("  2: Kernel address map (VA->PA for ktext/kdata via page table walk)\n");
            printf("  3: GPU DMA kdata test (read kdata via GPU, compare with CPU read)\n");
            printf("  4: GPU DMA ktext read (XOM bypass — THE key experiment)\n");
            printf("  5: PCI/MMIO probe (find GPU BAR0 for direct SDMA fallback)\n");
            printf("\nRecommended order: 0 -> 1 -> 2 -> 3 -> 4\n");
            printf("If Phase 0 fails: 5 -> (implement SDMA backend) -> 3 -> 4\n");
            break;
    }

    printf("\n=== Done ===\n");
    return 0;
}
