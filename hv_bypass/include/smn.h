#pragma once
#include <stdint.h>

/*
 * SMN (System Management Network) access via PCIe config space.
 *
 * On AMD APUs (Aeolia/Belize SoC in PS5), the SMN bus is accessible
 * through PCI device B0:D0:F0 registers 0xA0 (address) and 0xA4 (data).
 * This gives access to IOMMU configuration, TMR control, and other
 * low-level SoC peripherals.
 *
 * Requires: physical memory read/write (via DMAP or kernel R/W primitive)
 *
 * Reference: fail0verflow/prosperous iommu.lua
 */

/* PCIe ECAM base for PS5 (Belize SoC) */
#define PCIE_CFG_BASE 0xF0000000ULL

/* SMN index/data registers on B0:D0:F0 */
#define SMN_INDEX_REG 0xA0
#define SMN_DATA_REG  0xA4

/* IOMMU base address in SMN space */
#define IOMMU_SMN_BASE 0x02400000UL

/* IOMMU exclusion range registers (relative to IOMMU_SMN_BASE) */
#define IOMMU_EXCL_BASE_OFF  0x20
#define IOMMU_EXCL_LIMIT_OFF 0x28

/* Exclusion range control bits */
#define IOMMU_EXCL_ENABLE 0x1
#define IOMMU_EXCL_ALLOW  0x2

/*
 * Compute PCIe ECAM config space address for a given BDF.
 * bus << 20 | dev << 15 | fn << 12
 */
static inline uint64_t pci_cfg_addr(uint8_t bus, uint8_t dev, uint8_t fn)
{
    return PCIE_CFG_BASE
        + ((uint64_t)bus << 20)
        + ((uint64_t)dev << 15)
        + ((uint64_t)fn << 12);
}

/* B0:D0:F0 config space base (root complex) */
#define B0D0F0 (pci_cfg_addr(0, 0, 0))

/*
 * Context for SMN operations.
 * Callers must supply dmap_base (kernel direct-map base) and
 * a physical memory write function.
 */
struct smn_ctx {
    uint64_t dmap_base;
    /* kernel R/W primitives - caller provides these */
    void (*phys_write32)(uint64_t dmap_addr, uint32_t val, void *arg);
    uint32_t (*phys_read32)(uint64_t dmap_addr, void *arg);
    void *rw_arg;
};

/* Initialize SMN context */
void smn_init(struct smn_ctx *ctx, uint64_t dmap_base,
              void (*pw32)(uint64_t, uint32_t, void*),
              uint32_t (*pr32)(uint64_t, void*),
              void *rw_arg);

/* Read/write 32-bit SMN register */
uint32_t smn_read32(struct smn_ctx *ctx, uint32_t addr);
void smn_write32(struct smn_ctx *ctx, uint32_t addr, uint32_t val);

/* Read/write 64-bit SMN register (two 32-bit accesses) */
uint64_t smn_read64(struct smn_ctx *ctx, uint32_t addr);
void smn_write64(struct smn_ctx *ctx, uint32_t addr, uint64_t val);
