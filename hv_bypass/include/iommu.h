#pragma once
#include <stdint.h>
#include "smn.h"

/*
 * IOMMU exclusion range manipulation.
 *
 * The AMD IOMMU supports an "exclusion range" that bypasses address
 * translation for a specified physical address range. By setting this
 * to cover all of physical memory (0 to 0xFFFFFFFFFFFFF), devices
 * with DMA access (like the MP4 coprocessor) can read/write any
 * physical address without IOMMU intervention.
 *
 * Reference: fail0verflow/prosperous iommu.lua
 */

struct iommu_exclusion {
    uint64_t base;
    uint64_t limit;
};

/* Get current IOMMU exclusion range */
int iommu_get_exclusion(struct smn_ctx *ctx, struct iommu_exclusion *out);

/*
 * Set IOMMU exclusion range.
 * base: physical base address (bits [51:12] used)
 * size: size of the exclusion region
 */
int iommu_set_exclusion(struct smn_ctx *ctx, uint64_t base, uint64_t size);

/*
 * Disable IOMMU for all physical memory.
 * Sets exclusion range from 0 to 0xFFFFFFFFFFFFF (max 52-bit phys addr).
 */
int iommu_disable_all(struct smn_ctx *ctx);

/* Dump IOMMU register state (for debugging) */
void iommu_dump_regs(struct smn_ctx *ctx);
