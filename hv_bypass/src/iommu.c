#include "../include/iommu.h"

int iommu_get_exclusion(struct smn_ctx *ctx, struct iommu_exclusion *out)
{
    out->base = smn_read64(ctx, IOMMU_SMN_BASE + IOMMU_EXCL_BASE_OFF);
    out->limit = smn_read64(ctx, IOMMU_SMN_BASE + IOMMU_EXCL_LIMIT_OFF);
    return 0;
}

/*
 * Set IOMMU exclusion range.
 * From AMD IOMMU spec:
 *   ExclBase [51:12] = base physical address
 *   ExclBase [1]     = ExclAllow (allow all devices)
 *   ExclBase [0]     = ExclEn (enable exclusion)
 *   ExclLimit [51:12] = limit physical address
 */
int iommu_set_exclusion(struct smn_ctx *ctx, uint64_t base, uint64_t size)
{
    uint64_t limit = base + size - 1;

    /* Write limit first, then base with enable + allow bits */
    smn_write64(ctx, IOMMU_SMN_BASE + IOMMU_EXCL_LIMIT_OFF, limit);
    smn_write64(ctx, IOMMU_SMN_BASE + IOMMU_EXCL_BASE_OFF,
                base | IOMMU_EXCL_ENABLE | IOMMU_EXCL_ALLOW);

    /* Verify */
    struct iommu_exclusion verify;
    iommu_get_exclusion(ctx, &verify);

    if ((verify.base & IOMMU_EXCL_ENABLE) == 0)
        return -1; /* Failed to set exclusion */

    return 0;
}

int iommu_disable_all(struct smn_ctx *ctx)
{
    /* Check if already disabled (base=3 means enabled+allow at addr 0) */
    struct iommu_exclusion current;
    iommu_get_exclusion(ctx, &current);

    uint64_t max_limit = 0x000FFFFFFFFFF000ULL; /* bits [51:12] all set */

    if ((current.base & 0x3) == 0x3 && current.limit == max_limit)
        return 0; /* Already covering all memory */

    /* Set exclusion from 0 to max physical address */
    return iommu_set_exclusion(ctx, 0, 0xFFFFFFFFFFFFFFFFULL);
}

void iommu_dump_regs(struct smn_ctx *ctx)
{
    /* Dump IOMMU registers at offsets 0x00-0x30 for debugging */
    /* Caller should print these values */
    for (uint32_t off = 0; off <= 0x30; off += 8) {
        /* Read is done, caller can use smn_read64 directly */
        (void)smn_read64(ctx, IOMMU_SMN_BASE + off);
    }
}
