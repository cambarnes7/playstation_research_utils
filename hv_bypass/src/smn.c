#include "../include/smn.h"

void smn_init(struct smn_ctx *ctx, uint64_t dmap_base,
              void (*pw32)(uint64_t, uint32_t, void*),
              uint32_t (*pr32)(uint64_t, void*),
              void *rw_arg)
{
    ctx->dmap_base = dmap_base;
    ctx->phys_write32 = pw32;
    ctx->phys_read32 = pr32;
    ctx->rw_arg = rw_arg;
}

/*
 * SMN register access works by writing the target SMN address to
 * B0:D0:F0 + 0xA0 (index), then reading/writing the data at
 * B0:D0:F0 + 0xA4 (data).
 *
 * Since PCIe config space is memory-mapped at PCIE_CFG_BASE (0xF0000000),
 * we access it via the kernel's DMAP (direct physical mapping).
 */

uint32_t smn_read32(struct smn_ctx *ctx, uint32_t addr)
{
    uint64_t b0d0f0_dmap = ctx->dmap_base + B0D0F0;

    /* Write SMN address to index register */
    ctx->phys_write32(b0d0f0_dmap + SMN_INDEX_REG, addr, ctx->rw_arg);

    /* Read data from data register */
    return ctx->phys_read32(b0d0f0_dmap + SMN_DATA_REG, ctx->rw_arg);
}

void smn_write32(struct smn_ctx *ctx, uint32_t addr, uint32_t val)
{
    uint64_t b0d0f0_dmap = ctx->dmap_base + B0D0F0;

    /* Write SMN address to index register */
    ctx->phys_write32(b0d0f0_dmap + SMN_INDEX_REG, addr, ctx->rw_arg);

    /* Write data to data register */
    ctx->phys_write32(b0d0f0_dmap + SMN_DATA_REG, val, ctx->rw_arg);
}

uint64_t smn_read64(struct smn_ctx *ctx, uint32_t addr)
{
    uint32_t lo = smn_read32(ctx, addr);
    uint32_t hi = smn_read32(ctx, addr + 4);
    return ((uint64_t)hi << 32) | lo;
}

void smn_write64(struct smn_ctx *ctx, uint32_t addr, uint64_t val)
{
    smn_write32(ctx, addr, (uint32_t)(val & 0xFFFFFFFF));
    smn_write32(ctx, addr + 4, (uint32_t)(val >> 32));
}
