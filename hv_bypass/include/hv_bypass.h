#pragma once
#include <stdint.h>

/*
 * PS5 Hypervisor Bypass - Main Interface
 *
 * Combines SMN/IOMMU manipulation with VMCB patching to disable
 * hypervisor protections on PS5 firmware 4.03.
 *
 * The approach (from fail0verflow/prosperous):
 *
 * 1. Use existing kernel R/W to access PCIe config space via DMAP
 * 2. Through PCIe config space, access SMN (System Management Network)
 * 3. Via SMN, disable IOMMU exclusion range to allow full phys mem DMA
 * 4. Disable TMR (Trusted Memory Region) protecting the MP4 carveout
 * 5. Patch VMCB (Virtual Machine Control Block) to disable HV intercepts
 * 6. Clear guest memory tagging to allow unrestricted kernel memory access
 *
 * Prerequisites:
 *   - Kernel read/write primitive (e.g. via IPv6 pktopts from prosper0gdb)
 *   - DMAP base address
 *   - Firmware 4.03 specific offsets
 */

/* TMR (Trusted Memory Region) registers in SMN space */
#define TMR_SMN_BASE      0x01250000UL
#define TMR_CONTROL_OFF   0x00
#define TMR_BASE_LO_OFF   0x04
#define TMR_BASE_HI_OFF   0x08
#define TMR_LIMIT_LO_OFF  0x0C
#define TMR_LIMIT_HI_OFF  0x10

/* MP4 carveout region on FW 4.03 */
#define MP4_CARVEOUT_BASE  0x60000000ULL
#define MP4_CARVEOUT_LIMIT 0x605F0000ULL

/*
 * VMCB (Virtual Machine Control Block) fields.
 * AMD-V VMCB layout offsets for intercept control.
 */
#define VMCB_INTERCEPT_CR_OFF     0x000  /* CR read/write intercepts */
#define VMCB_INTERCEPT_DR_OFF     0x004  /* DR read/write intercepts */
#define VMCB_INTERCEPT_EXC_OFF    0x008  /* Exception intercepts */
#define VMCB_INTERCEPT_MISC1_OFF  0x00C  /* Miscellaneous intercepts 1 */
#define VMCB_INTERCEPT_MISC2_OFF  0x010  /* Miscellaneous intercepts 2 */
#define VMCB_GUEST_ASID_OFF       0x058  /* Guest ASID */
#define VMCB_TLB_CONTROL_OFF      0x05C  /* TLB control */
#define VMCB_VMCB_CLEAN_OFF       0x0C0  /* VMCB clean bits */
#define VMCB_GUEST_PAT_OFF        0x268  /* Guest PAT */
#define VMCB_N_CR3_OFF            0x408  /* Nested page table CR3 */
#define VMCB_LBR_VIRT_OFF         0x410  /* LBR virtualization */
#define VMCB_GUEST_TAG_OFF        0x414  /* Guest memory encryption tag */

/*
 * Callback type for kernel R/W primitives.
 * The hv_bypass module needs these to access physical memory via DMAP.
 */
typedef void (*krw_write32_fn)(uint64_t kaddr, uint32_t val, void *ctx);
typedef uint32_t (*krw_read32_fn)(uint64_t kaddr, void *ctx);
typedef void (*krw_copyin_fn)(uint64_t kdst, const void *usrc, size_t len, void *ctx);
typedef void (*krw_copyout_fn)(void *udst, uint64_t ksrc, size_t len, void *ctx);

struct hv_bypass_ctx {
    uint64_t dmap_base;
    krw_write32_fn write32;
    krw_read32_fn read32;
    krw_copyin_fn copyin;
    krw_copyout_fn copyout;
    void *krw_arg;
};

/*
 * Initialize the hypervisor bypass context.
 * Must be called before any other hv_bypass function.
 */
int hv_bypass_init(struct hv_bypass_ctx *ctx, uint64_t dmap_base,
                   krw_write32_fn w32, krw_read32_fn r32,
                   krw_copyin_fn ci, krw_copyout_fn co,
                   void *krw_arg);

/*
 * Step 1: Disable IOMMU protections.
 * Sets the exclusion range to cover all physical memory.
 */
int hv_bypass_disable_iommu(struct hv_bypass_ctx *ctx);

/*
 * Step 2: Disable TMR protecting the MP4 carveout.
 * After this, x86 can directly access the MP4 memory region.
 * NOTE: On FW >= 5.00, TMR is no longer directly modifiable via SMN.
 */
int hv_bypass_disable_tmr(struct hv_bypass_ctx *ctx, uint32_t tmr_index);

/*
 * Step 3: Patch VMCB to disable hypervisor intercepts.
 * vmcb_pa: physical address of the target VMCB
 * Clears intercept bits and guest memory tagging.
 */
int hv_bypass_patch_vmcb(struct hv_bypass_ctx *ctx, uint64_t vmcb_pa);

/*
 * Scan physical memory for VMCB structures.
 * VMCBs can be identified by their characteristic layout.
 * Returns number of VMCBs found, fills vmcb_pas array.
 */
int hv_bypass_find_vmcbs(struct hv_bypass_ctx *ctx,
                         uint64_t *vmcb_pas, int max_vmcbs);

/*
 * High-level: run the full bypass sequence.
 * 1. Disable IOMMU
 * 2. Disable TMR (MP4 carveout, index 20)
 * 3. Find and patch all VMCBs
 * Returns 0 on success.
 */
int hv_bypass_run(struct hv_bypass_ctx *ctx);
