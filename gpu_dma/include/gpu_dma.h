#pragma once

/*
 * GPU DMA abstraction layer
 *
 * Provides a unified interface for GPU DMA operations regardless of backend:
 *   - GNM API backend (sceGnmSubmitCommandBuffers)
 *   - Direct SDMA MMIO backend (programs GPU registers directly)
 */

#include <stdint.h>

/* Backend type */
enum gpu_backend {
    GPU_BACKEND_NONE = 0,
    GPU_BACKEND_GNM,       /* Using sceGnm* APIs */
    GPU_BACKEND_SDMA,      /* Direct SDMA register programming */
};

/* GPU DMA context */
struct gpu_dma_ctx {
    enum gpu_backend backend;

    /* GNM backend state */
    void *gnm_submit_fn;      /* sceGnmSubmitCommandBuffers */
    void *gnm_done_fn;        /* sceGnmSubmitDone */
    int gnm_module_handle;

    /* SDMA backend state */
    uint64_t gpu_mmio_base;   /* GPU MMIO BAR0 physical address */
    uint64_t dmap_base;       /* DMAP base for phys-to-virt */
    uint64_t sdma_rb_base;    /* SDMA ring buffer physical base */
    uint32_t sdma_rb_size;    /* Ring buffer size in bytes */
    uint32_t sdma_rb_wptr;    /* Current write pointer */

    /* Common state */
    uint64_t kernel_cr3;      /* Kernel page table root */
    uint64_t ktext_base;      /* Kernel .text virtual base */
    uint64_t kdata_base;      /* Kernel .data virtual base */

    /* Completion fence */
    volatile uint32_t *fence_va;   /* Virtual address of fence DWORD */
    uint64_t fence_phys;           /* Physical address of fence DWORD */
};

/* Result codes */
enum gpu_dma_result {
    GPU_OK = 0,
    GPU_ERR_NO_GNM = -1,        /* GNM library not found */
    GPU_ERR_NO_SYMBOLS = -2,    /* GNM functions not resolved */
    GPU_ERR_NO_GPU_BAR = -3,    /* GPU MMIO BAR not found */
    GPU_ERR_SDMA_INIT = -4,     /* SDMA ring init failed */
    GPU_ERR_SUBMIT = -5,        /* Command submission failed */
    GPU_ERR_TIMEOUT = -6,       /* DMA operation timed out */
    GPU_ERR_VADDR_XLAT = -7,    /* Virtual-to-physical translation failed */
    GPU_ERR_IOMMU_BLOCK = -8,   /* IOMMU blocked the access */
};

/*
 * Initialize GPU DMA context.
 * Tries GNM first, falls back to SDMA if GNM unavailable.
 * Requires dmap_base and kernel_cr3 to be set before calling.
 */
int gpu_dma_init(struct gpu_dma_ctx *ctx);

/*
 * GPU DMA read: copy `size` bytes from physical address `src_phys`
 * to userspace buffer `dst`.
 *
 * Uses an intermediate bounce buffer whose physical address is known.
 * The GPU copies src_phys → bounce_phys, then CPU reads bounce_va.
 */
int gpu_dma_read_phys(struct gpu_dma_ctx *ctx,
                      uint64_t src_phys, void *dst, uint32_t size);

/*
 * GPU DMA write: copy `size` bytes from userspace buffer `src`
 * to physical address `dst_phys`.
 */
int gpu_dma_write_phys(struct gpu_dma_ctx *ctx,
                       const void *src, uint64_t dst_phys, uint32_t size);

/*
 * Translate kernel virtual address to physical using page table walk.
 */
int64_t gpu_kva_to_phys(struct gpu_dma_ctx *ctx, uint64_t kva);
