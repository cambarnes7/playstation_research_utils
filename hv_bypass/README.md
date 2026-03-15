# PS5 Hypervisor Bypass (FW 4.03)

Based on the technique from [fail0verflow/prosperous](https://github.com/fail0verflow/prosperous).

## Approach

The PS5 uses AMD-V (SVM) virtualization to run the FreeBSD kernel as a guest
under a custom hypervisor. The hypervisor controls memory access via nested
page tables and intercepts privileged operations via VMCB configuration.

This module bypasses the hypervisor by exploiting the SoC's hardware topology:

1. **IOMMU Exclusion** — Access AMD IOMMU registers via PCIe config space
   (B0:D0:F0) → SMN bus. Set the exclusion range to cover all physical memory,
   disabling DMA address translation.

2. **TMR Disable** — Disable the Trusted Memory Region protecting the MP4
   media coprocessor's carveout (0x60000000–0x605F0000). This allows x86 to
   read/write the MP4's memory directly. *(FW 4.03 and below only — on FW ≥ 5.00,
   TMR is no longer directly modifiable via SMN.)*

3. **VMCB Patching** — Scan physical memory for VMCB (Virtual Machine Control
   Block) structures and patch them to:
   - Clear all CR/DR/exception/misc intercepts
   - Clear guest memory tagging (offset 0x414)
   - Mark VMCB dirty to force reload

## Prerequisites

- Kernel read/write primitive (e.g., from `prosper0gdb` via IPv6 pktopts)
- DMAP base address (computed from `kernel_pmap_store`)
- PS5 firmware 4.03

## Building

With PS5 Payload SDK:
```
export PS5_PAYLOAD_SDK=/path/to/sdk
make
```

For local compilation testing (stub R/W):
```
make
```

## Integration with kstuff-no-fpkg

The module is designed to integrate with the existing `prosper0gdb` kernel R/W.
See `src/main.c` for the callback wiring. To use from within `ps5-kstuff`:

```c
#include "hv_bypass.h"

// Use prosper0gdb's copyin/copyout as the R/W backend
struct hv_bypass_ctx ctx;
hv_bypass_init(&ctx, dmap_base, my_write32, my_read32, my_copyin, my_copyout, NULL);
hv_bypass_run(&ctx);
```

## Files

| File | Description |
|------|-------------|
| `include/smn.h` | SMN (System Management Network) register access via PCIe ECAM |
| `include/iommu.h` | IOMMU exclusion range manipulation |
| `include/hv_bypass.h` | Main interface — TMR, VMCB, and orchestration |
| `src/smn.c` | SMN read/write implementation |
| `src/iommu.c` | IOMMU exclusion disable |
| `src/hv_bypass.c` | TMR disable, VMCB scan/patch, full bypass sequence |
| `src/main.c` | Example standalone usage |

## Key Addresses (FW 4.03)

| What | Address |
|------|---------|
| PCIe ECAM base | `0xF0000000` |
| SMN index reg (B0:D0:F0+0xA0) | via DMAP |
| IOMMU base (SMN) | `0x02400000` |
| TMR base (SMN) | `0x01250000` |
| MP4 carveout | `0x60000000`–`0x605F0000` |

## References

- [fail0verflow/prosperous](https://github.com/fail0verflow/prosperous) — Original MP4/IOMMU technique
- AMD IOMMU Specification — Exclusion range registers
- AMD APM Vol. 2 — VMCB layout and SVM intercepts
