# prosperous_port - PS5 HV Bypass for FW 4.03

Port of [fail0verflow's prosperous](https://github.com/fail0verflow/prosperous) exploit chain, adapted for PS5 firmware 4.03.

## Overview

This exploit achieves full hypervisor bypass on PS5 4.03 by:

1. **TMR Bypass** - Disabling AMD Trusted Memory Region protections via PCI config registers
2. **MP4 Payload** - Injecting an AArch64 EL3 payload onto the ARM Cortex-A53 coprocessor
3. **VMCB Patching** - Using the MP4 to disable nested paging in AMD SVM control blocks
4. **NDA Disable** - Clearing Non-Debug Area enforcement on all CPU cores
5. **Kernel RPC** - Starting a TCP server on port 6670 for remote kernel access

## Architecture

```
┌─────────────────────────────────────────────────────┐
│ Host PC (Python client on port 6670)                │
└──────────────────────┬──────────────────────────────┘
                       │ TCP
┌──────────────────────▼──────────────────────────────┐
│ PS5 Kernel (kpayload RPC server thread)             │
│  ├─ Memory R/W (kernel VA + DMAP physical)          │
│  ├─ SMN register access                             │
│  ├─ MP4 command relay                               │
│  ├─ Data Fabric access                              │
│  └─ SBL service requests (PSP communication)        │
├─────────────────────────────────────────────────────┤
│ AMD SVM HV (nested paging DISABLED)                 │
├─────────────────────────────────────────────────────┤
│ MP4 ARM Cortex-A53 (EL3 payload)                    │
│  ├─ Memory R/W (bypasses x86 protections)           │
│  ├─ SysHub TLB manipulation                         │
│  └─ Cache management                                │
└─────────────────────────────────────────────────────┘
```

## Prerequisites

- PS5 on firmware 4.03 (CEX)
- Kernel R/W exploit loaded (e.g., ps5-kstuff via etaHEN)
- PS5 Payload SDK (`PS5_PAYLOAD_SDK` env var)
- Network connectivity to PS5

## Building

```bash
# Build the main exploit payload
export PS5_PAYLOAD_SDK=/path/to/ps5-payload-dev/sdk
make

# Optionally rebuild MP4 payload (requires aarch64 cross-compiler)
make mp4_payload

# Optionally rebuild kernel payload (requires host g++)
make kpayload
```

## Deployment

```bash
# Deploy to PS5
make test PS5_HOST=192.168.x.x

# Or manually
$PS5_PAYLOAD_SDK/toolchain/bin/ps5-deploy -h 192.168.x.x -p 9021 prosperous_port.elf
```

## Usage

After deployment, connect with the Python client:

```bash
cd client
python3 client.py 192.168.x.x
```

Or use the client library in your own scripts:

```python
from client import Client, Dmap, TmrAccess

with Client(('192.168.x.x', 6670)) as c:
    info = c.runtime_info()
    print(f"Kernel base: {info.kernel_base:#x}")

    # Read kernel memory
    data = c.mem_read(info.kernel_base, 0x100)

    # Physical memory via DMAP
    dmap = Dmap(c)
    val = dmap.read_u64(0x60000000)

    # SMN registers
    iommu_ctl = c.smn_read32(0x02400000)

    # MP4 coprocessor
    mp4_data = c.mp4_read(0x03230000, 0x100)
```

## Differences from Original

| Aspect | Original (FW 3.00) | This Port (FW 4.03) |
|--------|-------------------|---------------------|
| Entry vector | Don't Starve save file Lua exploit | PS5 Payload SDK (requires existing jailbreak) |
| Kernel exploit | UMTX use-after-free | Existing kekcall infrastructure |
| Kernel offsets | FW 3.00 hardcoded | FW 4.03 adapted |
| MP4 payload | Pre-compiled hex blob | Source + build system |
| TMR approach | Same (PCI indirect registers) | Same |
| VMCB patching | Same (via MP4 SysHub TLB) | Same |

## Key FW 4.03 Offsets

See `include/offsets_403.h` for the complete list. Critical values:

- `KOFF_COPYIN`: `0x2DFEB0`
- `KOFF_COPYOUT`: `0x2DFE00`
- `KOFF_KERNEL_PMAP`: `0x3D94218`
- `KOFF_CFI_CHECK_FAIL`: `0x441DD0`
- `VCPU_CTXS_PA`: `0x628485D0`

## File Structure

```
prosperous_port/
├── Makefile                    # Top-level build (PS5 Payload SDK)
├── README.md
├── include/
│   ├── pci.h                   # PCI config space access
│   ├── smn.h                   # AMD SMN register access
│   ├── tmr.h                   # Trusted Memory Region definitions
│   ├── mp4.h                   # MP4 coprocessor definitions
│   ├── mp4_thunk.h             # Pre-compiled AArch64 thunk binary
│   ├── offsets_403.h           # FW 4.03 kernel symbol offsets
│   └── prosperous.h            # Main header / exploit context
├── src/
│   ├── main.c                  # Exploit orchestrator + entry point
│   ├── tmr.c                   # TMR manipulation
│   ├── mp4_inject.c            # MP4 payload injection + command interface
│   └── vmcb_patch.c            # VMCB patching via MP4
├── mp4_payload/
│   ├── mp4_payload.c           # AArch64 EL3 payload source
│   └── Makefile                # Cross-compile for cortex-a53
├── kpayload/
│   ├── kpayload.cpp            # Kernel RPC payload (x86-64)
│   ├── kpayload.ld             # Linker script (16KB limit)
│   └── Makefile                # Build with host g++
└── client/
    └── client.py               # Python RPC client library
```

## Notes

- TMR manipulation **stops working at FW >= 5.00** (TMR becomes non-modifiable by x86)
- TMR 20 **must be restored** after MP4 injection or kernel will panic on game restart
- VMCB vec4 must keep bits 0-3 set (VMSAVE/VMLOAD/VMMCALL/VMRUN) or context switches hang
- The kpayload must fit within 16KB (single physically-contiguous page)
- Kernel offsets are firmware-specific - verify against your target build

## Credits

- **fail0verflow** (shuffle2) - Original prosperous exploit
- **cragson** - a53-code-exec (FW 2.00 base)
- **astrelsky** - mp4rw research
- This port builds on the existing ps5_kernel_research infrastructure
