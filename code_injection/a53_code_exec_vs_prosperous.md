# Comparison: cragson/a53-code-exec vs fail0verflow/prosperous

Both projects achieve code execution on the PS5's ARM Cortex-A53 coprocessor (MP4/Aeolia) at EL3, but differ significantly in scope and approach.

## Overview

| | a53-code-exec | prosperous |
|---|---|---|
| **Author** | cragson | fail0verflow |
| **Language** | C++ (PS5 Payload SDK) | Lua + C + ARM64 ASM |
| **Firmware** | 02.00 | Early FW (pre-5.00) |
| **Goal** | PoC: patch FW version string | Full chain: A53 -> HV bypass -> kernel payload |
| **Scope** | A53 read/write demo | A53 code exec + TMR bypass + VMCB patching + kernel exec |

## A53 Communication Method

### a53-code-exec
- Uses **DECI5S/SDBGP debug protocol** with raw packets (magic `0x73354450`)
- Communicates via `/dev/mp4/dump` ioctls (`IOCTL_START`, `IOCTL_ALTER_STATE`, `IOCTL_FINISH`)
- Walks EL3 page tables (L2/L3 descriptors) to resolve physical addresses
- Requires credential swapping (`SYSCORE_ID = 0x4800000000000007`) to access MP4

### prosperous
- Uses **direct BAR2 MMIO register access** to C2P/P2C mailbox registers
- Patches the `mDbg_intr` handler at `0x109854` to redirect to a custom payload
- Custom payload (`mp4_payload.c`) implements a full command dispatch loop
- Communication via simple register polling (write cmd to C2P reg 0, poll until clear)

## What Each Project Does

### a53-code-exec (Proof of Concept)
1. Finds MP4 device by walking kernel `bus_data_devices` list
2. Extracts `softc` pointer and BAR2 MMIO resource
3. Reads/writes A53 memory through DECI5S debug channel
4. Patches one ARM instruction + data string so FW version query returns `"pwned by cragson - 33"`
5. Restores everything afterward

### prosperous (Full Exploitation Chain)
1. **IOMMU bypass** (`iommu.lua`): Sets exclusion range over all physical memory via SMN registers
2. **TMR manipulation**: Disables/reconfigures hardware memory protections (TMR 5, 16-18, 20-21) to unlock HV and A53 memory regions
3. **A53 code injection**: Writes ARM64 payload into A53 memory, hooks `mDbg_intr` for command dispatch (r/w 8/16/32/64, memcpy, TLB setup, cache ops, etc.)
4. **Hypervisor bypass**: Uses A53 r/w to modify AMD SVM VMCBs for all 16 vCPUs — disables nested paging (`NP_ENABLE=0`, `GMET=0`) and clears intercept vectors
5. **Kernel code execution**: Patches `cfi_check_fail` to NOP (CFI bypass), hijacks syscall 8 to point to kernel payload loaded over TCP, maps with 1GB page

## MP4 Payload Commands (prosperous)

| Command | Function |
|---|---|
| `0x20400000` | Memory read (8/16/32/64-bit, virtual or physical) |
| `0x20400001-4` | Memory write (8/16/32/64-bit) |
| `0x20400005` | SysHub TLB setup |
| `0x20400006` | memcpy |
| `0x20400007` | Data cache clean/invalidate |
| `0x20400008` | TLB invalidate (all EL3) |
| `0x20400009` | Ping (returns timer count) |
| `0x2040000a` | Enable/disable caches |
| `0x2040000b` | System register read |

## Key Technical Differences

| Aspect | a53-code-exec | prosperous |
|---|---|---|
| A53 access | DECI5S debug protocol | Direct BAR2 MMIO |
| A53 payload | None (uses debug protocol) | Custom C payload with cmd dispatch |
| TMR handling | Not touched | Extensively manipulated |
| IOMMU | Not touched | Full bypass via exclusion range |
| Hypervisor | Not touched | VMCBs patched to disable nested paging |
| Kernel patching | Not touched | CFI bypass + syscall hijack |
| Build system | PS5 Payload SDK | Manual gcc + objcopy |

## Summary

**a53-code-exec** is a clean, well-documented PoC showing A53 memory access via the DECI5S debug protocol — essentially "hello world" for A53 exploitation.

**prosperous** is a comprehensive exploitation framework using the A53 as a stepping stone to disable IOMMU, TMR, hypervisor nested paging, and kernel CFI — achieving full kernel code execution. Notably stops working at FW 5.00 when TMR became no longer directly modifiable by x86.

## References
- https://github.com/cragson/a53-code-exec
- https://github.com/fail0verflow/prosperous
