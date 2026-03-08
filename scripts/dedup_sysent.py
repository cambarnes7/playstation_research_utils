#!/usr/bin/env python3
"""Parse v10c sysent fn ptr batch dumps and deduplicate."""

import sys
from collections import Counter

KTEXT_BASE = 0xffffffff82a60000
KDATA_BASE = 0xffffffff83660000

# Raw hex dumps from 3 batches (offset 0x20 = out[4] onwards, each 8 bytes)
# Batch 0: sysent[0..283]
batch0_hex = """
0xffffffff82cf84d8
0xffffffff82cf7f98
0xffffffff82cf8d18
0xffffffff82cf75d0
0xffffffff82cf83f0
0xffffffff82cf78a8
0xffffffff82cf8080
0xffffffff82cf7850
0xffffffff82cf84d8
0xffffffff82cf77b8
0xffffffff82cf8220
0xffffffff82cf84d8
0xffffffff82cf7c20
0xffffffff82cf8400
0xffffffff82cf8180
0xffffffff82cf7ac8
0xffffffff82cf7c68
0xffffffff82cf84d8
0xffffffff82cf84d8
0xffffffff82cf84d8
0xffffffff82cf8178
0xffffffff82cf89f8
0xffffffff82cf7d78
0xffffffff82cf8478
0xffffffff82cf8158
0xffffffff82cf8d20
0xffffffff82cf8668
0xffffffff82cf7ea0
0xffffffff82cf8928
0xffffffff82cf7950
0xffffffff82cf89e0
0xffffffff82cf78c0
0xffffffff82cf8498
0xffffffff82cf8448
0xffffffff82cf7ce0
0xffffffff82cf7c00
0xffffffff82cf7260
0xffffffff82cf7bd0
0xffffffff82cf84d8
0xffffffff82cf8c70
0xffffffff82cf84d8
0xffffffff82cf8128
0xffffffff82cf7fa0
0xffffffff82cf87f0
0xffffffff82cf7620
0xffffffff82cf73f8
0xffffffff82cf84d8
0xffffffff82cf82e8
0xffffffff82cf84d8
0xffffffff82cf7bb8
0xffffffff82cf7250
0xffffffff82cf84d8
0xffffffff82cf84d8
0xffffffff82cf8010
0xffffffff82cf71f0
0xffffffff82cf7c70
0xffffffff82cf8ae0
0xffffffff82cf8068
0xffffffff82cf8410
0xffffffff82cf74a8
"""

# Batch 1: sysent[284..567]
batch1_hex = """
0xffffffff82cf84d8
0xffffffff82cf84d8
0xffffffff82cf84d8
0xffffffff82cf84d8
0xffffffff82cf84d8
0xffffffff82cf7248
0xffffffff82cf7330
0xffffffff82cf84d8
0xffffffff82cf84d8
0xffffffff82cf84d8
0xffffffff82cf84d8
0xffffffff82cf84d8
0xffffffff82cf84d8
0xffffffff82cf84d8
0xffffffff82cf84d8
0xffffffff82cf84d8
0xffffffff82cf84d8
0xffffffff82cf84d8
0xffffffff82cf84d8
0xffffffff82cf84d8
0xffffffff82cf8a10
0xffffffff82cf7498
0xffffffff82cf73b8
0xffffffff82cf7bf8
0xffffffff82cf7380
0xffffffff82cf88b0
0xffffffff82cf8be0
0xffffffff82cf7ac0
0xffffffff82cf8b80
0xffffffff82cf84d8
0xffffffff82cf8358
0xffffffff82cf8310
0xffffffff82cf73b0
0xffffffff82cf7cb8
0xffffffff82cf84d8
0xffffffff82cf84d8
0xffffffff82cf84d8
0xffffffff82cf7be8
0xffffffff82cf84d8
0xffffffff82cf84d8
0xffffffff82cf8168
0xffffffff82cf8140
0xffffffff82cf75c8
0xffffffff82cf7dd8
0xffffffff82cf8530
0xffffffff82cf87c0
0xffffffff82cf8ba0
0xffffffff82cf7900
0xffffffff82cf7c10
0xffffffff82cf7958
0xffffffff82cf7508
0xffffffff82cf79f8
0xffffffff82cf84d8
0xffffffff82cf7f08
0xffffffff82cf84d8
0xffffffff82cf85a8
0xffffffff82cf8818
0xffffffff82cf7e68
0xffffffff82cf84d8
0xffffffff82cf87e0
"""

# Batch 2: sysent[568..677]
batch2_hex = """
0xffffffff82cf7df8
0xffffffff82cf71a8
0xffffffff82cf8280
0xffffffff82cf8348
0xffffffff82cf72e0
0xffffffff82cf7b38
0xffffffff82cf84d8
0xffffffff82cf84d8
0xffffffff82cf84d8
0xffffffff82cf84d8
0xffffffff82cf84d8
0xffffffff82cf84d8
0xffffffff82cf84d8
0xffffffff82cf84d8
0xffffffff82cf84d8
0xffffffff82cf84d8
0xffffffff82cf84d8
0xffffffff82cf8000
0xffffffff82cf84c8
0xffffffff82cf7c58
0xffffffff82cf75f0
0xffffffff82cf8670
0xffffffff82cf7a10
0xffffffff82cf8810
0xffffffff82cf7990
0xffffffff82cf7f40
0xffffffff82cf8150
0xffffffff82cf87f8
0xffffffff82cf81b8
0xffffffff82cf8b28
0xffffffff82cf7790
0xffffffff82cf8b68
0xffffffff82cf8c60
0xffffffff82cf7ca0
0xffffffff82cf8780
0xffffffff82cf89a8
0xffffffff82cf8020
0xffffffff82cf7458
0xffffffff82cf8b78
0xffffffff82cf7300
0xffffffff82cf78e0
0xffffffff82cf8c50
0xffffffff82cf8360
0xffffffff82cf8ab0
0xffffffff82cf75e0
0xffffffff82cf7d28
0xffffffff82cf8868
0xffffffff82cf83b8
0xffffffff82cf7de0
0xffffffff82cf85e0
0xffffffff82cf7408
0xffffffff82cf8948
0xffffffff82cf7440
0xffffffff82cf71e0
0xffffffff82cf7d40
0xffffffff82cf8d28
0xffffffff82cf7f90
0xffffffff82cf8880
0xffffffff82cf8a40
0xffffffff82cf77c0
"""

def parse_batch(hex_str):
    """Parse hex lines into list of integers."""
    ptrs = []
    for line in hex_str.strip().split('\n'):
        line = line.strip()
        if line and line.startswith('0x'):
            ptrs.append(int(line, 16))
    return ptrs

def main():
    b0 = parse_batch(batch0_hex)
    b1 = parse_batch(batch1_hex)
    b2 = parse_batch(batch2_hex)

    all_ptrs = b0 + b1 + b2
    print(f"Total entries: {len(all_ptrs)}")
    print(f"  Batch 0: {len(b0)} entries (sysent[0..{len(b0)-1}])")
    print(f"  Batch 1: {len(b1)} entries (sysent[284..{284+len(b1)-1}])")
    print(f"  Batch 2: {len(b2)} entries (sysent[568..{568+len(b2)-1}])")

    # Count occurrences
    counts = Counter(all_ptrs)
    nosys_addr = counts.most_common(1)[0][0]
    nosys_count = counts.most_common(1)[0][1]
    nosys_offset = nosys_addr - KTEXT_BASE

    print(f"\n--- nosys identification ---")
    print(f"Most common fn ptr: {nosys_addr:#x} (ktext+{nosys_offset:#x})")
    print(f"Occurrences: {nosys_count} / {len(all_ptrs)}")

    # Find all unique non-nosys ptrs
    unique_ptrs = set()
    for p in all_ptrs:
        if p != nosys_addr:
            unique_ptrs.add(p)

    print(f"\n--- Unique fn ptrs (excluding nosys) ---")
    print(f"Unique real handlers: {len(unique_ptrs)}")

    # Map each unique ptr to its sysent indices
    ptr_to_indices = {}
    for i, p in enumerate(all_ptrs):
        if p == nosys_addr:
            continue
        if p not in ptr_to_indices:
            ptr_to_indices[p] = []
        ptr_to_indices[p].append(i)

    # Sort by ktext offset
    sorted_ptrs = sorted(unique_ptrs, key=lambda p: p - KTEXT_BASE)

    print(f"\n{'idx':>5s}  {'ktext offset':>14s}  {'fn ptr':>20s}  {'sysent indices'}")
    print("-" * 80)
    for i, p in enumerate(sorted_ptrs):
        offset = p - KTEXT_BASE
        indices = ptr_to_indices[p]
        idx_str = ','.join(str(x) for x in indices)
        print(f"{i:5d}  ktext+{offset:#010x}  {p:#018x}  [{idx_str}]")

    # Offset range analysis
    offsets = [p - KTEXT_BASE for p in sorted_ptrs]
    print(f"\n--- Offset range analysis ---")
    print(f"Min offset: ktext+{min(offsets):#x}")
    print(f"Max offset: ktext+{max(offsets):#x}")
    print(f"Span: {max(offsets) - min(offsets):#x} ({(max(offsets) - min(offsets)):,d} bytes)")

    # Check for outliers (far from main cluster)
    median_off = sorted(offsets)[len(offsets)//2]
    print(f"Median offset: ktext+{median_off:#x}")

    outliers = [(p, p - KTEXT_BASE) for p in sorted_ptrs
                if abs((p - KTEXT_BASE) - median_off) > 0x10000]
    if outliers:
        print(f"\nOutliers (>64KB from median):")
        for p, off in outliers:
            indices = ptr_to_indices[p]
            print(f"  ktext+{off:#x} = sysent[{','.join(str(x) for x in indices)}]")
    else:
        print(f"\nNo outliers — all fn ptrs within 64KB of median")

    # Check for entries that share fn ptrs (non-nosys duplicates)
    shared = {p: idxs for p, idxs in ptr_to_indices.items() if len(idxs) > 1}
    if shared:
        print(f"\n--- Shared fn ptrs (non-nosys, same handler for multiple syscalls) ---")
        for p, idxs in sorted(shared.items(), key=lambda x: x[0]):
            offset = p - KTEXT_BASE
            print(f"  ktext+{offset:#010x}: sysent[{','.join(str(x) for x in idxs)}]")

    # nosys entries
    nosys_indices = [i for i, p in enumerate(all_ptrs) if p == nosys_addr]
    print(f"\n--- nosys entries ({nosys_count} total) ---")
    print(f"Indices: {nosys_indices}")

    # Summary for apic_ops comparison
    # apic_ops offsets from progress.md
    apic_offsets = [
        0x28DB88, 0x28D310, 0x294340, 0x290808, 0x293F18, 0x294100,
        0x2943B8, 0x290330, 0x28E9D0, 0x28DC60, 0x290240, 0x290AA8,
        0x28D770, 0x28E708, 0x28E700, 0x28DC58, 0x2902B8, 0x2941D0,
        0x294348, 0x294320, 0x28D130, 0x28DB80, 0x2906D0, 0x29E830,
        0x290800, 0x5569F0, 0x28DFA8, 0x28E760
    ]
    apic_range = (min(apic_offsets), max(apic_offsets))

    print(f"\n--- Comparison with apic_ops ---")
    print(f"apic_ops offset range: ktext+{apic_range[0]:#x} to ktext+{apic_range[1]:#x}")
    print(f"sysent offset range:   ktext+{min(offsets):#x} to ktext+{max(offsets):#x}")

    # Check overlap
    sysent_in_apic = [off for off in offsets
                      if apic_range[0] <= off <= apic_range[1]]
    print(f"Sysent entries in apic_ops range: {len(sysent_in_apic)}")

    # Entries NOT in the main cluster (potential different compilation units)
    main_cluster = [off for off in offsets if 0x290000 <= off <= 0x2A0000]
    outside_cluster = [(p, p - KTEXT_BASE) for p in sorted_ptrs
                       if not (0x290000 <= (p - KTEXT_BASE) <= 0x2A0000)]
    print(f"\nEntries in main cluster (0x29xxxx): {len(main_cluster)}")
    print(f"Entries outside main cluster: {len(outside_cluster)}")
    if outside_cluster:
        print("Outside cluster (priority targets for execution probing):")
        for p, off in outside_cluster:
            indices = ptr_to_indices[p]
            print(f"  ktext+{off:#010x}: sysent[{','.join(str(x) for x in indices)}]")

if __name__ == '__main__':
    main()
