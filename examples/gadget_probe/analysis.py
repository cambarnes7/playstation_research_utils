#!/usr/bin/env python3
"""Analyze apic_ops + sysent dump to find pivot probe targets."""

KTEXT_BASE = 0x297000  # relative offsets (KASLR-independent)

# All known function entry points (ktext-relative offsets)
apic_ops = [
    0x2971b0, 0x2972c0, 0x2974c8, 0x297560, 0x297758, 0x297758,
    0x297808, 0x297908, 0x297998, 0x2979c0, 0x297d50, 0x297db8,
    0x297e58, 0x297f28, 0x297fd0, 0x298048, 0x2980b0, 0x298160,
    0x2981e0, 0x2981f8, 0x298270, 0x298910, 0x2989d8, 0x298a58,
    0x298ad8, 0x298c48, 0x298c78, 0x298cc8,
]

sysent = [
    0x2971d8, 0x2971f0, 0x297248, 0x297250, 0x297258, 0x297260,
    0x297278, 0x297290, 0x297298, 0x2972f8, 0x297330, 0x297350,
    0x297360, 0x297368, 0x297380, 0x2973b0, 0x2973b8, 0x2973c8,
    0x2973d0, 0x2973f8, 0x297410, 0x297460, 0x297478, 0x297498,
    0x2974a8, 0x297508, 0x297518, 0x297578, 0x297598, 0x2975a8,
    0x2975c8, 0x2975d0, 0x2975f8, 0x297620, 0x297628, 0x297648,
    0x2976d8, 0x2976f0, 0x297730, 0x2977b8, 0x2977e8, 0x2977f8,
    0x297828, 0x297830, 0x297838, 0x297848, 0x297850, 0x297868,
    0x297880, 0x2978a8, 0x2978c0, 0x297900, 0x297910, 0x297930,
    0x297938, 0x297950, 0x297958, 0x297960, 0x297968, 0x2979a8,
    0x2979b0, 0x2979f8, 0x297a30, 0x297a48, 0x297a80, 0x297ac0,
    0x297ac8, 0x297af0, 0x297b10, 0x297b20, 0x297b80, 0x297bb8,
    0x297bd0, 0x297bd8, 0x297be0, 0x297be8, 0x297bf8, 0x297c00,
    0x297c10, 0x297c20, 0x297c48, 0x297c60, 0x297c68, 0x297c70,
    0x297ca8, 0x297cb8, 0x297cd0, 0x297cd8, 0x297ce0, 0x297d20,
    0x297d70, 0x297d78, 0x297d80, 0x297d98, 0x297dd8, 0x297df0,
    0x297e10, 0x297e18, 0x297e68, 0x297e90, 0x297ea0, 0x297ec0,
    0x297ee8, 0x297ef8, 0x297f08, 0x297f78, 0x297f98, 0x297fa0,
    0x298010, 0x298040, 0x298060, 0x298068, 0x298078, 0x298080,
    0x298090, 0x2980a0, 0x298128, 0x298140, 0x298158, 0x298168,
    0x298178, 0x298180, 0x2981d8, 0x2981f0, 0x298218, 0x298220,
    0x298240, 0x298260, 0x2982c0, 0x2982e8, 0x298310, 0x298338,
    0x298340, 0x298358, 0x298378, 0x298380, 0x2983a0, 0x2983e0,
    0x2983f0, 0x298400, 0x298410, 0x298448, 0x298478, 0x298498,
    0x2984d8, 0x298530, 0x298570, 0x298598, 0x2985a0, 0x2985a8,
    0x2985e8, 0x298608, 0x298650, 0x298658, 0x298668, 0x298680,
    0x2986b8, 0x2986c8, 0x2987b0, 0x2987c0, 0x2987e0, 0x2987e8,
    0x2987f0, 0x298818, 0x298850, 0x298890, 0x2988a0, 0x2988b0,
    0x2988d8, 0x298918, 0x298920, 0x298928, 0x298950, 0x298978,
    0x298998, 0x2989e0, 0x2989e8, 0x2989f8, 0x298a10, 0x298a28,
    0x298a88, 0x298ab8, 0x298ac0, 0x298ae0, 0x298b00, 0x298b60,
    0x298b80, 0x298ba0, 0x298bb8, 0x298bd8, 0x298be0, 0x298c18,
    0x298c40, 0x298c58, 0x298c70, 0x298c88, 0x298ca8, 0x298ce8,
    0x298d18, 0x298d20,
]

# Merge all known entry points, deduplicate, sort
all_entries = sorted(set(apic_ops + sysent))

print(f"Total unique function entries: {len(all_entries)}")
print(f"Range: ktext+{all_entries[0]:#x} to ktext+{all_entries[-1]:#x}")
print(f"Span: {all_entries[-1] - all_entries[0]} bytes")
print()

# Compute gaps between consecutive entries
gaps = []
for i in range(len(all_entries) - 1):
    gap = all_entries[i+1] - all_entries[i]
    gaps.append((all_entries[i], all_entries[i+1], gap))

# Distribution
from collections import Counter
gap_sizes = Counter(g[2] for g in gaps)
print("Gap size distribution:")
for size, count in sorted(gap_sizes.items()):
    print(f"  {size:4d} bytes: {count:3d} functions")
print()

# Interesting: functions with gaps >= 3 bytes (could contain 48 94 C3)
# The byte at entry-1 should be C3 (ret) or CC (int3)
# If entry-3 starts xchg rsp,rax (48 94) and entry-1 is C3 → found it!
print("=" * 60)
print("PIVOT PROBE TARGETS")
print("Probe at entry-3 for each entry (testing for 48 94 C3)")
print("=" * 60)
print()

# For pivot probing, we want entry - 3 where:
# entry - 3 = 0x48, entry - 2 = 0x94, entry - 1 = 0xC3
# These are KASLR-independent offsets from ktext_base

targets = []
for i in range(1, len(all_entries)):
    entry = all_entries[i]
    prev = all_entries[i-1]
    gap = entry - prev

    if gap < 3:
        continue  # not enough room

    # The candidate address is entry - 3
    # As offset from kdata_base: -(kdata_offset_to_ktext + ktext_offset)
    # kdata_base - ktext_base = 0xC00000 (from the LSTAR calculation)
    # So ktext+X = kdata_base - 0xC00000 + X
    # = kdata_base + (X - 0xC00000)
    # = kdata_base + (-(0xC00000 - X))

    kdata_offset = -(0xC00000 - (entry - 3))
    targets.append((entry, gap, kdata_offset, entry - 3))

print(f"Candidates: {len(targets)} entries with gap >= 3")
print()

# Print all targets grouped by safety (larger gap = safer, means preceding
# function is bigger = more likely to have complex code but also more likely
# to have the bytes we need)
print("Top candidates (sorted by gap size, largest first):")
for entry, gap, koff, probe_off in sorted(targets, key=lambda x: -x[1])[:50]:
    sign = "-" if koff < 0 else "+"
    abs_koff = abs(koff)
    print(f"  entry=ktext+{entry:#08x}  gap={gap:4d}  "
          f"probe=ktext+{probe_off:#08x}  kdata_off={sign}0x{abs_koff:x}")

print()
print("=" * 60)
print("ALL targets as kdata_base offsets (for Makefile TARGET_OFFSET):")
print("=" * 60)
# Print first 30 sorted by address
for entry, gap, koff, probe_off in sorted(targets, key=lambda x: x[0])[:30]:
    sign = "-" if koff < 0 else "+"
    abs_koff = abs(koff)
    print(f"  TARGET_OFFSET={sign}0x{abs_koff:x}  # entry-3 before ktext+{entry:#x} (gap={gap})")
