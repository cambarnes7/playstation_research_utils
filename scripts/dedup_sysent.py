#!/usr/bin/env python3
"""Parse v10c sysent fn ptr batch dumps (full 678 entries) and deduplicate."""

from collections import Counter

KTEXT_BASE = 0xffffffff82a60000  # normalized (subtract 0x4E070000 from live)

# Full data from 3 batches, parsed from kldload output.
# Format: (sysent_index, ktext_offset) — nosys entries omitted from raw lists.
# nosys = ktext+0x2984d8

NOSYS_OFFSET = 0x2984d8

# Batch 0: 284 entries, 110 nosys, 174 unique
batch0 = [
    (1, 0x297f98), (2, 0x298d18), (3, 0x2975d0), (4, 0x2983f0), (5, 0x2978a8),
    (6, 0x298080), (7, 0x297850), (9, 0x2977b8), (10, 0x298220), (12, 0x297c20),
    (13, 0x298400), (14, 0x298180), (15, 0x297ac8), (16, 0x297c68), (20, 0x298178),
    (21, 0x2989f8), (22, 0x297d78), (23, 0x298478), (24, 0x298158), (25, 0x298d20),
    (26, 0x298668), (27, 0x297ea0), (28, 0x298928), (29, 0x297950), (30, 0x2989e0),
    (31, 0x2978c0), (32, 0x298498), (33, 0x298448), (34, 0x297ce0), (35, 0x297c00),
    (36, 0x297260), (37, 0x297bd0), (39, 0x298c70), (41, 0x298128), (42, 0x297fa0),
    (43, 0x2987f0), (44, 0x297620), (45, 0x2973f8), (47, 0x2982e8), (49, 0x297bb8),
    (50, 0x297250), (53, 0x298010), (54, 0x2971f0), (55, 0x297c70), (56, 0x298ae0),
    (57, 0x298068), (58, 0x298410), (59, 0x2974a8), (60, 0x297a30), (61, 0x297c48),
    (65, 0x297e18), (66, 0x2976d8), (69, 0x297b80), (70, 0x2981d8), (73, 0x297d20),
    (74, 0x298c40), (75, 0x2987e8), (78, 0x298650), (79, 0x297838), (80, 0x2979a8),
    (81, 0x2988a0), (82, 0x298ca8), (83, 0x297460), (85, 0x297a80), (86, 0x298090),
    (89, 0x298ab8), (90, 0x297848), (92, 0x298060), (93, 0x298c58), (95, 0x297350),
    (96, 0x2973c8), (97, 0x297648), (98, 0x2988d8), (99, 0x297a48), (100, 0x2986b8),
    (101, 0x298240), (102, 0x297518), (104, 0x297868), (105, 0x297ee8), (106, 0x297880),
    (113, 0x2985e8), (114, 0x2973d0), (116, 0x298040), (117, 0x297938), (118, 0x298378),
    (120, 0x297410), (121, 0x2987b0), (122, 0x298078), (123, 0x2976f0), (124, 0x297e10),
    (125, 0x2983a0), (126, 0x298570), (127, 0x297930), (128, 0x297cd8), (131, 0x297960),
    (132, 0x297828), (133, 0x2985a0), (134, 0x297df0), (135, 0x298890), (136, 0x298340),
    (137, 0x297ec0), (138, 0x297290), (140, 0x2975a8), (141, 0x298978),
    (147, 0x2980a0),
    (154, 0x2985a8), (155, 0x2985a8),
    (165, 0x298380), (166, 0x2979b0),
    (169, 0x2985a8), (170, 0x2985a8), (171, 0x2985a8),
    (181, 0x298338), (182, 0x298bd8), (183, 0x297968),
    (188, 0x297be0), (189, 0x298608), (190, 0x2983e0),
    (191, 0x297258), (192, 0x297278),
    (194, 0x298a88), (195, 0x297478), (196, 0x298c88),
    (202, 0x297c60), (203, 0x297298), (204, 0x297ef8),
    (206, 0x297f78), (207, 0x297d98),
    (209, 0x2975f8),
    (210, 0x298918), (211, 0x298918), (212, 0x298918), (213, 0x298918),
    (214, 0x298918), (215, 0x298918), (216, 0x298918), (217, 0x298918),
    (218, 0x298918), (219, 0x298918),
    (220, 0x2985a8), (221, 0x2985a8), (222, 0x2985a8),
    (224, 0x2985a8), (225, 0x2985a8), (226, 0x2985a8), (227, 0x2985a8),
    (228, 0x2985a8), (229, 0x2985a8), (230, 0x2985a8), (231, 0x2985a8),
    (232, 0x297628), (233, 0x2986c8), (234, 0x298598), (235, 0x2989e8),
    (236, 0x297bd8), (237, 0x298920), (238, 0x297830), (239, 0x297ca8),
    (240, 0x298c18), (241, 0x2971d8), (242, 0x298b00), (243, 0x298b60),
    (247, 0x298658), (250, 0x297730), (251, 0x297b10),
    (253, 0x298ac0), (254, 0x297598), (255, 0x2981f0), (256, 0x298218),
    (272, 0x298ce8), (274, 0x297af0), (275, 0x297598), (276, 0x297d80),
    (277, 0x297e18),
]

# Batch 1: 284 entries, 111 nosys, 173 unique
batch1 = [
    (289, 0x297248), (290, 0x297330),
    (304, 0x298a10), (305, 0x297498), (306, 0x2973b8), (307, 0x297bf8),
    (308, 0x297380), (309, 0x2988b0), (310, 0x298be0), (311, 0x297ac0),
    (312, 0x298b80), (314, 0x298358), (315, 0x298310), (316, 0x2973b0),
    (317, 0x297cb8), (321, 0x297be8), (324, 0x298168), (325, 0x298140),
    (326, 0x2975c8), (327, 0x297dd8), (328, 0x298530), (329, 0x2987c0),
    (330, 0x298ba0), (331, 0x297900), (332, 0x297c10), (333, 0x297958),
    (334, 0x297508), (335, 0x2979f8), (337, 0x297f08), (339, 0x2985a8),
    (340, 0x298818), (341, 0x297e68), (343, 0x2987e0),
    (345, 0x298680), (346, 0x2982c0),
    (359, 0x298998), (360, 0x298950), (361, 0x297368), (362, 0x297e90),
    (363, 0x297360),
    (374, 0x298bb8), (377, 0x2985a8), (378, 0x297910), (379, 0x297b20),
    (384, 0x298850), (385, 0x297578), (386, 0x297cd0), (387, 0x2972f8),
    (388, 0x2977f8), (389, 0x298260), (390, 0x2977e8), (391, 0x298a28),
    (392, 0x297d70), (393, 0x297e98), (394, 0x2982c8), (395, 0x297a00),
    (396, 0x297708), (397, 0x2984f0), (400, 0x298760), (401, 0x297ae0),
    (402, 0x2985d8), (403, 0x2972c8), (404, 0x297d58), (405, 0x297d88),
    (406, 0x2977d0), (407, 0x298508), (408, 0x2983a8), (409, 0x297f50),
    (410, 0x297590), (411, 0x297920), (415, 0x297a08), (416, 0x297198),
    (417, 0x297ef0), (421, 0x297b78), (422, 0x297e40), (423, 0x297a20),
    (429, 0x298520), (430, 0x2985f8), (431, 0x298980), (432, 0x2971a0),
    (433, 0x298738),
    (441, 0x298768), (442, 0x297e78), (443, 0x297e00), (444, 0x298588),
    (454, 0x297d30), (455, 0x2986a0), (456, 0x297cf0),
    (457, 0x2985a8), (458, 0x2985a8), (459, 0x2985a8), (460, 0x2985a8),
    (461, 0x2985a8), (462, 0x2985a8),
    (464, 0x297ba0), (465, 0x298888), (466, 0x2985b0),
    (475, 0x298c98), (476, 0x2973a0), (477, 0x297a40), (478, 0x297810),
    (479, 0x297a98), (480, 0x297e30), (481, 0x2976a0), (482, 0x298c10),
    (483, 0x297fa8), (484, 0x298630), (485, 0x298870), (486, 0x2982e0),
    (487, 0x297cc8), (488, 0x298a50), (490, 0x297338), (491, 0x298248),
    (493, 0x298460), (494, 0x2985b8), (495, 0x297818), (496, 0x298238),
    (497, 0x2978a0), (498, 0x298b98), (499, 0x2986f8),
    (501, 0x298700), (502, 0x2976e8), (503, 0x298440),
    (505, 0x2985a8), (510, 0x2985a8), (511, 0x2985a8), (512, 0x2985a8),
    (515, 0x2989d0), (516, 0x298748), (517, 0x297978),
    (519, 0x298a90), (520, 0x298988),
    (522, 0x297c08),
    (525, 0x298640), (526, 0x297680), (527, 0x298458), (528, 0x2974f0),
    (529, 0x297500),
    (532, 0x297b98), (533, 0x2973d8), (534, 0x297f88), (535, 0x298ce0),
    (536, 0x297a50), (538, 0x2985d0), (539, 0x2972a0), (540, 0x298558),
    (541, 0x298390), (542, 0x297db0), (543, 0x298578), (544, 0x297eb8),
    (545, 0x298250), (546, 0x2976f8), (547, 0x298368), (548, 0x297480),
    (549, 0x297e08), (550, 0x2985c8), (551, 0x297528), (552, 0x298688),
    (553, 0x298d50), (554, 0x298210), (555, 0x297690), (556, 0x2975b0),
    (557, 0x297208), (558, 0x297218), (559, 0x2973f0), (560, 0x298638),
    (561, 0x2975a0), (562, 0x297230), (563, 0x298038), (564, 0x297320),
    (565, 0x297eb0), (566, 0x297400), (567, 0x297588),
]

# Batch 2: 110 entries, 13 nosys, 97 unique
batch2 = [
    (568, 0x297df8), (569, 0x2971a8), (570, 0x298280), (571, 0x298348),
    (572, 0x2972e0), (573, 0x297b38),
    (585, 0x298000), (586, 0x2984c8), (587, 0x297c58), (588, 0x2975f0),
    (589, 0x298670), (590, 0x297a10), (591, 0x298810), (592, 0x297990),
    (593, 0x297f40), (594, 0x298150), (595, 0x2987f8), (596, 0x2981b8),
    (597, 0x298b28), (598, 0x297790), (599, 0x298b68), (600, 0x298c60),
    (601, 0x297ca0), (602, 0x298780), (603, 0x2989a8), (604, 0x298020),
    (605, 0x297458), (606, 0x298b78), (607, 0x297300), (608, 0x2978e0),
    (609, 0x298c50), (610, 0x298360), (611, 0x298ab0), (612, 0x2975e0),
    (613, 0x297d28), (614, 0x298868), (615, 0x2983b8), (616, 0x297de0),
    (617, 0x2985e0), (618, 0x297408), (619, 0x298948), (620, 0x297440),
    (621, 0x2971e0), (622, 0x297d40), (623, 0x298d28), (624, 0x297f90),
    (625, 0x298880), (626, 0x298a40), (627, 0x2977c0),
    (628, 0x298278), (629, 0x298bb0), (630, 0x298488), (631, 0x298a68),
    (632, 0x298110), (633, 0x297a60), (634, 0x297898), (635, 0x298d00),
    (636, 0x298ba8), (637, 0x2982a0), (638, 0x297988), (639, 0x298058),
    (640, 0x297940), (641, 0x298b88), (642, 0x297888), (643, 0x298be8),
    (646, 0x298708), (647, 0x297ad0), (648, 0x297bc0), (649, 0x298300),
    (650, 0x2973c0), (651, 0x298ad0), (652, 0x298930), (653, 0x298cf8),
    (654, 0x297f70), (655, 0x298198), (656, 0x298cb8), (657, 0x297ce8),
    (658, 0x297550), (659, 0x2973a8), (660, 0x2971d0), (661, 0x298100),
    (662, 0x297180), (663, 0x297a90), (664, 0x297188), (665, 0x298628),
    (666, 0x297688), (667, 0x297630), (668, 0x297220), (669, 0x298510),
    (670, 0x2979f0), (671, 0x297718), (672, 0x298698), (673, 0x2977c8),
    (674, 0x297570), (675, 0x2987d0), (676, 0x2986d8), (677, 0x2989c8),
]

# Known nosys indices (fill from total - unique counts)
# Batch 0: 284 total, 174 unique => 110 nosys
# Batch 1: 284 total, 173 unique => 111 nosys
# Batch 2: 110 total, 97 unique => 13 nosys

def main():
    all_entries = batch0 + batch1 + batch2
    total_unique_entries = len(all_entries)

    # Build offset -> [indices] map
    offset_to_indices = {}
    for idx, off in all_entries:
        if off not in offset_to_indices:
            offset_to_indices[off] = []
        offset_to_indices[off].append(idx)

    # All sysent indices that have real handlers
    real_indices = set(idx for idx, _ in all_entries)

    # All indices 0..677
    all_indices = set(range(678))
    nosys_indices = sorted(all_indices - real_indices)

    print(f"=== SYSENT FULL DUMP ANALYSIS (678 entries) ===")
    print(f"Total sysent entries: 678")
    print(f"nosys entries: {len(nosys_indices)}")
    print(f"Entries with handlers: {total_unique_entries}")

    # Unique fn ptrs (unique offsets)
    unique_offsets = set(off for _, off in all_entries)
    print(f"Unique fn ptrs (distinct handlers): {len(unique_offsets)}")

    # Offset range
    offsets_sorted = sorted(unique_offsets)
    print(f"\nOffset range: ktext+{offsets_sorted[0]:#x} to ktext+{offsets_sorted[-1]:#x}")
    span = offsets_sorted[-1] - offsets_sorted[0]
    print(f"Span: {span:#x} ({span:,d} bytes)")

    # Shared handlers (same fn ptr, multiple syscalls)
    print(f"\n=== SHARED HANDLERS (non-nosys, same fn for multiple syscalls) ===")
    shared = {off: idxs for off, idxs in offset_to_indices.items() if len(idxs) > 1}
    for off in sorted(shared.keys()):
        idxs = shared[off]
        print(f"  ktext+{off:#010x}: sysent[{', '.join(str(i) for i in sorted(idxs))}] ({len(idxs)} syscalls)")

    print(f"\nTotal shared fn ptrs: {len(shared)}")
    total_shared_entries = sum(len(v) for v in shared.values())
    print(f"Total entries using shared handlers: {total_shared_entries}")

    # The 0x2985a8 and 0x298918 groups look interesting
    big_groups = {off: idxs for off, idxs in shared.items() if len(idxs) >= 5}
    if big_groups:
        print(f"\n=== LARGE SHARED GROUPS (5+ syscalls) ===")
        for off in sorted(big_groups.keys()):
            idxs = sorted(big_groups[off])
            print(f"  ktext+{off:#x}: {len(idxs)} syscalls: [{', '.join(str(i) for i in idxs)}]")

    # Nosys gaps
    print(f"\n=== NOSYS INDEX RANGES ===")
    ranges = []
    start = None
    prev = None
    for i in nosys_indices:
        if start is None:
            start = i
            prev = i
        elif i == prev + 1:
            prev = i
        else:
            ranges.append((start, prev))
            start = i
            prev = i
    if start is not None:
        ranges.append((start, prev))

    for s, e in ranges:
        if s == e:
            print(f"  [{s}]")
        else:
            print(f"  [{s}..{e}] ({e - s + 1} entries)")

    # Spacing analysis
    print(f"\n=== FN PTR SPACING ANALYSIS ===")
    spacing = []
    for i in range(1, len(offsets_sorted)):
        spacing.append(offsets_sorted[i] - offsets_sorted[i-1])

    from collections import Counter as C
    spacing_counts = C(spacing)
    print(f"Most common spacings:")
    for sp, cnt in spacing_counts.most_common(10):
        print(f"  {sp:#x} ({sp} bytes): {cnt} occurrences")

    # 8-byte aligned check
    aligned = sum(1 for off in unique_offsets if off % 8 == 0)
    print(f"\n8-byte aligned: {aligned}/{len(unique_offsets)}")

    # Check if offsets look like sysent struct stride
    # FreeBSD sysent entry: sy_narg(4) + sy_call(8) + sy_auevent(2) + sy_systrace(8*2) + sy_thrcnt(4) = ~36 bytes?
    # Or simpler: just fn ptr, nargs, etc.

    # apic_ops comparison
    apic_offsets = [
        0x28DB88, 0x28D310, 0x294340, 0x290808, 0x293F18, 0x294100,
        0x2943B8, 0x290330, 0x28E9D0, 0x28DC60, 0x290240, 0x290AA8,
        0x28D770, 0x28E708, 0x28E700, 0x28DC58, 0x2902B8, 0x2941D0,
        0x294348, 0x294320, 0x28D130, 0x28DB80, 0x2906D0, 0x29E830,
        0x290800, 0x5569F0, 0x28DFA8, 0x28E760
    ]

    print(f"\n=== COMPARISON WITH APIC_OPS ===")
    print(f"apic_ops range: ktext+{min(apic_offsets):#x} to ktext+{max(apic_offsets):#x}")
    print(f"sysent range:   ktext+{offsets_sorted[0]:#x} to ktext+{offsets_sorted[-1]:#x}")

    # Overlap check
    sysent_set = unique_offsets
    apic_set = set(apic_offsets)
    overlap = sysent_set & apic_set
    if overlap:
        print(f"OVERLAP: {len(overlap)} shared offsets!")
        for off in sorted(overlap):
            print(f"  ktext+{off:#x}")
    else:
        print(f"No overlap between sysent and apic_ops fn ptrs")

    # Distance from sysent cluster to apic cluster
    print(f"\nSysent cluster center: ~ktext+{sum(offsets_sorted)//len(offsets_sorted):#x}")
    apic_median = sorted(apic_offsets)[len(apic_offsets)//2]
    print(f"apic_ops median:       ktext+{apic_median:#x}")
    print(f"Gap: {offsets_sorted[0] - max(apic_offsets):#x} bytes (sysent starts after apic ends)")

    # Summary stats
    print(f"\n=== SUMMARY ===")
    print(f"678 sysent entries total")
    print(f"  {len(nosys_indices)} nosys (unimplemented)")
    print(f"  {total_unique_entries} with handlers")
    print(f"  {len(unique_offsets)} distinct handler functions")
    print(f"  {len(shared)} handlers shared by multiple syscalls")
    print(f"  All handlers in {span:,d}-byte span at ktext+0x2971xx-0x298dxx")
    print(f"  nosys = ktext+{NOSYS_OFFSET:#x}")

if __name__ == '__main__':
    main()
