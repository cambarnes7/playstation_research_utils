#!/bin/bash
set -e
OUTDIR="bins"
mkdir -p "$OUTDIR"

CFLAGS="-Os -std=c11 -ffunction-sections -fdata-sections -fno-builtin -nostartfiles -nostdlib -Wall -march=btver2 -mtune=btver2 -m64 -mabi=sysv -mcmodel=small -fpie -fno-stack-protector"
LFLAGS="-Xlinker -T ./linker.x -Wl,--build-id=none -Wl,--gc-sections -nostdlib"

build_batch() {
    local name="$1" start_off="$2" count="$3"
    mkdir -p build
    gcc -c -o build/main.o src/batch_pivot_scan.c $CFLAGS \
        -DSCAN_START_OFF="($start_off)" -DSCAN_COUNT="$count" 2>/dev/null
    gcc build/main.o -o build/batch.elf $CFLAGS $LFLAGS 2>/dev/null
    objcopy -S -O binary build/batch.elf "$OUTDIR/${name}.bin"
    echo "  Built $name.bin (start=$start_off count=$count)"
}

# Scan function gaps in the syscall/ops region (SAFE — no wrmsr)
# These are the largest gaps between known function entries
# Gap addresses are ktext-relative, convert to kdata offset:
#   kdata_off = -(0xC00000 - ktext_off)

echo "=== Building batch pivot scanners ==="
echo "Each binary scans 256 bytes (configurable)"
echo ""

# Gap: ktext+0x2952e0 to 0x297448 = 8552 bytes (34 batches of 256)
echo "--- Gap 8552 bytes: ktext+0x2952e0..0x297448 ---"
for i in $(seq 0 33); do
    off=$((0x2952e0 + i * 256))
    remaining=$((0x297448 - off))
    count=256
    if [ $remaining -lt 256 ]; then count=$remaining; fi
    if [ $count -le 0 ]; then break; fi
    hex_off=$(printf '%x' $((0xC00000 - off)))
    build_batch "batch_8552_${i}" "-0x${hex_off}" "$count"
done

# Gap: ktext+0x298430 to 0x2997e8 = 5048 bytes (20 batches)
echo ""
echo "--- Gap 5048 bytes: ktext+0x298430..0x2997e8 ---"
for i in $(seq 0 19); do
    off=$((0x298430 + i * 256))
    remaining=$((0x2997e8 - off))
    count=256
    if [ $remaining -lt 256 ]; then count=$remaining; fi
    if [ $count -le 0 ]; then break; fi
    hex_off=$(printf '%x' $((0xC00000 - off)))
    build_batch "batch_5048_${i}" "-0x${hex_off}" "$count"
done

# Gap: ktext+0x290e30 to 0x290e88+gap = 2872 bytes (12 batches)
# Actually this is ktext+0x2902f8 to 0x290e30 = 2872 bytes
echo ""
echo "--- Gap 2872 bytes: ktext+0x2902f8..0x290e30 ---"
for i in $(seq 0 11); do
    off=$((0x2902f8 + i * 256))
    remaining=$((0x290e30 - off))
    count=256
    if [ $remaining -lt 256 ]; then count=$remaining; fi
    if [ $count -le 0 ]; then break; fi
    hex_off=$(printf '%x' $((0xC00000 - off)))
    build_batch "batch_2872_${i}" "-0x${hex_off}" "$count"
done

# Gap: ktext+0x290048 to 0x290140 = 2256 bytes  
# Actually 0x28f778 to 0x290048 = 2256
echo ""
echo "--- Gap 2256 bytes: ktext+0x28f778..0x290048 ---"
for i in $(seq 0 8); do
    off=$((0x28f778 + i * 256))
    remaining=$((0x290048 - off))
    count=256
    if [ $remaining -lt 256 ]; then count=$remaining; fi
    if [ $count -le 0 ]; then break; fi
    hex_off=$(printf '%x' $((0xC00000 - off)))
    build_batch "batch_2256_${i}" "-0x${hex_off}" "$count"
done

# Gap: ktext+0x297760 to 0x297f48 = 2024 bytes (8 batches)
echo ""
echo "--- Gap 2024 bytes: ktext+0x297760..0x297f48 ---"
for i in $(seq 0 7); do
    off=$((0x297760 + i * 256))
    remaining=$((0x297f48 - off))
    count=256
    if [ $remaining -lt 256 ]; then count=$remaining; fi
    if [ $count -le 0 ]; then break; fi
    hex_off=$(printf '%x' $((0xC00000 - off)))
    build_batch "batch_2024_${i}" "-0x${hex_off}" "$count"
done

echo ""
echo "=== Done! ==="
ls "$OUTDIR"/batch_*.bin | wc -l
echo "batch scanner binaries built"
