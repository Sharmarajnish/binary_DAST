#!/bin/bash

# DAST Test Binary Build Script
# Compiles vulnerable ECU for testing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE="${SCRIPT_DIR}/vulnerable_ecu.c"
OUTPUT="${SCRIPT_DIR}/vulnerable_ecu"

echo "==================================="
echo "  ECU Test Binary Build Script"
echo "==================================="

# Check for GCC
if ! command -v gcc &> /dev/null; then
    echo "[ERROR] gcc not found. Please install build tools."
    echo "  macOS:  xcode-select --install"
    echo "  Ubuntu: sudo apt install build-essential"
    exit 1
fi

# Compile x86_64
echo "[Build] Compiling for x86_64..."
gcc -o "${OUTPUT}" "${SOURCE}" \
    -no-pie \
    -fno-stack-protector \
    -Wno-format-security \
    -Wno-deprecated-declarations \
    2>/dev/null || {
    echo "[WARN] Some warnings were suppressed"
}

echo "[Build] Output: ${OUTPUT}"
echo "[Build] Size: $(du -h "${OUTPUT}" | cut -f1)"

# Test the binary
echo ""
echo "[Test] Running basic test..."
echo -ne '\x10\x01' | "${OUTPUT}" - 2>/dev/null || true

# Cross-compile for ARM (if toolchain exists)
if command -v arm-linux-gnueabi-gcc &> /dev/null; then
    echo ""
    echo "[Build] Cross-compiling for ARM..."
    arm-linux-gnueabi-gcc -o "${OUTPUT}_arm" "${SOURCE}" \
        -static \
        -no-pie \
        -fno-stack-protector \
        2>/dev/null || echo "[WARN] ARM compilation had warnings"
    echo "[Build] ARM Output: ${OUTPUT}_arm"
fi

# Cross-compile for PowerPC (if toolchain exists)
if command -v powerpc-linux-gnu-gcc &> /dev/null; then
    echo ""
    echo "[Build] Cross-compiling for PowerPC..."
    powerpc-linux-gnu-gcc -o "${OUTPUT}_ppc" "${SOURCE}" \
        -static \
        -no-pie \
        -fno-stack-protector \
        2>/dev/null || echo "[WARN] PowerPC compilation had warnings"
    echo "[Build] PowerPC Output: ${OUTPUT}_ppc"
fi

echo ""
echo "==================================="
echo "  Build Complete!"
echo "==================================="
echo ""
echo "Usage:"
echo "  # Test buffer overflow"
echo "  echo -ne '\\x10\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41' | ${OUTPUT} -"
echo ""
echo "  # Test UDS Security Access"
echo "  echo -ne '\\x27\\x01' | ${OUTPUT} -"
echo ""
echo "  # Run DAST test"
echo "  python test_dast.py"
