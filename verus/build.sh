#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------------------------
# VerusHash static library build script – Solana BPF edition
# ------------------------------------------------------------------------------

# Where to put the .a and intermediate .o files
# Cargo sets OUT_DIR; use it directly. Default to target/bpf-build if not set.
OUT_DIR="${OUT_DIR:-$(pwd)/target/bpf-build}"
mkdir -p "$OUT_DIR"

# Root directory of the verus crate
CRATE_DIR="$(cd "$(dirname "$0")" && pwd)"
# Point directly to the 'c' directory containing our source files
CRYPTO_SRC="$CRATE_DIR/c"

# --- 0. Provide missing headers if needed ---
# Create a stub directory within OUT_DIR to avoid polluting the source tree
STUB_DIR="$OUT_DIR/stub"
mkdir -p "$STUB_DIR"

# • dummy librustzcash.h (Verus Hash never uses its contents)
#   Assume it's not present in verus/c/ and always create the stub.
echo '#pragma once' >"$STUB_DIR/librustzcash.h"
LIBRUSTZCASH_H_PATH="$STUB_DIR"

# • stub common.cpp if it's not present in verus/c/
#   (Needed for memory_cleanse if not defined elsewhere)
COMMON_CPP="$CRYPTO_SRC/common.cpp" # Check in the new location
if [[ ! -f "$COMMON_CPP" ]]; then
  COMMON_CPP="$STUB_DIR/common.cpp"
  # Generate a stub common.cpp compatible with SBF (-nostdlib++)
  # Include haraka_portable.h for our custom memset and size_t definition.
  cat >"$COMMON_CPP" <<'CPP'
#include "haraka_portable.h" // Use our header for memset/size_t

// Provide a basic implementation if the original is missing.
// Calls the verus_memset declared in haraka_portable.h (implemented in haraka_portable.c)
extern "C" void memory_cleanse(void* p, size_t n) {
    verus_memset(p, 0, n); // Use our custom memset
}
CPP
fi

# ------------------------------------------------------------------------------
# 1. Source files
# ------------------------------------------------------------------------------
# Use paths relative to the script's location (CRATE_DIR)
# CRYPTO_SRC now points to verus/c/
SRC_FILES=(
  "$CRYPTO_SRC/haraka_portable.c"
  "$CRYPTO_SRC/haraka_constants.c"
  "$CRYPTO_SRC/verus_hash.cpp"
  "$CRYPTO_SRC/uint256.cpp" # Add uint256.cpp
  # Add any other *.c/*.cpp sources from verus/c/
)

# Filter out non-existent files to prevent build errors
EXISTING_SRC_FILES=()
for src in "${SRC_FILES[@]}"; do
  if [[ -f "$src" ]]; then
    EXISTING_SRC_FILES+=("$src")
  else
    echo "Warning: Source file not found, skipping: $src"
  fi
done

# Check if common.cpp was stubbed and needs to be added
if [[ "$COMMON_CPP" == "$STUB_DIR/common.cpp" ]]; then
  EXISTING_SRC_FILES+=("$COMMON_CPP")
fi

# ------------------------------------------------------------------------------
# 2. Common include path(s)
# ------------------------------------------------------------------------------
# Use paths relative to the script's location (CRATE_DIR)
INC="-I $CRYPTO_SRC \

     -I $LIBRUSTZCASH_H_PATH \
     -I $STUB_DIR" # Include stub dir for generated headers/sources

# ------------------------------------------------------------------------------
# 3. Toolchain & flags for Solana BPF
#    (clang/clang++ are shipped with the Solana SDK tool-chain)
# ------------------------------------------------------------------------------
# Solana's cargo build-bpf sets TARGET, CC, CXX, CFLAGS, CXXFLAGS
# We just need to add our specific flags.

# Default to clang if CC is not set by Cargo/Solana SDK
CC="${CC:-clang}"

# Derive CXX from the directory of CC to ensure we use the Solana SDK's clang++
# If CC is just "clang", assume "clang++" is also in the PATH.
if [[ "$CC" == "clang" ]]; then
  CXX="clang++"
else
  # Get the directory containing CC and append clang++
  CC_DIR=$(dirname "$CC")
  CXX="$CC_DIR/clang++"
fi

# --- Debug: Print the compiler paths being used ---
echo "build.sh: Using CC=$CC"
echo "build.sh: Using CXX=$CXX" # This should now point to the SDK clang++
# --- End Debug ---

# Base flags common to both BPF and host
# -O3 : Optimization level
# -fPIC : Position-independent code (required for static libs)
# -ffunction-sections / -fdata-sections : Allow linker garbage collection
BASE_FLAGS="-O3 -fPIC -ffunction-sections -fdata-sections $INC"

# Append base flags and includes to whatever Cargo provides
CFLAGS="${CFLAGS:-} $BASE_FLAGS"
CXXFLAGS="${CXXFLAGS:-} $BASE_FLAGS"

# --- Target-specific flags ---
# TARGET env var is passed from build.rs
echo "build.sh: Building for TARGET=$TARGET"
if [[ "$TARGET" == *"bpf"* || "$TARGET" == *"sbf"* ]]; then
  echo "build.sh: Using SBF/BPF specific flags"
  # SBF/BPF specific flags
  BPF_TARGET_FLAGS="-target bpfel-unknown-unknown -mcpu=generic"
  CFLAGS="$CFLAGS $BPF_TARGET_FLAGS"
  # Add C++17 standard, disable stdlib++, exceptions, RTTI for BPF
  # Also explicitly disable compiler builtins for memcpy and memset for SBF
  SBF_NO_BUILTIN_FLAGS="-fno-builtin-memcpy -fno-builtin-memset"
  CFLAGS="$CFLAGS $BPF_TARGET_FLAGS $SBF_NO_BUILTIN_FLAGS"
  CXXFLAGS="$CXXFLAGS $BPF_TARGET_FLAGS -std=c++17 -nostdlib++ -fno-exceptions -fno-rtti $SBF_NO_BUILTIN_FLAGS"
else
  echo "build.sh: Using native host flags for $TARGET"
  # Native host specific flags (adjust as needed for different hosts)
  # Assume C++17 is desired for host too, but use standard library
  CXXFLAGS="$CXXFLAGS -std=c++17"

  # Add macOS specific flags if on Darwin
  if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "build.sh: Adding macOS specific flags"
    # Match architecture and deployment target with Rust linker flags if possible
    # Using 10.14 as seen in the linker error message
    MACOS_ARCH="x86_64" # Assuming x86_64 based on error log
    MACOS_MIN_VER="10.14"
    CFLAGS="$CFLAGS -arch $MACOS_ARCH -mmacosx-version-min=$MACOS_MIN_VER"
    CXXFLAGS="$CXXFLAGS -arch $MACOS_ARCH -mmacosx-version-min=$MACOS_MIN_VER"
  fi
  # Add flags for other host OSes here if needed (e.g., Linux)
fi

# Tell the portable code path to compile (avoids AES-NI intrinsics)
# This is crucial for BPF compatibility and ensures host uses same logic.
CFLAGS="$CFLAGS -DVERUSHASH_PORTABLE=1"
CXXFLAGS="$CXXFLAGS -DVERUSHASH_PORTABLE=1"

# ------------------------------------------------------------------------------
# 4. Compile every .c / .cpp -> object file
# ------------------------------------------------------------------------------
OBJ_FILES=()
echo "--- Compiling VerusHash sources for BPF ---"
for src in "${EXISTING_SRC_FILES[@]}"; do
  # Place object files directly in OUT_DIR
  obj="$OUT_DIR/$(basename "${src%.*}").o"
  OBJ_FILES+=("$obj")
  echo "Compiling $src -> $obj"
  case "$src" in
  *.c) $CC $CFLAGS -c "$src" -o "$obj" || exit 1 ;;
  *.cpp) $CXX $CXXFLAGS -c "$src" -o "$obj" || exit 1 ;;
  esac
done
echo "-------------------------------------------"

# ------------------------------------------------------------------------------
# 5. Archive into libverushash.a
# ------------------------------------------------------------------------------
# Use llvm-ar for BPF targets, system ar for host targets
if [[ "$TARGET" == *"bpf"* || "$TARGET" == *"sbf"* ]]; then
  AR="${AR:-llvm-ar}"
  echo "build.sh: Using llvm-ar for BPF target"
else
  AR="${AR:-ar}" # Use system ar for host
  echo "build.sh: Using system ar for host target"
fi

ARCHIVE_FILE="$OUT_DIR/libverushash.a"

echo "Archiving object files into $ARCHIVE_FILE using $AR"
# rcs: replace existing files, create archive if needed, suppress output
$AR rcs "$ARCHIVE_FILE" "${OBJ_FILES[@]}" || exit 1

echo "✔ libverushash.a built successfully at $OUT_DIR"

# Optional: Clean up intermediate object files
# rm -f "${OBJ_FILES[@]}"
