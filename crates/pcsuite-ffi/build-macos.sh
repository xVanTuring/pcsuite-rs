#!/usr/bin/env bash
# Build the static library + Swift glue for an Xcode/SwiftUI macOS target.
#
#   ./build-macos.sh              # release, host arch only (fast; for local dev)
#   ./build-macos.sh --universal  # arm64 + x86_64 lipo'd into one .a (for shipping)
#
# Outputs (paths printed at the end):
#   target/release/libpcsuite_ffi.a              (host)            — or
#   target/universal/libpcsuite_ffi.a            (--universal)
#   crates/pcsuite-ffi/generated/                Swift + C glue    — add to Xcode
set -euo pipefail
cd "$(dirname "$0")/../.."   # -> workspace root (pcsuite-rs/)

UNIVERSAL=0
[[ "${1:-}" == "--universal" ]] && UNIVERSAL=1

echo "▶ generating Swift glue + building Rust static lib (release)…"
if [[ $UNIVERSAL == 1 ]]; then
  rustup target add aarch64-apple-darwin x86_64-apple-darwin >/dev/null 2>&1 || true
  cargo build -p pcsuite-ffi --release --target aarch64-apple-darwin
  cargo build -p pcsuite-ffi --release --target x86_64-apple-darwin
  mkdir -p target/universal
  lipo -create \
    target/aarch64-apple-darwin/release/libpcsuite_ffi.a \
    target/x86_64-apple-darwin/release/libpcsuite_ffi.a \
    -output target/universal/libpcsuite_ffi.a
  LIB="target/universal/libpcsuite_ffi.a"
else
  cargo build -p pcsuite-ffi --release
  LIB="target/release/libpcsuite_ffi.a"
fi

echo
echo "✅ done."
echo "   static lib : $(pwd)/$LIB"
echo "   swift glue : $(pwd)/crates/pcsuite-ffi/generated/"
echo "   link flags : add -liconv to the Xcode target's Other Linker Flags"
echo "   next       : see crates/pcsuite-ffi/SWIFT_INTEGRATION.md"
