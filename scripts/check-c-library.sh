#!/usr/bin/env bash
# Check that a Linux release binary links the C library its platform claims.
#
# The one copy of these rules: both build workflows run it on each Linux
# binary before packing, and both preflights run it on the packed tarballs.
#
# `file` reads gnu and musl x86-64 binaries identically, so the C library is
# read from the NEEDED entries, the libraries the loader must load with it.
# A musl binary must name musl, not only avoid glibc: a statically linked
# binary names no C library, and Node.js cannot load it as a native module.
#
# A platform with no rule fails, so a new Linux platform cannot ship unchecked.
#
# Usage: check-c-library.sh <platform> <binary>
set -euo pipefail

usage='usage: check-c-library.sh <platform> <binary>'
platform=${1:?$usage}
binary=${2:?$usage}

# Into a variable, never piped into `grep -q`: grep exits at the first match,
# readelf takes SIGPIPE, and under pipefail the musl glibc test fails open.
dynamic=$(readelf -d "$binary")

needs() { grep -q "NEEDED.*$1" <<< "$dynamic"; }

case "$platform" in
  linux-x64-gnu|linux-arm64-gnu)
    needs 'libc\.so\.6' || {
      echo "::error::$platform does not link glibc"; exit 1; } ;;
  linux-x64-musl)
    if needs 'libc\.so\.6'; then
      echo "::error::$platform links glibc — it is the gnu binary"; exit 1
    fi
    needs 'libc\.musl-' || {
      echo "::error::$platform has no musl libc NEEDED entry — it is linked statically"
      exit 1; } ;;
  *)
    echo "::error::no C library rule for $platform"; exit 1 ;;
esac
echo "$platform: links the expected C library"
