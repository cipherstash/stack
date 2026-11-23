#!/usr/bin/env bash
# Prints the lines of a release's guests.sha256 that belong to one Go module,
# with each path made relative to that module's directory: the paths its
# module zip holds them at. release-golang.yml's `verify` job checks each
# module zip the Go proxy serves against this.
#
# A guest belongs to the module whose directory is the longest one above it:
# encrypt/encrypttest/wasm/… is the encrypttest module's, not the SDK's,
# though both directories are above it. Exits non-zero when no guest belongs
# to the module, since a module the release tags with no guests to check is
# a release that checks nothing.
#
# Usage: go-release-module-guests.sh <guests.sha256> <module dir> <every module dir>...
set -euo pipefail

manifest=${1:?usage: go-release-module-guests.sh <guests.sha256> <module dir> <module dirs>...}
module=${2:?usage: go-release-module-guests.sh <guests.sha256> <module dir> <module dirs>...}
shift 2
if [ $# -eq 0 ]; then
  echo "error: name every module directory the release tags" >&2
  exit 2
fi

found=0
while read -r sum path; do
  owner=""
  for candidate in "$@"; do
    case "$path" in
      "$candidate"/*)
        if [ "${#candidate}" -gt "${#owner}" ]; then owner=$candidate; fi
        ;;
    esac
  done
  if [ "$owner" = "$module" ]; then
    echo "$sum  ${path#"$module"/}"
    found=$((found + 1))
  fi
done < "$manifest"

if [ "$found" -eq 0 ]; then
  echo "error: no guest in $manifest belongs to $module" >&2
  exit 1
fi
