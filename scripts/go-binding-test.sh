#!/usr/bin/env bash
# Format check, vet and test one Go binding module against its embedded guest.
#
# One definition of "the Go binding passes", run on three platforms: the mise
# task `go:test` (Linux CI, and locally) and the macOS/Windows
# jobs in .github/workflows/test-wasi.yml both call this, so they cannot
# drift apart. The guest module itself is built once, on Linux, and handed to
# the other platforms as an artifact — the wasm is platform-independent and
# the Rust build is the slow part.
#
# Usage: go-binding-test.sh <module dir> [<guest path, relative to it>...]
# With no guest paths, both guests the module embeds are expected.
set -euo pipefail

dir=${1:?usage: go-binding-test.sh <module dir> [<guest path>...]}
shift || true
if [ $# -eq 0 ]; then
  set -- stackencrypt/wasm/stack_encrypt_guest.wasm stackauth/wasm/stack_auth_guest.wasm
fi

cd "$dir"
for guest in "$@"; do
  if [ ! -f "$guest" ]; then
    echo "guest module not built at $dir/$guest — run: mise run wasm:guest:build wasm:auth-guest:build" >&2
    exit 1
  fi
done

# gofmt exits 0 even when files need formatting; -l lists them.
out=$(gofmt -l .)
if [ -n "$out" ]; then
  echo "gofmt needed:"
  echo "$out"
  exit 1
fi

go vet ./...
CGO_ENABLED=0 go test ./...

# The transport codec's u32-bound guards are load-bearing where int is 32
# bits (vitaminc's vcffi runs this sweep too); the binding's own reflection
# and buffer arithmetic must hold there as well. Linux hosts execute 386
# natively; elsewhere the binary cannot run, so only vet.
if [ "$(uname -s)" = "Linux" ]; then
  CGO_ENABLED=0 GOOS=linux GOARCH=386 go test ./...
else
  CGO_ENABLED=0 GOOS=linux GOARCH=386 go vet ./...
fi
