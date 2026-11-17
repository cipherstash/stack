#!/usr/bin/env bash
# Format check, vet and test one Go binding module against its embedded guest.
#
# One definition of "the Go binding passes", run on three platforms: the mise
# task `go:test` (Linux CI, and locally) and the macOS/Windows
# jobs in .github/workflows/tests-golang.yml both call this, so they cannot
# drift apart. The guest module itself is built once, on Linux, and handed to
# the other platforms as an artifact — the wasm is platform-independent and
# the Rust build is the slow part.
#
# Usage: go-binding-test.sh <module dir> [<guest path, relative to it>...]
# The modules nested under <module dir> are tested too: see the end.
# With no guest paths, every guest the module embeds is expected: the
# stack-encrypt guest, its build with the EQL types, the credential guest,
# and the two deterministic test builds package encrypttest embeds. Its
# tests fail, rather than skip, without them, so they are checked here first.
set -euo pipefail

# Before the cd below, which a relative $0 would not survive.
scripts=$(cd "$(dirname "$0")" && pwd)

dir=${1:?usage: go-binding-test.sh <module dir> [<guest path>...]}
shift || true
if [ $# -eq 0 ]; then
  set -- encrypt/wasm/stack_encrypt_guest.wasm encrypt/eql/wasm/stack_encrypt_guest_eql.wasm auth/wasm/stack_auth_guest.wasm \
    encrypt/encrypttest/wasm/stack_encrypt_guest_deterministic.wasm encrypt/encrypttest/wasm/stack_encrypt_guest_eql_deterministic.wasm
fi

cd "$dir"
for guest in "$@"; do
  if [ ! -f "$guest" ]; then
    echo "guest module not built at $dir/$guest — run: mise run wasm:guest:build wasm:guest:build:eql wasm:auth-guest:build wasm:guest:build:deterministic wasm:guest:build:eql:deterministic" >&2
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
# Keep the refresh-lock results explicit in CI logs on Linux, macOS, and
# Windows. These tests exercise the platform lock implementation with two
# independent guest instances sharing one auth.json.
CGO_ENABLED=0 go test -v ./auth -run '^TestDeviceRefresh'
# A producer must execute even if Go has cached a previous successful run.
# The guest paths have been checked; reuse positional arguments for test flags.
# Unlike an empty array, "$@" is safe under nounset in macOS's Bash 3.2.
set --
if [[ -n "${STACK_CONFORMANCE_OUTPUT:-}" ]]; then
  set -- -count=1
fi
CGO_ENABLED=0 go test "$@" ./...

# The transport codec's u32-bound guards are load-bearing where int is 32
# bits (vitaminc's vcffi runs this sweep too); the binding's own reflection
# and buffer arithmetic must hold there as well. Linux hosts execute 386
# natively; elsewhere the binary cannot run, so only vet.
if [ "$(uname -s)" = "Linux" ]; then
  CGO_ENABLED=0 GOOS=linux GOARCH=386 go test "$@" ./...
else
  CGO_ENABLED=0 GOOS=linux GOARCH=386 go vet ./...
fi

# Nested modules (encrypt/encrypttest, encrypt/example): `./...` stops at a
# directory with its own go.mod, so each is vetted and tested in turn.
# go-nested-modules.sh lists them for every tool that needs to. gofmt above
# already walked their files.
"$scripts/go-nested-modules.sh" | while IFS= read -r nested; do
  echo "nested module $nested"
  (
    cd "$nested"
    go vet ./...
    CGO_ENABLED=0 go test "$@" ./...
    if [ "$(uname -s)" = "Linux" ]; then
      CGO_ENABLED=0 GOOS=linux GOARCH=386 go test "$@" ./...
    else
      CGO_ENABLED=0 GOOS=linux GOARCH=386 go vet ./...
    fi
  )
done
