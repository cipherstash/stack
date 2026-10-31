#!/usr/bin/env bash
# Credential-free shared cases plus fresh Go -> native Rust artifact exchange.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ -n "${STACK_CONFORMANCE_UPDATE:-}" ]]; then
  echo 'Conformance checks must not update frozen artifacts.' >&2
  exit 1
fi
unset STACK_CONFORMANCE_INPUT STACK_CONFORMANCE_OUTPUT
export STACK_CONFORMANCE_REQUIRED=1

if [[ ! -s languages/golang/encrypt/testdata/stack_encrypt_guest_deterministic.wasm ]]; then
  echo 'Build the test guest first: mise run wasm:guest:build:deterministic' >&2
  exit 1
fi

artifacts=$(mktemp -d)
trap 'rm -rf "$artifacts"' EXIT

mise x --env test -- cargo nextest run --locked -p stack-encrypt --all-features --test conformance
(
  cd languages/golang
  STACK_CONFORMANCE_OUTPUT="$artifacts/go.json" CGO_ENABLED=0 \
    go test -count=1 -v -run '^TestStackConformance$' ./encrypt
)
test -s "$artifacts/go.json"
STACK_CONFORMANCE_INPUT="$artifacts/go.json" mise x --env test -- \
  cargo nextest run --locked -p stack-encrypt --all-features --test conformance
