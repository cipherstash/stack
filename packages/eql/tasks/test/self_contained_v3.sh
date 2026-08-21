#!/usr/bin/env bash
#MISE description="Assert the eql_v3 surface is self-contained (no eql_v2 symbol/file leakage)"

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

fail=0

# Symbol level (design goal 1): no eql_v2.<symbol> anywhere under src/v3 — the
# hand-written SEM + foundation files plus the gitignored generated scalar
# surface (present because build runs codegen). Run `mise run build` first.
# Match both schema-qualified refs (`eql_v2.<fn>`) and bare v2 entity names
# (`eql_v2_encrypted`, `eql_v2_configuration`, …). Prose like "the eql_v2
# original is unchanged" in doc comments is intentionally still allowed.
echo "==> Symbol gate: no 'eql_v2.' / 'eql_v2_' under src/v3"
if grep -rnE 'eql_v2[._]' src/v3; then
  echo "ERROR: eql_v2 symbol/entity reference found in src/v3 (must be self-contained)" >&2
  fail=1
fi

# File level (design goal 2): the v3-only dependency closure pulls in no file
# outside src/v3/. `eql-codegen order` emits one repo-relative path per line.
#
# Belt-and-braces: surface_order already rejects any `-- REQUIRE:` edge leaving
# src/v3, and the walk is rooted at src/v3, so every node is under it by
# construction. This gate would only fire again if that root ever widened.
if [[ ! -f src/deps-ordered-v3.txt ]]; then
  echo "ERROR: src/deps-ordered-v3.txt missing — run 'mise run build' first" >&2
  exit 2
fi
echo "==> File gate: every path in src/deps-ordered-v3.txt is under src/v3/"
if grep -v '^src/v3/' src/deps-ordered-v3.txt; then
  echo "ERROR: v3 dep closure pulls in a path outside src/v3/ (eql_v2 file leak)" >&2
  fail=1
fi

# Belt-and-braces: the assembled artifact carries no eql_v2 symbol.
echo "==> Artifact gate: release/cipherstash-encrypt.sql has no 'eql_v2.' / 'eql_v2_'"
if [[ ! -f release/cipherstash-encrypt.sql ]]; then
  echo "ERROR: release/cipherstash-encrypt.sql missing — run 'mise run build' first" >&2
  exit 2
fi
if grep -nE 'eql_v2[._]' release/cipherstash-encrypt.sql; then
  echo "ERROR: assembled v3 artifact contains an eql_v2 symbol/entity reference" >&2
  fail=1
fi

if [[ $fail -ne 0 ]]; then
  echo "self-containment gate FAILED" >&2
  exit 1
fi
echo "self-containment gate OK"
