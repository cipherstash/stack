#!/usr/bin/env bash
#
# Vendor the generated EQL v3 TypeScript payload types (eql-bindings crate,
# ts-rs output) into src/eql-v3-types/.
#
# The vendored files are GENERATED — never hand-edit them. To refresh:
#
#   ./scripts/sync-eql-v3-types.sh [path-to-encrypt-query-language]
#
# By default the source is the LOCKED eql-bindings release: the published
# crate ships its ts-rs output (`bindings/**`), and `cargo metadata` resolves
# the exact copy in the cargo registry that Cargo.lock pins. The vendored TS
# types therefore cannot drift from the release the Rust conversion code links
# against. Integration SQL comes independently from the matching exact
# @cipherstash/eql version in integration-tests/package-lock.json.
#
# Passing a path to an encrypt-query-language checkout as $1 overrides the
# source for local development against unreleased bindings — regenerate the
# ts-rs output there first (`cargo test -p eql-bindings` writes
# crates/eql-bindings/bindings/v3/), and re-run WITHOUT the override before
# committing so the committed types carry release provenance.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${REPO_ROOT}/src/eql-v3-types"

if [ $# -ge 1 ]; then
  EQL_BINDINGS_DIR="${1}/crates/eql-bindings"
  PROVENANCE="checkout ${1}"
else
  EQL_BINDINGS_DIR="$(
    cd "${REPO_ROOT}" &&
      cargo metadata --format-version 1 --locked |
      python3 -c '
import json, os, sys
pkgs = [p for p in json.load(sys.stdin)["packages"] if p["name"] == "eql-bindings"]
if not pkgs:
    sys.exit("eql-bindings not in the cargo dependency graph")
print(os.path.dirname(pkgs[0]["manifest_path"]))
'
  )"
  PROVENANCE="locked release $(basename "${EQL_BINDINGS_DIR}")"
fi

SRC="${EQL_BINDINGS_DIR}/bindings/v3"

if [ ! -d "${SRC}" ]; then
  echo "error: ${SRC} not found — pass an encrypt-query-language checkout as \$1, or check the locked eql-bindings crate ships bindings/**" >&2
  exit 1
fi

mkdir -p "${DEST}"
rm -f "${DEST}"/*.ts

for file in "${SRC}"/*.ts; do
  name="$(basename "${file}")"
  {
    echo "// @generated — vendored from eql-bindings bindings/v3 (encrypt-query-language)."
    echo "// Do not hand-edit. Refresh with scripts/sync-eql-v3-types.sh."
    cat "${file}"
  } > "${DEST}/${name}"
done

echo "Vendored $(ls "${DEST}" | wc -l | tr -d ' ') files into src/eql-v3-types/ from ${PROVENANCE}"
