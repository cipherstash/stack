#!/usr/bin/env bash
#MISE description="Assert the eql_v4 installer and uninstaller name nothing from eql_v3 (DB-free)"
#
# ADR-0002 installs one SQL source under two names, so a column's domain says
# which engine produced its terms. That holds only while the v4 bundle is v3's
# SQL with EVERY name and version changed. A stray eql_v3 reference installs
# cleanly and then quietly compares v4 data with v3 terms, or casts a v4 payload
# to a v3 domain.
#
# `eql-codegen render` already refuses a literal eql_v3 in the source. This
# checks the built artefact, so it also catches a build step that splices text
# in around the renderer.
#
# Usage: verify_no_v3_in_v4.sh [file...]   (exit 1 on a leak, 2 on bad input)
# With no arguments it checks the v4 installer and uninstaller in release/.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

if [[ $# -eq 0 ]]; then
  set -- release/cipherstash-encrypt-v4.sql release/cipherstash-encrypt-v4-uninstall.sql
fi

# Capture matches before printing them. `grep | head -5` under pipefail is
# false whenever grep has more output than the pipe holds: head exits, grep
# dies of SIGPIPE, and a wholesale leak read as no leak at all.
report() {
  local f=$1 what=$2 hits=$3
  sed -n "1,5s|^|$f:|p" <<<"$hits"
  echo "ERROR: $f $what (first 5 shown)" >&2
  fail=1
}

fail=0
for f in "$@"; do
  if [[ ! -s "$f" ]]; then
    echo "ERROR: $f missing or empty — run 'mise run build' first" >&2
    exit 2
  fi
  # Non-vacuity: a v4 bundle that never names eql_v4 was not rendered as v4.
  if ! grep -q 'eql_v4' "$f"; then
    echo "ERROR: $f never names eql_v4 — not a v4 render" >&2
    fail=1
  fi
  if hits=$(grep -n 'eql_v3' "$f"); then
    report "$f" "names eql_v3" "$hits"
  fi
  # The domain CHECKs compare the payload version. Any v3 comparison left in
  # the v4 bundle would admit v3 payloads into v4 columns.
  if hits=$(grep -nE "'v'[[:space:]]*=[[:space:]]*'3'" "$f"); then
    report "$f" "checks for payload version 3" "$hits"
  fi
done

if [[ $fail -ne 0 ]]; then
  echo "v4 isolation gate FAILED" >&2
  exit 1
fi
echo "v4 isolation gate OK ($# files)"
