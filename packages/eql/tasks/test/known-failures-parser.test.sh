#!/usr/bin/env bash
#MISE description="Unit-test the known-failure gate's strict ISSUE_ declaration parser"
#
# The gate in known-failures.sh is fail-closed by construction: it counts
# declarations with a LOOSE matcher and cross-checks that count against a STRICT
# parse. A declaration the strict parse cannot recover is drift, and drift is a
# hard error (exit 2) — never a silent pass.
#
# These cases pin that contract at the seam where it is easiest to break: the
# strict `sed` expression. A regex that accepts more than the documented grammar
# (`pub const ISSUE_<NAME>: u64 = <n>;` + optional line comment) lets a malformed
# declaration read as well-formed, and the declared-vs-parsed cross-check — the
# gate's only defence — silently agrees.
#
# Portability: bash 3.2, matching known-failures.sh itself.
set -euo pipefail

GATE="$(cd "$(dirname "$0")" && pwd)/known-failures.sh"
failures=0

# Run the gate against a throwaway EQL_ROOT holding only `$1` as its registry.
# Echoes the exit status; never itself exits non-zero.
#
# The registry is the gate's sole input, and every case here is decided before
# the gate makes a `gh` call, so this stays hermetic and offline.
run_gate_with_registry() {
  root=$(mktemp -d)
  mkdir -p "${root}/tests/sqlx/src" "${root}/tests/sqlx/tests"
  printf '%s\n' "$1" > "${root}/tests/sqlx/src/known_failure.rs"
  status=0
  EQL_ROOT="$root" bash "$GATE" >/dev/null 2>&1 || status=$?
  rm -rf "$root"
  echo "$status"
}

expect_status() {
  description="$1"; expected="$2"; registry="$3"
  actual=$(run_gate_with_registry "$registry")
  if [ "$actual" = "$expected" ]; then
    echo "  ✓ ${description}"
  else
    echo "  ✗ ${description}: expected exit ${expected}, got ${actual}" >&2
    failures=1
  fi
}

REPO_LINE='pub const KNOWN_FAILURE_REPO: &str = "cipherstash/encrypt-query-language";'

echo "==> known-failure parser"

# Arbitrary trailing text is NOT part of the documented grammar. It must read as
# drift (exit 2), not parse as a well-formed declaration. Were the strict regex
# to accept it, `declared` and `parsed` would agree and the gate would wave the
# malformed line through.
expect_status "trailing junk after the semicolon is drift" 2 \
  "${REPO_LINE}
pub const ISSUE_JUNK: u64 = 5; junk"

# The negative controls: everything the comment promises to tolerate must still
# parse, or the tightened regex has over-corrected into false drift. These pass
# the parse and fail LATER (exit 1, "referenced by no test") — the temp root has
# no tests referencing the constant. Exit 1 therefore proves the parse succeeded,
# which is precisely what these cases assert.
expect_status "a bare declaration parses" 1 \
  "${REPO_LINE}
pub const ISSUE_BARE: u64 = 5;"

expect_status "a trailing line comment parses" 1 \
  "${REPO_LINE}
pub const ISSUE_COMMENTED: u64 = 5; // see #5"

expect_status "leading indentation and _ digit separators parse" 1 \
  "${REPO_LINE}
    pub const ISSUE_INDENTED: u64 = 1_000;"

if [ "$failures" -ne 0 ]; then
  echo >&2
  echo "known-failure parser tests FAILED" >&2
  exit 1
fi

echo "known-failure parser tests OK"
