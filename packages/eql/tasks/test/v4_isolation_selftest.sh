#!/usr/bin/env bash
#MISE description="DB-free self-test for the v4 isolation gate (clean passes, small and wholesale leaks fail)"
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

# Run the gate on one case and require an exact exit status. The gate exits 1
# on a leak and 2 on bad input or a fault, so "non-zero" would let a crashed
# gate pass every rejection case.
expect() {
  local want=$1 what=$2 file=$3 rc=0
  bash tasks/test/verify_no_v3_in_v4.sh "$file" >/dev/null 2>&1 || rc=$?
  if [[ $rc -ne $want ]]; then
    echo "FAIL: $what: gate exited $rc, expected $want"
    exit 1
  fi
  echo "ok: $what (exit $rc)"
}

# CLEAN: names eql_v4, checks version 4, names nothing from v3.
printf "CREATE SCHEMA eql_v4;\nCHECK (VALUE->>'v' = '4');\nSELECT jsonb_build_object('v', val->'v');\n" > "$tmp/clean.sql"
expect 0 "clean v4 bundle accepted" "$tmp/clean.sql"

# ONE stray reference.
printf "CREATE SCHEMA eql_v4;\nSELECT eql_v3.eq_term(x);\n" > "$tmp/one.sql"
expect 1 "one eql_v3 reference rejected" "$tmp/one.sql"

# WHOLESALE leak: far more matching lines than a pipe buffer holds. A
# `grep | head` check under pipefail read this as no leak (SIGPIPE).
{
  echo "CREATE SCHEMA eql_v4;"
  for i in $(seq 1 20000); do echo "SELECT eql_v3_internal.f$i(eql_v4.g());"; done
} > "$tmp/wholesale.sql"
expect 1 "wholesale eql_v3 leak rejected" "$tmp/wholesale.sql"

# The version check, wholesale too.
{
  echo "CREATE SCHEMA eql_v4;"
  for i in $(seq 1 20000); do echo "CHECK (VALUE->>'v' = '3');"; done
} > "$tmp/version.sql"
expect 1 "wholesale version-3 checks rejected" "$tmp/version.sql"

# Other spellings of a version check that is not v4's. The gate accepts only
# `->> 'v' = '4'`, so each of these is refused without being listed there.
n=0
for check in \
  "VALUE->>'v' IN ('3')" \
  "'3' = VALUE->>'v'" \
  "(VALUE->>'v')::int = 3" \
  "VALUE->>'v' = '40'" \
  "(VALUE->'v') = '3'::jsonb" \
  "'3'::jsonb = VALUE->'v'"; do
  n=$((n + 1))
  printf "CREATE SCHEMA eql_v4;\nCHECK (%s);\n" "$check" > "$tmp/spelling$n.sql"
  expect 1 "version check rejected: $check" "$tmp/spelling$n.sql"
done

# NON-VACUITY: a file that never names eql_v4 is not a v4 render.
printf "SELECT 1;\n" > "$tmp/none.sql"
expect 1 "non-v4 render rejected" "$tmp/none.sql"

# BAD INPUT is a fault, not a leak.
expect 2 "missing file is bad input" "$tmp/does-not-exist.sql"
: > "$tmp/empty.sql"
expect 2 "empty file is bad input" "$tmp/empty.sql"
