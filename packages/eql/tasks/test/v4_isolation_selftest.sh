#!/usr/bin/env bash
#MISE description="DB-free self-test for the v4 isolation gate (clean passes, small and wholesale leaks fail)"
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

gate() { bash tasks/test/verify_no_v3_in_v4.sh "$@" >/dev/null 2>&1; }

# CLEAN: names eql_v4, checks version 4, names nothing from v3.
printf "CREATE SCHEMA eql_v4;\nCHECK (VALUE->>'v' = '4');\n" > "$tmp/clean.sql"
gate "$tmp/clean.sql" || { echo "FAIL: clean v4 bundle rejected"; exit 1; }
echo "ok: clean v4 bundle accepted"

# ONE stray reference.
printf "CREATE SCHEMA eql_v4;\nSELECT eql_v3.eq_term(x);\n" > "$tmp/one.sql"
if gate "$tmp/one.sql"; then echo "FAIL: one eql_v3 reference accepted"; exit 1; fi
echo "ok: one eql_v3 reference rejected"

# WHOLESALE leak: far more matching lines than a pipe buffer holds. A
# `grep | head` check under pipefail read this as no leak (SIGPIPE).
{
  echo "CREATE SCHEMA eql_v4;"
  for i in $(seq 1 20000); do echo "SELECT eql_v3_internal.f$i(eql_v4.g());"; done
} > "$tmp/wholesale.sql"
if gate "$tmp/wholesale.sql"; then echo "FAIL: wholesale eql_v3 leak accepted"; exit 1; fi
echo "ok: wholesale eql_v3 leak rejected"

# The version check, wholesale too.
{
  echo "CREATE SCHEMA eql_v4;"
  for i in $(seq 1 20000); do echo "CHECK (VALUE->>'v' = '3');"; done
} > "$tmp/version.sql"
if gate "$tmp/version.sql"; then echo "FAIL: wholesale version-3 checks accepted"; exit 1; fi
echo "ok: wholesale version-3 checks rejected"

# NON-VACUITY: a file that never names eql_v4 is not a v4 render.
printf "SELECT 1;\n" > "$tmp/none.sql"
if gate "$tmp/none.sql"; then echo "FAIL: non-v4 render accepted"; exit 1; fi
echo "ok: non-v4 render rejected"
