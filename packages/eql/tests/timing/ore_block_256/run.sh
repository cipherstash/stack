#!/usr/bin/env bash
# Timing harness for the ORE block comparator (compare_ore_block_256_terms).
# By hand, not CI: timing on shared runners is too noisy to gate on.
#
#   DATABASE_URL=postgres://... tests/timing/ore_block_256/run.sh [samples]
#
# DATABASE_URL must point at a database with EQL installed (e.g. the release
# installer from `mise run build`). Needs psql and cargo. samples defaults to
# 200000 single-term samples (and a quarter as many six-term ones), a few
# minutes in all. See README.md for the method and how to read the output.
set -euo pipefail

samples="${1:-200000}"
here="$(cd "$(dirname "$0")" && pwd)"
: "${DATABASE_URL:?set DATABASE_URL to a database with EQL installed}"

tmp="$(mktemp -d)"
cleanup() {
    rm -rf "$tmp"
    psql "$DATABASE_URL" -q -c "DROP SCHEMA IF EXISTS ore_timing CASCADE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== generating ciphertexts (ore-rs, throwaway key)"
cargo run --quiet --release --manifest-path "$here/ctgen/Cargo.toml" -- 256 >"$tmp/ct.tsv"

psql "$DATABASE_URL" -q -v ON_ERROR_STOP=1 -c "DROP SCHEMA IF EXISTS ore_timing CASCADE" \
    -c "CREATE SCHEMA ore_timing" \
    -c "CREATE TABLE ore_timing.staging (kind text, label text, a_hex text, b_hex text)" \
    -c "\\copy ore_timing.staging FROM '$tmp/ct.tsv'" >/dev/null
psql "$DATABASE_URL" -q -v ON_ERROR_STOP=1 -f "$here/harness.sql" >/dev/null

echo "== correctness (must be 0 wrong before timing means anything)"
wrong="$(psql "$DATABASE_URL" -tA -c "
  SELECT count(*) FILTER (WHERE eql_v3_internal.compare_ore_block_256_terms(a, b) IS DISTINCT FROM expected)
       + count(*) FILTER (WHERE eql_v3_internal.compare_ore_block_256_terms(b, a) IS DISTINCT FROM -expected)
  FROM ore_timing.checks")"
echo "   wrong: $wrong"
[ "$wrong" = "0" ] || { echo "comparator disagrees with plaintext order; not timing"; exit 1; }

echo "== timing (two runs per kind; classes: values first differ early vs late)"
for run in 1 2; do
    psql "$DATABASE_URL" -q -v ON_ERROR_STOP=1 -c "
      CREATE TABLE ore_timing.single_$run AS SELECT * FROM ore_timing.bench('timing1', $samples, 16);
      CREATE TABLE ore_timing.six_$run AS SELECT * FROM ore_timing.bench('timing6', $((samples / 4)), 8);"
done
psql "$DATABASE_URL" -c "
  SELECT * FROM ore_timing.welch('single term, 16/sample #1', 'ore_timing.single_1')
  UNION ALL SELECT * FROM ore_timing.welch('single term, 16/sample #2', 'ore_timing.single_2')
  UNION ALL SELECT * FROM ore_timing.welch('six terms, 8/sample #1', 'ore_timing.six_1')
  UNION ALL SELECT * FROM ore_timing.welch('six terms, 8/sample #2', 'ore_timing.six_2');"
