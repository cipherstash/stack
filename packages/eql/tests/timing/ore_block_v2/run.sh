#!/usr/bin/env bash
# Timing harness for EQL v4's block ORE comparator (compare_ore_block_v2_terms).
# By hand, not CI: timing on shared runners is too noisy to gate on.
#
#   DATABASE_URL=postgres://... tests/timing/ore_block_v2/run.sh [samples]
#
# DATABASE_URL must point at a database with the EQL v4 bundle installed (e.g.
# release/cipherstash-encrypt-v4.sql from `mise run build`). Needs psql and
# cargo. samples defaults to 100000 per kind, a few minutes in all. See
# README.md for the method and how to read the output.
set -euo pipefail

samples="${1:-100000}"
here="$(cd "$(dirname "$0")" && pwd)"
: "${DATABASE_URL:?set DATABASE_URL to a database with the EQL v4 bundle installed}"

# Everything lives in the ore_v2_timing schema, which is dropped on exit.
# Refuse to start if it already exists, so a run never drops a schema it did
# not make. A failed psql is reported as itself, not as an existing schema.
if ! exists="$(psql "$DATABASE_URL" -tA -c "SELECT to_regnamespace('ore_v2_timing') IS NOT NULL")"; then
    echo "could not query the database at DATABASE_URL (see the psql error above)" >&2
    exit 1
fi
if [ "$exists" != "f" ]; then
    echo "schema ore_v2_timing already exists; not touching it" >&2
    exit 1
fi

tmp="$(mktemp -d)"
created=0
cleanup() {
    rm -rf "$tmp"
    if [ "$created" = 1 ]; then
        psql "$DATABASE_URL" -q -c "DROP SCHEMA ore_v2_timing CASCADE" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

echo "== generating ciphertexts (ore-rs, throwaway key)"
cargo run --locked --quiet --release --manifest-path "$here/ctgen/Cargo.toml" -- 256 >"$tmp/ct.tsv"

psql "$DATABASE_URL" -q -v ON_ERROR_STOP=1 -c "CREATE SCHEMA ore_v2_timing" >/dev/null
created=1
psql "$DATABASE_URL" -q -v ON_ERROR_STOP=1 \
    -c "CREATE TABLE ore_v2_timing.staging (kind text, label text, a_hex text, b_hex text)" \
    -c "\\copy ore_v2_timing.staging FROM '$tmp/ct.tsv'" >/dev/null
psql "$DATABASE_URL" -q -v ON_ERROR_STOP=1 -f "$here/harness.sql" >/dev/null

echo "== correctness (must be 0 wrong before timing means anything)"
wrong="$(psql "$DATABASE_URL" -tA -c "
  SELECT count(*) FILTER (WHERE eql_v4_internal.compare_ore_block_v2_terms(a, b) IS DISTINCT FROM expected)
       + count(*) FILTER (WHERE eql_v4_internal.compare_ore_block_v2_terms(b, a) IS DISTINCT FROM -expected)
  FROM ore_v2_timing.checks")"
echo "   wrong: $wrong"
[ "$wrong" = "0" ] || { echo "comparator disagrees with plaintext order; not timing"; exit 1; }

echo "== timing (two runs per kind; classes: see README.md)"
for run in 1 2; do
    psql "$DATABASE_URL" -q -v ON_ERROR_STOP=1 -c "
      CREATE TABLE ore_v2_timing.fixed_$run AS SELECT * FROM ore_v2_timing.bench('fixed', $samples, 16);
      CREATE TABLE ore_v2_timing.equal_$run AS SELECT * FROM ore_v2_timing.bench('equal', $samples, 16);
      CREATE TABLE ore_v2_timing.chained_$run AS SELECT * FROM ore_v2_timing.bench('chained', $samples, 8);
      CREATE TABLE ore_v2_timing.prefix_$run AS SELECT * FROM ore_v2_timing.bench('prefix', $samples, 8);"
done
psql "$DATABASE_URL" -c "
  SELECT * FROM ore_v2_timing.welch('fixed, first vs last block, 16/sample #1', 'ore_v2_timing.fixed_1')
  UNION ALL SELECT * FROM ore_v2_timing.welch('fixed, first vs last block, 16/sample #2', 'ore_v2_timing.fixed_2')
  UNION ALL SELECT * FROM ore_v2_timing.welch('fixed, equal vs first block, 16/sample #1', 'ore_v2_timing.equal_1')
  UNION ALL SELECT * FROM ore_v2_timing.welch('fixed, equal vs first block, 16/sample #2', 'ore_v2_timing.equal_2')
  UNION ALL SELECT * FROM ore_v2_timing.welch('chained, first vs last block, 8/sample #1', 'ore_v2_timing.chained_1')
  UNION ALL SELECT * FROM ore_v2_timing.welch('chained, first vs last block, 8/sample #2', 'ore_v2_timing.chained_2')
  UNION ALL SELECT * FROM ore_v2_timing.welch('chained, prefix vs first block, 8/sample #1', 'ore_v2_timing.prefix_1')
  UNION ALL SELECT * FROM ore_v2_timing.welch('chained, prefix vs first block, 8/sample #2', 'ore_v2_timing.prefix_2');"
