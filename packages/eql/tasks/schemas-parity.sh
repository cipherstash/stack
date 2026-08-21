#!/usr/bin/env bash
#MISE description="Drift gate: the SQL eql_v3_internal.owned_schemas() array must match the Rust codegen SCHEMA/INTERNAL_SCHEMA consts (via the list-schemas subcommand)"

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# The schema split is declared in two places that must never drift:
#   * Rust: consts::SCHEMA / consts::INTERNAL_SCHEMA (crates/eql-codegen/src/consts.rs),
#     surfaced by `eql-codegen list-schemas`, public first.
#   * SQL:  the ARRAY[...] literal in eql_v3_internal.owned_schemas()
#     (src/v3/schema.sql), which every SQL consumer (lints(), pin_search_path)
#     scans across.
# This gate is DB-free: it compares the two source-of-truth declarations
# directly, so a hand-edit to one side without the other fails CI before any
# Postgres install. The installed-DB copy is separately pinned by
# `owned_schemas_returns_exactly_the_two_v3_schemas` in tests/sqlx.

SCHEMA_SQL="src/v3/schema.sql"

# Pull the ARRAY['eql_v3', 'eql_v3_internal']::name[] literal from the
# owned_schemas() body and extract its single-quoted tokens, in order.
array_literal=$(grep -oE "ARRAY\[[^]]*\]::name\[\]" "$SCHEMA_SQL" | head -1 || true)
if [ -z "$array_literal" ]; then
  echo "ERROR: could not find the ARRAY[...]::name[] literal in $SCHEMA_SQL" >&2
  echo "       (eql_v3_internal.owned_schemas() body changed shape?)" >&2
  exit 1
fi
sql_schemas=$(printf '%s\n' "$array_literal" | grep -oE "'[^']*'" | tr -d "'")

rust_schemas=$(cargo run -q -p eql-codegen -- list-schemas)

if [ "$sql_schemas" != "$rust_schemas" ]; then
  echo "SCHEMA DRIFT: SQL owned_schemas() and Rust codegen consts disagree." >&2
  echo "  SQL  ($SCHEMA_SQL, eql_v3_internal.owned_schemas()):" >&2
  printf '    %s\n' $sql_schemas >&2
  echo "  Rust (eql-codegen list-schemas / consts.rs SCHEMA,INTERNAL_SCHEMA):" >&2
  printf '    %s\n' $rust_schemas >&2
  echo "  Fix: reconcile src/v3/schema.sql and crates/eql-codegen/src/consts.rs" >&2
  echo "       (both must list the same schemas, public first)." >&2
  exit 1
fi

echo "SCHEMAS PARITY OK: SQL owned_schemas() matches the Rust codegen consts."
