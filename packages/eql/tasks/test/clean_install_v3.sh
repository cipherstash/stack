#!/usr/bin/env bash
#MISE description="Install release/cipherstash-encrypt.sql into a scratch DB with NO eql_v2 and smoke-test it (D11, D4)"
#USAGE flag "--port <port>" help="Postgres port" default="7432"
#USAGE flag "--user <user>" help="Postgres user" default="cipherstash"

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

PG_PORT="${usage_port:-7432}"
PG_USER="${usage_user:-cipherstash}"
export PGPASSWORD="${POSTGRES_PASSWORD:-password}"
SCRATCH_DB="cipherstash_v3_clean"

ADMIN=(psql -U "$PG_USER" -h localhost -p "$PG_PORT" -d postgres -v ON_ERROR_STOP=1 -q)
RUN=(psql -U "$PG_USER" -h localhost -p "$PG_PORT" -d "$SCRATCH_DB" -v ON_ERROR_STOP=1 -q)

test -f release/cipherstash-encrypt.sql || { echo "Build first: release/cipherstash-encrypt.sql missing" >&2; exit 2; }

echo "==> (re)creating scratch database $SCRATCH_DB (no eql_v2 installed)"
"${ADMIN[@]}" -c "DROP DATABASE IF EXISTS ${SCRATCH_DB} WITH (FORCE);"
"${ADMIN[@]}" -c "CREATE DATABASE ${SCRATCH_DB};"

cleanup() { "${ADMIN[@]}" -c "DROP DATABASE IF EXISTS ${SCRATCH_DB} WITH (FORCE);" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "==> installing the standalone eql_v3 surface"
"${RUN[@]}" -f release/cipherstash-encrypt.sql

echo "==> asserting NO eql_v2 schema exists (proves no v2 dependency)"
"${RUN[@]}" -c "DO \$\$ BEGIN IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'eql_v2') THEN RAISE EXCEPTION 'eql_v2 schema unexpectedly present'; END IF; END \$\$;"

echo "==> smoke: domains, SEM types, extractors, opclass functional index (D4)"
"${RUN[@]}" <<'SQL'
-- Domains stay in eql_v3; SEM index-term types now live in eql_v3_internal.
SELECT 'public.eql_v3_integer_ord'::regtype;
SELECT 'eql_v3_internal.hmac_256'::regtype;
SELECT 'eql_v3_internal.ore_block_256'::regtype;

-- Real ordered-domain columns + the documented functional indexes, one per
-- ordering path. `_ord` is CLLW-OPE: eql_v3.ord_term returns a bytea-backed
-- type with a native btree opclass, so its index needs nothing installed.
-- `_ord_ore` is block-ORE and is the D4 proof: eql_v3.ord_term_ore's index
-- fails outright if the ported operator_class is absent.
CREATE TABLE v3_smoke (c public.eql_v3_integer_ord, c_ore public.eql_v3_integer_ord_ore);
CREATE INDEX v3_smoke_ord ON v3_smoke (eql_v3.ord_term(c));
CREATE INDEX v3_smoke_ord_ore ON v3_smoke (eql_v3.ord_term_ore(c_ore));
DROP TABLE v3_smoke;
SQL

echo "==> smoke: the shared blocker is reachable and raises"
"${RUN[@]}" <<'SQL'
DO $$
DECLARE
  raised boolean := false;
BEGIN
  -- The blocker always RAISEs; catch it and assert we got the expected message.
  BEGIN
    PERFORM eql_v3_internal.encrypted_domain_unsupported_bool('public.eql_v3_integer', '<');
  EXCEPTION WHEN OTHERS THEN
    raised := true;
    IF SQLERRM <> 'operator < is not supported for public.eql_v3_integer' THEN
      RAISE EXCEPTION 'blocker raised an unexpected message: %', SQLERRM;
    END IF;
  END;

  IF NOT raised THEN
    RAISE EXCEPTION 'blocker eql_v3_internal.encrypted_domain_unsupported_bool did not raise';
  END IF;
END $$;
SQL

echo "==> smoke: v3 searchable encrypted-JSON (SteVec) surface"
"${RUN[@]}" <<'SQL'
CREATE TABLE v3_json_smoke (id int PRIMARY KEY, e public.eql_v3_json_search);
INSERT INTO v3_json_smoke VALUES
  (1, '{"k":"sv","i":{"t":"v3_json_smoke","c":"e"},"v":3,"h":"key-header","sv":[{"s":"sel","c":"ciphertext"}]}'::public.eql_v3_json_search);

-- Supported typed accessors and containment.
SELECT (e -> 'sel'::text)::jsonb ->> 'c' FROM v3_json_smoke WHERE id = 1;
SELECT e ->> 'sel'::text FROM v3_json_smoke WHERE id = 1;
SELECT count(*) FROM v3_json_smoke
WHERE e @> '{"sv":[{"s":"sel"}]}'::eql_v3.query_json;
SELECT count(*) FROM v3_json_smoke
WHERE '{"sv":[{"s":"sel"}]}'::eql_v3.query_json <@ e;

-- Documented GIN expression installs cleanly in a v3-only database.
CREATE INDEX v3_json_smoke_gin
  ON v3_json_smoke USING gin ((eql_v3.to_ste_vec_query(e)::jsonb) jsonb_path_ops);

DO $$
DECLARE
  raised boolean := false;
BEGIN
  BEGIN
    PERFORM e ? 'sel'::text FROM v3_json_smoke WHERE id = 1;
  EXCEPTION WHEN OTHERS THEN
    raised := true;
    IF SQLERRM <> 'operator ? is not supported for public.eql_v3_json_search' THEN
      RAISE EXCEPTION 'json blocker raised an unexpected message: %', SQLERRM;
    END IF;
  END;

  IF NOT raised THEN
    RAISE EXCEPTION 'v3 json blocker did not raise';
  END IF;
END $$;

DROP TABLE v3_json_smoke;
SQL

echo "==> smoke: v3 storage-only encrypted-JSON surface"
"${RUN[@]}" <<'SQL'
-- The bare public.eql_v3_json is ciphertext-only: it accepts a {v,i,c} envelope
-- and rejects a SteVec document (no root c).
CREATE TABLE v3_json_storage_smoke (id int PRIMARY KEY, e public.eql_v3_json);
INSERT INTO v3_json_storage_smoke VALUES
  (1, '{"v":"3","i":{"t":"v3_json_storage_smoke","c":"e"},"c":"ciphertext"}'::public.eql_v3_json);
SELECT count(*) FROM v3_json_storage_smoke WHERE id = 1;

DO $$
DECLARE
  raised boolean := false;
BEGIN
  -- A SteVec document (sv, no root c) must be rejected by the storage CHECK.
  BEGIN
    PERFORM '{"v":3,"i":{"t":"v3_json_storage_smoke","c":"e"},"sv":[{"s":"sel","hm":"00"}]}'::public.eql_v3_json;
  EXCEPTION WHEN check_violation THEN
    raised := true;
  END;
  IF NOT raised THEN
    RAISE EXCEPTION 'v3 storage json CHECK accepted a SteVec document';
  END IF;
END $$;

DROP TABLE v3_json_storage_smoke;
SQL

echo "clean v3 install OK (D11 + D4 proven)"
