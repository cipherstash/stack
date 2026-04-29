#!/usr/bin/env bash
# End-to-end smoke test for `stash encrypt`.
#
# Requires a local Postgres you have superuser on. Creates & destroys
# `stash_e2e_test`. Requires CipherStash credentials in the environment
# for the actual encryption step (CS_CLIENT_ACCESS_KEY etc).
#
# Usage: bash packages/cli/scripts/e2e-encrypt.sh

set -euo pipefail

DB=${STASH_E2E_DB:-stash_e2e_test}
HOST=${STASH_E2E_HOST:-localhost}
DATABASE_URL="postgres://${USER}@${HOST}/${DB}"
STASH="$(cd "$(dirname "$0")/../dist/bin" && pwd)/stash.js"
FIXTURES="$(cd "$(dirname "$0")/fixtures" && pwd)"

if [ ! -x "$STASH" ]; then
  echo "CLI not built. Run: pnpm --filter @cipherstash/cli build" >&2
  exit 1
fi

psql -h "$HOST" -d postgres -c "DROP DATABASE IF EXISTS ${DB}" >/dev/null
psql -h "$HOST" -d postgres -c "CREATE DATABASE ${DB}" >/dev/null

export DATABASE_URL

echo "==> 1. Install EQL + cs_migrations"
"$STASH" db install --force

echo "==> 2. Seed 5000 plaintext users"
psql "$DATABASE_URL" -f "$FIXTURES/seed-users.sql" >/dev/null
psql "$DATABASE_URL" -c "ALTER TABLE users ADD COLUMN email_encrypted eql_v2_encrypted" >/dev/null

echo "==> 3. Record dual-writing"
"$STASH" encrypt advance --to dual-writing --table users --column email

echo "==> 4. Backfill with interrupt/resume"
"$STASH" encrypt backfill --table users --column email --chunk-size 500 &
PID=$!
sleep 2
kill -INT "$PID" || true
wait "$PID" || true
"$STASH" encrypt backfill --table users --column email

REMAINING=$(psql "$DATABASE_URL" -At -c "SELECT count(*) FROM users WHERE email_encrypted IS NULL")
if [ "$REMAINING" != "0" ]; then
  echo "FAIL: ${REMAINING} rows still unencrypted" >&2
  exit 1
fi
echo "OK: all 5000 rows encrypted"

echo "==> 5. Status"
"$STASH" encrypt status

echo "==> 6. Cutover"
"$STASH" encrypt cutover --table users --column email

echo "==> 7. Drop"
"$STASH" encrypt drop --table users --column email --migrations-dir "$(pwd)/drizzle"

echo "==> Done."
