#!/usr/bin/env bash
# End-to-end smoke test for `stash encrypt`, then `stash decrypt` back to
# plaintext — the full round trip, verified against the original values.
#
# Requires a local Postgres you have superuser on. Creates & destroys
# `stash_e2e_test`. Requires CipherStash credentials in the environment
# for the actual encryption step (CS_CLIENT_ACCESS_KEY etc).
#
# Usage: bash languages/typescript/packages/cli/scripts/e2e-encrypt.sh

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
"$STASH" eql install --force

echo "==> 2. Seed 5000 plaintext users"
psql "$DATABASE_URL" -f "$FIXTURES/seed-users.sql" >/dev/null
psql "$DATABASE_URL" -c "ALTER TABLE users ADD COLUMN email_encrypted public.eql_v3_text_search" >/dev/null

echo "==> 3. Backfill with interrupt/resume (dual-writes confirmed via flag for non-interactive run)"
"$STASH" encrypt backfill --table users --column email --chunk-size 500 --confirm-dual-writes-deployed &
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

echo "==> 4. Status"
"$STASH" encrypt status

echo "==> 5. Switch application reads to email_encrypted (manual deploy step)"

echo "==> 6. Generate plaintext drop migration"
"$STASH" encrypt drop --table users --column email --migrations-dir "$(pwd)/drizzle"
DROP_MIGRATION=$(ls -t "$(pwd)/drizzle"/*_drop_users_email.sql | head -1)
psql "$DATABASE_URL" -f "$DROP_MIGRATION" >/dev/null
ORIGINAL=$(psql "$DATABASE_URL" -At -c "SELECT md5(string_agg('user-' || id || '@example.com', ',' ORDER BY id)) FROM users")

# ---------------------------------------------------------------------------
# Reverse lifecycle: move the column back to plaintext (stash decrypt).
# ---------------------------------------------------------------------------

echo "==> 7. Plan the plaintext twin (users.email_encrypted → email text)"
"$STASH" decrypt plan
"$STASH" decrypt plan --table users --column email_encrypted --migrations-dir "$(pwd)/drizzle"
ADD_MIGRATION=$(ls -t "$(pwd)/drizzle"/*_add_plaintext_users_email.sql | head -1)
psql "$DATABASE_URL" -f "$ADD_MIGRATION" >/dev/null

echo "==> 8. Decrypt backfill with interrupt/resume (reverse dual-writes confirmed via flag)"
"$STASH" decrypt backfill --table users --column email_encrypted --chunk-size 500 --confirm-dual-writes-deployed &
PID=$!
sleep 2
kill -INT "$PID" || true
wait "$PID" || true
"$STASH" decrypt backfill --table users --column email_encrypted

REMAINING=$(psql "$DATABASE_URL" -At -c "SELECT count(*) FROM users WHERE email_encrypted IS NOT NULL AND email IS NULL")
if [ "$REMAINING" != "0" ]; then
  echo "FAIL: ${REMAINING} rows still undecrypted" >&2
  exit 1
fi
ROUNDTRIP=$(psql "$DATABASE_URL" -At -c "SELECT md5(string_agg(email, ',' ORDER BY id)) FROM users")
if [ "$ROUNDTRIP" != "$ORIGINAL" ]; then
  echo "FAIL: decrypted plaintext does not match the original values" >&2
  exit 1
fi
echo "OK: all 5000 rows decrypted back to their original plaintext"

echo "==> 9. Reverse status"
"$STASH" decrypt status

echo "==> 10. Switch application reads to email (manual deploy step)"

echo "==> 11. Generate and apply the encrypted-column drop"
"$STASH" decrypt drop --table users --column email_encrypted --migrations-dir "$(pwd)/drizzle"
DECRYPT_DROP=$(ls -t "$(pwd)/drizzle"/*_drop_encrypted_users_email_encrypted.sql | head -1)
psql "$DATABASE_URL" -f "$DECRYPT_DROP" >/dev/null
GONE=$(psql "$DATABASE_URL" -At -c "SELECT count(*) FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'email_encrypted'")
if [ "$GONE" != "0" ]; then
  echo "FAIL: email_encrypted still exists" >&2
  exit 1
fi
echo "OK: users is plaintext again"

echo "==> Done."
