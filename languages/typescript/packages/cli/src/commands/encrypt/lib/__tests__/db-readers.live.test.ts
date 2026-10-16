/**
 * Live-Postgres coverage for `detectPkColumn`, shared by `encrypt backfill`
 * and `decrypt backfill`.
 *
 * An unqualified table name must resolve the way Postgres resolves it — the
 * first match on `search_path` — not match `relname` in every schema. On
 * Supabase `public.users` and `auth.users` both have PK `id`; a catalog query
 * that ignores `search_path` sees two PK rows and reports a composite key.
 *
 * Gated on STASH_TEST_DATABASE_URL so the default `pnpm test` stays green
 * without a database.
 */

import type pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { detectPkColumn } from '../db-readers.js'

const DATABASE_URL = process.env.STASH_TEST_DATABASE_URL
const describeLive = DATABASE_URL ? describe : describe.skip

const SCHEMA_A = 'stash_pk_live_a'
const SCHEMA_B = 'stash_pk_live_b'

describeLive('detectPkColumn — live Postgres', () => {
  let client: pg.Client

  beforeAll(async () => {
    const { default: pgMod } = await import('pg')
    client = new pgMod.Client({ connectionString: DATABASE_URL })
    await client.connect()
    await client.query(`
      DROP SCHEMA IF EXISTS ${SCHEMA_A} CASCADE;
      DROP SCHEMA IF EXISTS ${SCHEMA_B} CASCADE;
      CREATE SCHEMA ${SCHEMA_A};
      CREATE SCHEMA ${SCHEMA_B};
      CREATE TABLE ${SCHEMA_A}.users (id bigint PRIMARY KEY, email text);
      CREATE TABLE ${SCHEMA_B}.users (uid uuid PRIMARY KEY, email text);
      CREATE TABLE ${SCHEMA_A}."User" (pk_mixed bigint PRIMARY KEY);
    `)
  })

  afterAll(async () => {
    await client.query(`
      DROP SCHEMA IF EXISTS ${SCHEMA_A} CASCADE;
      DROP SCHEMA IF EXISTS ${SCHEMA_B} CASCADE;
    `)
    await client.end().catch(() => undefined)
  })

  it('resolves an unqualified name through search_path, ignoring a same-named table in another schema', async () => {
    // Only SCHEMA_A is on the path, as `public` is on Supabase while
    // `auth.users` is not.
    await client.query(`SET search_path TO ${SCHEMA_A}`)
    await expect(detectPkColumn(client, 'users')).resolves.toBe('id')
  })

  it('still resolves a schema-qualified name to that schema', async () => {
    await client.query(`SET search_path TO ${SCHEMA_A}`)
    await expect(detectPkColumn(client, `${SCHEMA_B}.users`)).resolves.toBe(
      'uid',
    )
  })

  it('keeps the name case-exact (a Prisma-style "User"), as REGCLASS_SQL does', async () => {
    // A bare to_regclass($1) would case-fold 'User' to 'user' and miss it.
    await client.query(`SET search_path TO ${SCHEMA_A}`)
    await expect(detectPkColumn(client, 'User')).resolves.toBe('pk_mixed')
  })
})
