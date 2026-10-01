/**
 * Integration tests for the backfill engine against a real local Postgres.
 *
 * Skipped unless `PG_TEST_URL` is set. Suggested setup:
 *
 * ```
 * cd local && docker compose up -d
 * PG_TEST_URL=postgres://cipherstash:password@localhost:5432/cipherstash \
 *   pnpm -F @cipherstash/migrate test backfill.integration
 * ```
 *
 * These tests do NOT require CipherStash credentials — they use a stub
 * encryption client that returns deterministic marker payloads. They
 * exercise the full mechanics of the backfill loop (chunking, keyset
 * pagination, checkpointing, resume, idempotency, error handling)
 * against a real transactional Postgres, which is the part with the
 * most surface area for subtle bugs.
 */

import 'dotenv/config'
import pg from 'pg'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import { type EncryptionClientLike, runBackfill } from '../backfill.js'
import { installMigrationsSchema } from '../install.js'
import { latestByColumn, progress } from '../state.js'

const PG_URL = process.env.PG_TEST_URL

// Skip the whole file when PG_TEST_URL is not configured. We wrap describe
// so that vitest still renders a "skipped" entry rather than silently
// omitting the file.
const runIntegration = Boolean(PG_URL)

describe.skipIf(!runIntegration)('runBackfill (integration)', () => {
  let pool: pg.Pool

  beforeAll(async () => {
    pool = new pg.Pool({ connectionString: PG_URL, max: 4 })

    // Fresh slate: own schema so we can blow it away without touching EQL.
    const db = await pool.connect()
    try {
      await db.query('DROP SCHEMA IF EXISTS cipherstash CASCADE')
      await db.query('DROP SCHEMA IF EXISTS migrate_test CASCADE')
      await db.query('CREATE SCHEMA migrate_test')
      await installMigrationsSchema(db)
    } finally {
      db.release()
    }
  })

  afterAll(async () => {
    await pool.end()
  })

  afterEach(async () => {
    // Each test uses a fresh users table, but the migrations log is
    // shared so later queries see a clean slate too.
    const db = await pool.connect()
    try {
      await db.query('DROP TABLE IF EXISTS migrate_test.users')
      await db.query('TRUNCATE cipherstash.cs_migrations')
    } finally {
      db.release()
    }
  })

  /** Stub that returns `{"ct": "<plain>"}` for every input — lets us
   * verify the runner's UPDATE path without running real encryption. */
  const stubClient: EncryptionClientLike = {
    bulkEncryptModels(input) {
      return Promise.resolve({
        data: input.map((row) => ({
          __pk: row.__pk,
          email: {
            v: 2,
            i: { t: 'users', c: 'email' },
            c: `mock-ciphertext:${row.email}`,
          },
        })),
      })
    },
  }

  async function seed(n: number) {
    const db = await pool.connect()
    try {
      await db.query(`
        CREATE TABLE migrate_test.users (
          id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          email          text NOT NULL,
          email_encrypted jsonb
        )
      `)
      await db.query(
        `INSERT INTO migrate_test.users (email)
         SELECT 'user-' || g || '@example.com' FROM generate_series(1, $1) AS g`,
        [n],
      )
    } finally {
      db.release()
    }
  }

  async function countEncrypted(): Promise<number> {
    const result = await pool.query<{ n: string }>(
      'SELECT count(*)::text AS n FROM migrate_test.users WHERE email_encrypted IS NOT NULL',
    )
    return Number(result.rows[0]?.n ?? 0)
  }

  it('backfills every row and records a completion event', async () => {
    await seed(500)
    const db = await pool.connect()
    try {
      const result = await runBackfill({
        db,
        encryptionClient: stubClient,
        tableSchema: { tableName: 'users', build: () => ({}) },
        tableName: 'migrate_test.users',
        schemaColumnKey: 'email',
        plaintextColumn: 'email',
        encryptedColumn: 'email_encrypted',
        pkColumn: 'id',
        chunkSize: 100,
      })
      expect(result.completed).toBe(true)
      expect(result.rowsProcessed).toBe(500)
      expect(result.resumed).toBe(false)
    } finally {
      db.release()
    }

    expect(await countEncrypted()).toBe(500)

    const readDb = await pool.connect()
    try {
      const state = await progress(readDb, 'migrate_test.users', 'email')
      expect(state?.phase).toBe('backfilled')
      expect(state?.event).toBe('backfilled')
      expect(state?.rowsProcessed).toBe(500)
    } finally {
      readDb.release()
    }
  })

  it('is idempotent on re-run (zero additional writes)', async () => {
    await seed(200)
    const run = async () => {
      const db = await pool.connect()
      try {
        return await runBackfill({
          db,
          encryptionClient: stubClient,
          tableSchema: { tableName: 'users', build: () => ({}) },
          tableName: 'migrate_test.users',
          schemaColumnKey: 'email',
          plaintextColumn: 'email',
          encryptedColumn: 'email_encrypted',
          pkColumn: 'id',
          chunkSize: 50,
        })
      } finally {
        db.release()
      }
    }

    await run()
    expect(await countEncrypted()).toBe(200)

    // Capture a per-row hash so we can prove nothing was rewritten.
    const before = await pool.query<{ h: string }>(
      `SELECT md5(string_agg(email_encrypted::text, ',' ORDER BY id)) AS h FROM migrate_test.users`,
    )

    const secondResult = await run()
    expect(secondResult.completed).toBe(true)
    expect(secondResult.rowsProcessed).toBe(0) // starts from zero because no checkpoint is a checkpoint event

    const after = await pool.query<{ h: string }>(
      `SELECT md5(string_agg(email_encrypted::text, ',' ORDER BY id)) AS h FROM migrate_test.users`,
    )
    expect(after.rows[0]?.h).toBe(before.rows[0]?.h)
  })

  it('resumes from a checkpoint after mid-run abort', async () => {
    await seed(500)

    // First pass: abort after ~200 rows.
    const controller = new AbortController()
    let rowsSeen = 0
    const db1 = await pool.connect()
    let firstResult: Awaited<ReturnType<typeof runBackfill>>
    try {
      firstResult = await runBackfill({
        db: db1,
        encryptionClient: stubClient,
        tableSchema: { tableName: 'users', build: () => ({}) },
        tableName: 'migrate_test.users',
        schemaColumnKey: 'email',
        plaintextColumn: 'email',
        encryptedColumn: 'email_encrypted',
        pkColumn: 'id',
        chunkSize: 50,
        signal: controller.signal,
        onProgress: (p) => {
          rowsSeen = p.rowsProcessed
          if (rowsSeen >= 200) controller.abort()
        },
      })
    } finally {
      db1.release()
    }

    expect(firstResult.completed).toBe(false)
    expect(firstResult.rowsProcessed).toBeGreaterThanOrEqual(200)
    expect(firstResult.rowsProcessed).toBeLessThan(500)
    const partialCount = await countEncrypted()
    expect(partialCount).toBe(firstResult.rowsProcessed)

    // Second pass: resume from checkpoint, should finish.
    const db2 = await pool.connect()
    let secondResult: Awaited<ReturnType<typeof runBackfill>>
    try {
      secondResult = await runBackfill({
        db: db2,
        encryptionClient: stubClient,
        tableSchema: { tableName: 'users', build: () => ({}) },
        tableName: 'migrate_test.users',
        schemaColumnKey: 'email',
        plaintextColumn: 'email',
        encryptedColumn: 'email_encrypted',
        pkColumn: 'id',
        chunkSize: 50,
      })
    } finally {
      db2.release()
    }

    expect(secondResult.resumed).toBe(true)
    expect(secondResult.completed).toBe(true)
    expect(await countEncrypted()).toBe(500)
  })

  it('records an error event and rethrows when encryption fails', async () => {
    await seed(100)
    let calls = 0
    const failingClient: EncryptionClientLike = {
      bulkEncryptModels(input) {
        calls += 1
        if (calls === 2) {
          return Promise.resolve({
            failure: { message: 'ZeroKMS exploded', type: 'EncryptionError' },
          })
        }
        return Promise.resolve({
          data: input.map((row) => ({
            __pk: row.__pk,
            email: {
              v: 2,
              i: { t: 'users', c: 'email' },
              c: `mock-ciphertext:${row.email}`,
            },
          })),
        })
      },
    }

    const db = await pool.connect()
    try {
      await expect(
        runBackfill({
          db,
          encryptionClient: failingClient,
          tableSchema: { tableName: 'users', build: () => ({}) },
          tableName: 'migrate_test.users',
          schemaColumnKey: 'email',
          plaintextColumn: 'email',
          encryptedColumn: 'email_encrypted',
          pkColumn: 'id',
          chunkSize: 25,
        }),
      ).rejects.toThrow(/ZeroKMS exploded/)
    } finally {
      db.release()
    }

    const readDb = await pool.connect()
    try {
      const state = await progress(readDb, 'migrate_test.users', 'email')
      expect(state?.event).toBe('error')
      expect((state?.details as { message?: string } | null)?.message).toMatch(
        /ZeroKMS exploded/,
      )
    } finally {
      readDb.release()
    }
    // Chunk 1 succeeded and committed before chunk 2 failed.
    expect(await countEncrypted()).toBe(25)
  })

  it('handles an empty table gracefully', async () => {
    await seed(0)
    const db = await pool.connect()
    try {
      const result = await runBackfill({
        db,
        encryptionClient: stubClient,
        tableSchema: { tableName: 'users', build: () => ({}) },
        tableName: 'migrate_test.users',
        schemaColumnKey: 'email',
        plaintextColumn: 'email',
        encryptedColumn: 'email_encrypted',
        pkColumn: 'id',
        chunkSize: 100,
      })
      expect(result.completed).toBe(true)
      expect(result.rowsProcessed).toBe(0)
    } finally {
      db.release()
    }
  })

  it('skips rows already encrypted by a previous run (idempotency guard)', async () => {
    await seed(100)
    // Pre-encrypt half the rows by hand — simulates a dual-write path
    // that was already populating encrypted ciphertext before backfill ran.
    await pool.query(
      `UPDATE migrate_test.users
       SET email_encrypted = jsonb_build_object('v', 2, 'i', jsonb_build_object('t', 'users', 'c', 'email'), 'c', 'preexisting')
       WHERE id <= 50`,
    )

    const db = await pool.connect()
    try {
      const result = await runBackfill({
        db,
        encryptionClient: stubClient,
        tableSchema: { tableName: 'users', build: () => ({}) },
        tableName: 'migrate_test.users',
        schemaColumnKey: 'email',
        plaintextColumn: 'email',
        encryptedColumn: 'email_encrypted',
        pkColumn: 'id',
        chunkSize: 25,
      })
      expect(result.completed).toBe(true)
      // Only the 50 unencrypted rows should have been processed.
      expect(result.rowsProcessed).toBe(50)
    } finally {
      db.release()
    }

    // First half still has the pre-existing ciphertext.
    const preserved = await pool.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM migrate_test.users
       WHERE id <= 50 AND email_encrypted->>'c' = 'preexisting'`,
    )
    expect(Number(preserved.rows[0]?.n)).toBe(50)

    // Second half was backfilled by the stub.
    const backfilled = await pool.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM migrate_test.users
       WHERE id > 50 AND email_encrypted->>'c' LIKE 'mock-ciphertext:user-%'`,
    )
    expect(Number(backfilled.rows[0]?.n)).toBe(50)
  })

  it('writes a backfill_started event on every run with resume metadata', async () => {
    await seed(100)
    const db = await pool.connect()
    try {
      await runBackfill({
        db,
        encryptionClient: stubClient,
        tableSchema: { tableName: 'users', build: () => ({}) },
        tableName: 'migrate_test.users',
        schemaColumnKey: 'email',
        plaintextColumn: 'email',
        encryptedColumn: 'email_encrypted',
        pkColumn: 'id',
        chunkSize: 50,
      })
    } finally {
      db.release()
    }

    const events = await pool.query<{ event: string; details: unknown }>(
      `SELECT event, details FROM cipherstash.cs_migrations
       WHERE table_name = 'migrate_test.users' AND column_name = 'email'
       ORDER BY id ASC`,
    )
    const eventNames = events.rows.map((r) => r.event)
    expect(eventNames[0]).toBe('backfill_started')
    expect(eventNames).toContain('backfill_checkpoint')
    expect(eventNames.at(-1)).toBe('backfilled')
    expect((events.rows[0]?.details as { resumed?: boolean })?.resumed).toBe(
      false,
    )
  })

  it('latestByColumn returns the most recent row per column', async () => {
    await seed(50)
    const db = await pool.connect()
    try {
      await runBackfill({
        db,
        encryptionClient: stubClient,
        tableSchema: { tableName: 'users', build: () => ({}) },
        tableName: 'migrate_test.users',
        schemaColumnKey: 'email',
        plaintextColumn: 'email',
        encryptedColumn: 'email_encrypted',
        pkColumn: 'id',
        chunkSize: 25,
      })
    } finally {
      db.release()
    }

    const readDb = await pool.connect()
    try {
      const map = await latestByColumn(readDb)
      const latest = map.get('migrate_test.users.email')
      expect(latest?.phase).toBe('backfilled')
      expect(latest?.rowsProcessed).toBe(50)
    } finally {
      readDb.release()
    }
  })
})
