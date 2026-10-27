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
import { ColumnMigrationError } from '../column-migration.js'
import { runChunkedMigration } from '../engine.js'
import { installMigrationsSchema } from '../install.js'
import { appendEvent, latestByColumn, progress } from '../state.js'

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
      // The error's name, never its message: a client or database message
      // can carry row data.
      expect(state?.details).toMatchObject({ errorName: 'Error' })
      expect(JSON.stringify(state?.details)).not.toContain('ZeroKMS exploded')
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

  /** One forward run over `migrate_test.users` with the stub client. */
  async function forward(
    overrides: Partial<Parameters<typeof runBackfill>[0]> = {},
  ) {
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
        ...overrides,
      })
    } finally {
      db.release()
    }
  }

  async function staleCount(): Promise<number> {
    const result = await pool.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM migrate_test.users WHERE email_encrypted->>'c' = 'stale'`,
    )
    return Number(result.rows[0]?.n ?? 0)
  }

  it('a resumed run counts its total once, so progress ends at 100%', async () => {
    await seed(300)
    const controller = new AbortController()
    await forward({
      signal: controller.signal,
      onProgress: (p) => {
        if (p.rowsProcessed >= 100) controller.abort()
      },
    })
    const resumed = await forward()
    expect(resumed.resumed).toBe(true)
    expect(resumed.rowsTotal).toBe(300)
    expect(resumed.rowsProcessed).toBe(300)
  })

  it('resumes after a failed run from its last committed cursor', async () => {
    await seed(150)
    let calls = 0
    const failSecond: EncryptionClientLike = {
      bulkEncryptModels(input, table) {
        calls += 1
        return calls === 2
          ? Promise.resolve({ failure: { message: 'boom' } })
          : stubClient.bulkEncryptModels(input, table)
      },
    }
    await expect(forward({ encryptionClient: failSecond })).rejects.toThrow()
    const fixed = await forward()
    expect(fixed.resumed).toBe(true)
    expect(fixed.rowsProcessed).toBe(150)
    expect(await countEncrypted()).toBe(150)
  })

  it('a plain run finishes an interrupted --force pass as a forced pass', async () => {
    await seed(300)
    await pool.query(
      `UPDATE migrate_test.users SET email_encrypted = '{"v":2,"c":"stale"}'::jsonb`,
    )
    const controller = new AbortController()
    await forward({
      force: true,
      signal: controller.signal,
      onProgress: (p) => {
        if (p.rowsProcessed >= 100) controller.abort()
      },
    })

    // Unforced, this run would find nothing pending and leave rows 101-300
    // stale. The open obligation makes it forced, and it resumes the pass.
    const finished = await forward()
    expect(finished).toMatchObject({
      resumed: true,
      completed: true,
      force: true,
      forcedBy: 'forced-pass',
    })
    expect(await staleCount()).toBe(0)

    // The completed forced pass met the obligation.
    expect(await forward()).toMatchObject({ force: false, forcedBy: null })
  })

  it('records the pass mode on every event', async () => {
    await seed(120)
    await forward({ force: true })
    const { rows } = await pool.query<{ event: string; force: unknown }>(
      `SELECT event, details->'force' AS force FROM cipherstash.cs_migrations ORDER BY id`,
    )
    expect(rows.map((r) => r.event)).toEqual([
      'backfill_started',
      'backfill_checkpoint',
      'backfill_checkpoint',
      'backfill_checkpoint',
      'backfilled',
    ])
    expect(rows.every((r) => r.force === true)).toBe(true)
  })

  it('refuses to start while a reverse column migration of the pair is open', async () => {
    await seed(10)
    const db = await pool.connect()
    try {
      await appendEvent(db, {
        tableName: 'migrate_test.users',
        columnName: 'email_encrypted',
        event: 'decrypt_started',
        phase: 'decrypting',
        details: { plaintextColumn: 'email' },
      })
    } finally {
      db.release()
    }
    await expect(forward()).rejects.toBeInstanceOf(ColumnMigrationError)
    expect(await countEncrypted()).toBe(0)
  })
  it('the engine records the twin itself, so a paused run is not resumed into another', async () => {
    await seed(4)
    const firstAfter: Array<string | null> = []
    const run = async (twinColumn: string, controller?: AbortController) => {
      const db = await pool.connect()
      let fetched = false
      try {
        return await runChunkedMigration<{ pk: string }>({
          db,
          tableName: 'migrate_test.users',
          stateColumn: 'email',
          twinColumn,
          direction: 'forward',
          chunkSize: 2,
          signal: controller?.signal,
          // Pause once the first chunk has committed.
          onProgress: () => controller?.abort(),
          countPending: async (after) =>
            Number(
              (
                await db.query<{ n: string }>(
                  'SELECT count(*)::text AS n FROM migrate_test.users WHERE id > $1',
                  [after ?? 0],
                )
              ).rows[0]?.n,
            ),
          fetchPage: async (after, limit) => {
            if (!fetched) firstAfter.push(after)
            fetched = true
            const { rows } = await db.query<{ pk: string }>(
              'SELECT id::text AS pk FROM migrate_test.users WHERE id > $1 ORDER BY id LIMIT $2',
              [after ?? 0, limit],
            )
            return { rows, lastPk: rows.at(-1)?.pk ?? null }
          },
          prepareChunk: async () => ({ write: async () => {} }),
        })
      } finally {
        db.release()
      }
    }

    // Paused after its first chunk, with no baseDetails naming the twin.
    const paused = await run('email_encrypted', new AbortController())
    expect(paused.completed).toBe(false)
    const { rows: recorded } = await pool.query<{
      cursor_value: string | null
      details: unknown
    }>(
      `SELECT cursor_value, details FROM cipherstash.cs_migrations
        WHERE column_name = 'email' ORDER BY id DESC LIMIT 1`,
    )
    expect(recorded[0]?.cursor_value).toBe('2')
    expect(recorded[0]?.details).toMatchObject({
      encryptedColumn: 'email_encrypted',
    })

    // Another twin is refused before it can resume the paused cursor…
    await expect(run('email_ciphertext')).rejects.toMatchObject({
      code: 'twin-mismatch',
    })
    // …while the recorded one resumes after it.
    const resumed = await run('email_encrypted')
    expect(resumed.completed).toBe(true)
    expect(firstAfter).toEqual([null, '2'])
  })

  it.each([
    ['a thrown value that is not an Error', () => 'row 7: alice@example.com'],
    [
      'an Error whose name is not an identifier',
      () =>
        Object.assign(new Error('boom'), { name: 'alice@example.com failed' }),
    ],
  ])('records %s as errorName "Error"', async (_label, thrown) => {
    await seed(2)
    const db = await pool.connect()
    try {
      await expect(
        runChunkedMigration<{ pk: string }>({
          db,
          tableName: 'migrate_test.users',
          stateColumn: 'email',
          twinColumn: 'email_encrypted',
          direction: 'forward',
          chunkSize: 2,
          countPending: async () => 2,
          fetchPage: async () => ({ rows: [{ pk: '1' }], lastPk: '1' }),
          prepareChunk: async () => {
            throw thrown()
          },
        }),
      ).rejects.toBeDefined()
    } finally {
      db.release()
    }

    const { rows } = await pool.query<{ details: Record<string, unknown> }>(
      `SELECT details FROM cipherstash.cs_migrations
        WHERE column_name = 'email' AND event = 'error'`,
    )
    expect(rows).toHaveLength(1)
    expect(rows[0]?.details.errorName).toBe('Error')
    expect(JSON.stringify(rows[0]?.details)).not.toContain('alice@example.com')
  })

  it("a caller's checkpoint and error details cannot overwrite the fields a resume reads", async () => {
    await seed(4)
    const spoof = { encryptedColumn: 'spoofed', force: true, rowsSkipped: 99 }
    const db = await pool.connect()
    let chunk = 0
    try {
      await expect(
        runChunkedMigration<{ pk: string }>({
          db,
          tableName: 'migrate_test.users',
          stateColumn: 'email',
          twinColumn: 'email_encrypted',
          direction: 'forward',
          chunkSize: 2,
          errorDetails: () => spoof,
          countPending: async () => 4,
          fetchPage: async (after, limit) => {
            const { rows } = await db.query<{ pk: string }>(
              'SELECT id::text AS pk FROM migrate_test.users WHERE id > $1 ORDER BY id LIMIT $2',
              [after ?? 0, limit],
            )
            return { rows, lastPk: rows.at(-1)?.pk ?? null }
          },
          prepareChunk: async () => {
            chunk += 1
            if (chunk === 2) throw new Error('second chunk fails')
            return { checkpointDetails: spoof, write: async () => {} }
          },
        }),
      ).rejects.toThrow('second chunk fails')
    } finally {
      db.release()
    }

    const { rows } = await pool.query<{
      event: string
      details: Record<string, unknown>
    }>(
      `SELECT event, details FROM cipherstash.cs_migrations
        WHERE column_name = 'email' AND event IN ('backfill_checkpoint', 'error')
        ORDER BY id`,
    )
    expect(rows.map((r) => r.event)).toEqual(['backfill_checkpoint', 'error'])
    for (const { details } of rows) {
      expect(details).toMatchObject({
        encryptedColumn: 'email_encrypted',
        force: false,
        rowsSkipped: 0,
      })
    }
  })
})
