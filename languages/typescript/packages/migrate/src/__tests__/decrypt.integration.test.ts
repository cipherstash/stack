/**
 * Integration tests for the REVERSE (decrypt) backfill against a real local
 * Postgres — the twin of `backfill.integration.test.ts`, on the same engine.
 *
 * Skipped unless `PG_TEST_URL` is set:
 *
 * ```
 * docker compose -f local/docker-compose.postgres.yml up -d --wait
 * PG_TEST_URL=postgres://cipherstash:password@localhost:55432/cipherstash \
 *   pnpm -F @cipherstash/migrate test decrypt.integration
 * ```
 *
 * No CipherStash credentials required: a stub `bulkDecrypt` decodes
 * deterministic v3-shaped markers, and reports a per-row failure for any
 * marker flagged `locked` — the shape a value bound to an end-user lock
 * context takes when decrypted with workspace credentials. What is under test
 * is everything around the crypto: keyset paging, the per-row skip path, the
 * checkpoint/resume contract, the typed write, and the guards.
 */

import 'dotenv/config'
import pg from 'pg'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import { ColumnMigration, ColumnMigrationError } from '../column-migration.js'
import { columnHasValues, countUndecrypted } from '../cursor.js'
import {
  type BulkDecryptItem,
  type DecryptionClientLike,
  MAX_DECRYPT_CHUNK_SIZE,
  PlaintextWriteError,
  runDecryptBackfill,
  UndecryptableBatchError,
} from '../decrypt.js'
import { installMigrationsSchema } from '../install.js'
import { appendEvent, latestByColumn, progress } from '../state.js'
import {
  columnSqlType,
  countEqlColumnsInDatabase,
  listColumnIndexes,
} from '../version.js'

const PG_URL = process.env.PG_TEST_URL
const runIntegration = Boolean(PG_URL)

const TABLE = 'migrate_decrypt_test.users'

/** A v3-shaped marker the stub "decrypts" back to `plaintext`. */
function envelope(plaintext: unknown, locked = false) {
  return {
    v: 3,
    i: { t: 'users', c: 'email_encrypted' },
    c: JSON.stringify({ plaintext }),
    ...(locked ? { locked: true } : {}),
  }
}

/** Decodes {@link envelope}; a `locked` marker fails that row only. */
const stubClient: DecryptionClientLike & { calls: number[] } = {
  calls: [],
  bulkDecrypt(payloads) {
    this.calls.push(payloads.length)
    const data: BulkDecryptItem[] = payloads.map((payload) => {
      const value = payload.data as { c: string; locked?: boolean } | null
      if (value?.locked) {
        return { id: payload.id, error: 'lock context required' }
      }
      return {
        id: payload.id,
        data: (JSON.parse(value?.c ?? 'null') as { plaintext: unknown })
          .plaintext,
      }
    })
    return Promise.resolve({ data })
  },
}

describe.skipIf(!runIntegration)('runDecryptBackfill (integration)', () => {
  let pool: pg.Pool

  beforeAll(async () => {
    pool = new pg.Pool({ connectionString: PG_URL, max: 4 })
    const db = await pool.connect()
    try {
      await db.query('DROP SCHEMA IF EXISTS cipherstash CASCADE')
      await db.query('DROP SCHEMA IF EXISTS migrate_decrypt_test CASCADE')
      await db.query('CREATE SCHEMA migrate_decrypt_test')
      await installMigrationsSchema(db)
    } finally {
      db.release()
    }
  })

  afterAll(async () => {
    await pool.end()
  })

  afterEach(async () => {
    stubClient.calls = []
    await pool.query(`DROP TABLE IF EXISTS ${TABLE}`)
    await pool.query('TRUNCATE cipherstash.cs_migrations')
  })

  /**
   * `n` rows of encrypted email; every `lockedEvery`-th row is locked. The
   * plaintext twin starts empty, as `stash decrypt plan` leaves it.
   */
  async function seed(n: number, lockedEvery = 0, plaintextType = 'text') {
    await pool.query(`
      CREATE TABLE ${TABLE} (
        id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        email_encrypted jsonb,
        email           ${plaintextType}
      )
    `)
    const values: unknown[] = []
    const rows: string[] = []
    for (let i = 1; i <= n; i++) {
      values.push(
        JSON.stringify(
          envelope(
            `user-${i}@example.com`,
            lockedEvery > 0 && i % lockedEvery === 0,
          ),
        ),
      )
      rows.push(`($${values.length}::jsonb)`)
    }
    await pool.query(
      `INSERT INTO ${TABLE} (email_encrypted) VALUES ${rows.join(', ')}`,
      values,
    )
  }

  async function run(
    overrides: Partial<Parameters<typeof runDecryptBackfill>[0]> = {},
  ) {
    const db = await pool.connect()
    try {
      return await runDecryptBackfill({
        db,
        decryptionClient: stubClient,
        tableName: TABLE,
        encryptedColumn: 'email_encrypted',
        plaintextColumn: 'email',
        plaintextSqlType: 'text',
        pkColumn: 'id',
        chunkSize: 100,
        ...overrides,
      })
    } finally {
      db.release()
    }
  }

  async function plaintextCount(): Promise<number> {
    const { rows } = await pool.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM ${TABLE} WHERE email IS NOT NULL`,
    )
    return Number(rows[0]?.n ?? 0)
  }

  it('decrypts every row, one bulkDecrypt per chunk, keyed by the encrypted column', async () => {
    await seed(250)

    const result = await run()

    expect(result.completed).toBe(true)
    expect(result.rowsProcessed).toBe(250)
    expect(result.rowsDecrypted).toBe(250)
    expect(result.rowsSkipped).toBe(0)
    // 250 rows at chunk 100 → exactly three ZeroKMS round trips.
    expect(stubClient.calls).toEqual([100, 100, 50])
    expect(await plaintextCount()).toBe(250)
    const { rows } = await pool.query<{ email: string }>(
      `SELECT email FROM ${TABLE} WHERE id = 7`,
    )
    expect(rows[0]?.email).toBe('user-7@example.com')

    const db = await pool.connect()
    try {
      // Recorded under the ENCRYPTED column, never the plaintext name — the
      // forward history lives there.
      expect(await progress(db, TABLE, 'email')).toBeNull()
      const state = await progress(db, TABLE, 'email_encrypted')
      expect(state?.event).toBe('decrypted')
      expect(state?.phase).toBe('decrypted')
      expect(state?.details).toMatchObject({
        plaintextColumn: 'email',
        rowsSkipped: 0,
      })
    } finally {
      db.release()
    }
  })

  it('skips and counts values it cannot decrypt (lock contexts), leaving them NULL', async () => {
    await seed(200, 10)

    const result = await run()

    expect(result.completed).toBe(true)
    expect(result.rowsProcessed).toBe(200)
    expect(result.rowsSkipped).toBe(20)
    expect(result.rowsDecrypted).toBe(180)
    expect(result.skippedByCode).toEqual({ UNKNOWN: 20 })
    expect(await plaintextCount()).toBe(180)

    const db = await pool.connect()
    try {
      // The coverage gate `stash decrypt drop` relies on still sees them.
      expect(
        await countUndecrypted(db, TABLE, 'email_encrypted', 'email'),
      ).toBe(20)
      const state = await progress(db, TABLE, 'email_encrypted')
      expect(state?.details).toMatchObject({ rowsSkipped: 20 })
    } finally {
      db.release()
    }
  })

  it('resumes from a checkpoint after an abort, carrying the skip count forward', async () => {
    await seed(500, 50)

    const controller = new AbortController()
    const first = await run({
      signal: controller.signal,
      onProgress: (p) => {
        if (p.rowsProcessed >= 200) controller.abort()
      },
    })
    expect(first.completed).toBe(false)
    expect(first.rowsProcessed).toBe(200)
    expect(first.rowsSkipped).toBe(4)

    const second = await run()
    expect(second.resumed).toBe(true)
    expect(second.completed).toBe(true)
    expect(second.rowsProcessed).toBe(500)
    expect(second.rowsSkipped).toBe(10)
    expect(await plaintextCount()).toBe(490)
  })

  it('a resumed run counts its total once, so progress ends at 100%', async () => {
    await seed(500, 50)

    const controller = new AbortController()
    await run({
      signal: controller.signal,
      onProgress: (p) => {
        if (p.rowsProcessed >= 200) controller.abort()
      },
    })

    // The 4 rows skipped before the cursor are already in rowsProcessed and
    // still match the pending predicate; counting them again made the total
    // 504 and the run end below 100%.
    const seen: Array<{ processed: number; total: number }> = []
    const second = await run({
      onProgress: (p) =>
        seen.push({ processed: p.rowsProcessed, total: p.rowsTotal }),
    })
    expect(second.resumed).toBe(true)
    expect(second.rowsTotal).toBe(500)
    expect(seen.at(-1)).toEqual({ processed: 500, total: 500 })
  })

  it('resumes after a failed run from its last committed cursor, not the first primary key', async () => {
    await seed(300)

    const controller = new AbortController()
    await run({
      signal: controller.signal,
      onProgress: (p) => {
        if (p.rowsProcessed >= 200) controller.abort()
      },
    })

    // Credentials for the wrong keyset: the first chunk of this run decrypts
    // nothing, so it stops before writing and records an `error` event…
    const wrongKeyset: DecryptionClientLike = {
      bulkDecrypt: (payloads) =>
        Promise.resolve({
          data: payloads.map((payload) => ({
            id: payload.id,
            error: 'no key',
          })),
        }),
    }
    await expect(run({ decryptionClient: wrongKeyset })).rejects.toBeInstanceOf(
      UndecryptableBatchError,
    )
    const db = await pool.connect()
    try {
      const state = await progress(db, TABLE, 'email_encrypted')
      expect(state?.event).toBe('error')
      expect(state?.cursorValue).toBe('200')
      expect(state?.rowsProcessed).toBe(200)
    } finally {
      db.release()
    }

    // …which carries the committed cursor, so the fixed re-run picks up at
    // row 201 instead of re-reading the first 200.
    stubClient.calls = []
    const fixed = await run()
    expect(fixed.resumed).toBe(true)
    expect(fixed.completed).toBe(true)
    expect(fixed.rowsProcessed).toBe(300)
    expect(stubClient.calls).toEqual([100])
    expect(await plaintextCount()).toBe(300)
  })

  it('a plain run finishes an interrupted --force pass as a forced pass', async () => {
    await seed(300)
    // Stale plaintext everywhere: the case --force exists for.
    await pool.query(`UPDATE ${TABLE} SET email = 'stale@example.com'`)

    const controller = new AbortController()
    await run({
      force: true,
      signal: controller.signal,
      onProgress: (p) => {
        if (p.rowsProcessed >= 100) controller.abort()
      },
    })

    // Unforced, this re-run would resume at row 101 and keep rows 101-300
    // stale. The open obligation makes it forced, so it resumes the pass.
    const finished = await run()
    expect(finished.resumed).toBe(true)
    const { rows } = await pool.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM ${TABLE} WHERE email = 'stale@example.com'`,
    )
    expect(rows[0]?.n).toBe('0')
  })

  /** The reverse column migration of `email_encrypted`, freshly loaded. */
  async function migration(): Promise<ColumnMigration> {
    const db = await pool.connect()
    try {
      return await ColumnMigration.load(db, {
        table: TABLE,
        column: 'email_encrypted',
        direction: 'reverse',
        twin: 'email',
        manifest: null,
      })
    } finally {
      db.release()
    }
  }

  /** Confirm dual-writes on a connection held for the call. */
  async function confirm(waiver?: 'plaintext-current') {
    const db = await pool.connect()
    try {
      const loaded = await ColumnMigration.load(db, {
        table: TABLE,
        column: 'email_encrypted',
        direction: 'reverse',
        twin: 'email',
        manifest: null,
      })
      return await loaded.confirmDualWrites({ waiver })
    } finally {
      db.release()
    }
  }

  async function staleCount(): Promise<string | undefined> {
    const { rows } = await pool.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM ${TABLE} WHERE email = 'stale@example.com'`,
    )
    return rows[0]?.n
  }

  it('dual-writes confirmed over a twin that already holds values: a plain run overwrites it', async () => {
    await seed(300)
    await pool.query(`UPDATE ${TABLE} SET email = 'stale@example.com'`)
    const confirmed = await confirm()
    expect(confirmed.obligations).toMatchObject([
      { reason: 'existing-values', waivable: true },
    ])

    const result = await run()
    expect(result).toMatchObject({ force: true, forcedBy: 'existing-values' })
    expect(await staleCount()).toBe('0')
    expect((await migration()).obligations).toEqual([])
  })

  it('a pass with no column migration on record treats a twin with values as owed', async () => {
    // An embedded worker that never confirmed dual-writes.
    await seed(50)
    await pool.query(`UPDATE ${TABLE} SET email = 'stale@example.com'`)
    expect(await run()).toMatchObject({
      force: true,
      forcedBy: 'existing-values',
    })
    expect(await staleCount()).toBe('0')
  })

  it('a waiver recorded at confirmation keeps the existing values', async () => {
    await seed(50)
    await pool.query(
      `UPDATE ${TABLE} SET email = 'current@example.com' WHERE id <= 10`,
    )
    const confirmed = await confirm('plaintext-current')
    expect(confirmed.obligations).toEqual([])

    expect(await run()).toMatchObject({ force: false, forcedBy: null })
    const { rows } = await pool.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM ${TABLE} WHERE email = 'current@example.com'`,
    )
    expect(rows[0]?.n).toBe('10')
  })

  it('a waiver given later still closes an up-front obligation no pass has started on', async () => {
    await seed(20)
    await pool.query(`UPDATE ${TABLE} SET email = 'stale@example.com'`)
    expect((await confirm()).obligations).toHaveLength(1)
    expect((await confirm('plaintext-current')).obligations).toEqual([])
  })

  it('refuses a waiver once a forced pass has started', async () => {
    await seed(20)
    await pool.query(`UPDATE ${TABLE} SET email = 'stale@example.com'`)
    await confirm()
    const controller = new AbortController()
    controller.abort()
    await run({ signal: controller.signal })

    const error = await confirm('plaintext-current').catch((e: unknown) => e)
    expect(error).toBeInstanceOf(ColumnMigrationError)
    expect((error as ColumnMigrationError).code).toBe('waiver-refused')
    expect((await migration()).obligations).toMatchObject([
      { reason: 'forced-pass', waivable: false },
    ])
  })

  it('refuses a reverse column migration while the forward one of the twin is open', async () => {
    await seed(10)
    const db = await pool.connect()
    try {
      await appendEvent(db, {
        tableName: TABLE,
        columnName: 'email',
        event: 'backfilled',
        phase: 'backfilled',
      })
    } finally {
      db.release()
    }

    expect((await migration()).blockedBy).toEqual({
      direction: 'forward',
      column: 'email',
      phase: 'backfilled',
    })
    await expect(confirm()).rejects.toMatchObject({ code: 'counterpart-open' })
    await expect(run()).rejects.toMatchObject({ code: 'counterpart-open' })
    expect(await plaintextCount()).toBe(0)
  })

  it('encrypting a column again after a full round trip starts a new forward column migration', async () => {
    await seed(10)
    const db = await pool.connect()
    try {
      // email encrypted into email_encrypted and dropped, then decrypted back
      // into email and email_encrypted's drop generated.
      const forwardTwin = { encryptedColumn: 'email_encrypted' }
      for (const [event, phase] of [
        ['dual_writing', 'dual-writing'],
        ['backfilled', 'backfilled'],
        ['dropped', 'dropped'],
      ] as const) {
        await appendEvent(db, {
          tableName: TABLE,
          columnName: 'email',
          event,
          phase,
          details: forwardTwin,
        })
      }
      await confirm()
      await run()
      const reverse = await ColumnMigration.load(db, {
        table: TABLE,
        column: 'email_encrypted',
        direction: 'reverse',
        manifest: null,
      })
      await reverse.recordDropGenerated({ migrationFile: 'x.sql' })

      const forward = await ColumnMigration.load(db, {
        table: TABLE,
        column: 'email',
        direction: 'forward',
        twin: 'email_encrypted_v2',
        manifest: null,
      })
      expect(forward.phase).toBeNull()
      const confirmed = await forward.confirmDualWrites()
      expect(confirmed.phase).toBe('dual-writing')
      expect(confirmed.latest?.event).toBe('dual_writing')
      expect(confirmed.twin.column).toBe('email_encrypted_v2')
    } finally {
      db.release()
    }
  })

  it('refuses to close a column migration that is not open, recording nothing', async () => {
    await seed(10)
    const db = await pool.connect()
    try {
      const none = await ColumnMigration.load(db, {
        table: TABLE,
        column: 'email',
        direction: 'forward',
        twin: 'email_encrypted',
        manifest: null,
      })
      await expect(none.recordSourceRemoved()).rejects.toMatchObject({
        code: 'wrong-phase',
      })

      // Closed once, it cannot be closed again.
      await appendEvent(db, {
        tableName: TABLE,
        columnName: 'email',
        event: 'dual_writing',
        phase: 'dual-writing',
        details: { encryptedColumn: 'email_encrypted' },
      })
      const open = await ColumnMigration.load(db, {
        table: TABLE,
        column: 'email',
        direction: 'forward',
        manifest: null,
      })
      const closed = await open.recordSourceRemoved()
      await expect(closed.recordSourceRemoved()).rejects.toMatchObject({
        code: 'wrong-phase',
      })
      const { rows } = await db.query<{ event: string }>(
        'SELECT event FROM cipherstash.cs_migrations WHERE column_name = $1 ORDER BY id',
        ['email'],
      )
      expect(rows.map((r) => r.event)).toEqual(['dual_writing', 'dropped'])
    } finally {
      db.release()
    }
  })

  it('a forward migration closed as observed absent is superseded by the reverse one too', async () => {
    await seed(10)
    const db = await pool.connect()
    try {
      // email's forward migration was open when its drop happened outside
      // stash; `decrypt plan` records that before the reverse one starts.
      await appendEvent(db, {
        tableName: TABLE,
        columnName: 'email',
        event: 'dual_writing',
        phase: 'dual-writing',
        details: { encryptedColumn: 'email_encrypted' },
      })
      const open = await ColumnMigration.load(db, {
        table: TABLE,
        column: 'email',
        direction: 'forward',
        manifest: null,
      })
      const closed = await open.recordSourceRemoved()
      expect(closed.latest?.details).toMatchObject({
        encryptedColumn: 'email_encrypted',
        observedAbsent: true,
      })

      await confirm()
      await run()
      const reverse = await ColumnMigration.load(db, {
        table: TABLE,
        column: 'email_encrypted',
        direction: 'reverse',
        manifest: null,
      })
      await reverse.recordDropGenerated({ migrationFile: 'x.sql' })

      const again = await ColumnMigration.load(db, {
        table: TABLE,
        column: 'email',
        direction: 'forward',
        twin: 'email_encrypted_v2',
        manifest: null,
      })
      expect(again.phase).toBeNull()
    } finally {
      db.release()
    }
  })

  it('refuses a run into a different plaintext column than the one recorded', async () => {
    await seed(10)
    await confirm()
    await pool.query(`ALTER TABLE ${TABLE} ADD COLUMN other text`)
    await expect(run({ plaintextColumn: 'other' })).rejects.toMatchObject({
      code: 'twin-mismatch',
    })
  })

  it('generates the drop only once the backfill completed', async () => {
    await seed(10)
    await confirm()
    const db = await pool.connect()
    try {
      const before = await ColumnMigration.load(db, {
        table: TABLE,
        column: 'email_encrypted',
        direction: 'reverse',
        manifest: null,
      })
      await expect(before.recordDropGenerated()).rejects.toMatchObject({
        code: 'wrong-phase',
      })
    } finally {
      db.release()
    }
    await run()
    const db2 = await pool.connect()
    try {
      const done = await ColumnMigration.load(db2, {
        table: TABLE,
        column: 'email_encrypted',
        direction: 'reverse',
        manifest: null,
      })
      const dropped = await done.recordDropGenerated({ migrationFile: 'x.sql' })
      expect(dropped.phase).toBe('encrypted-dropped')
      expect(dropped.open).toBe(false)
      expect(dropped.twin).toEqual({ column: 'email', via: 'recorded' })
    } finally {
      db2.release()
    }
  })

  it('refuses to generate the drop while a forced pass is owed', async () => {
    await seed(10)
    const db = await pool.connect()
    try {
      // A forced pass started, then an unforced one completed: still owed.
      for (const [event, phase, force] of [
        ['decrypt_dual_writing', 'decrypt-dual-writing', undefined],
        ['decrypt_started', 'decrypting', true],
        ['decrypted', 'decrypted', false],
      ] as const) {
        await appendEvent(db, {
          tableName: TABLE,
          columnName: 'email_encrypted',
          event,
          phase,
          details: {
            plaintextColumn: 'email',
            ...(force === undefined ? {} : { force }),
          },
        })
      }
      const owing = await ColumnMigration.load(db, {
        table: TABLE,
        column: 'email_encrypted',
        direction: 'reverse',
        manifest: null,
      })
      await expect(owing.recordDropGenerated()).rejects.toMatchObject({
        code: 'obligation-open',
      })
      const after = await ColumnMigration.load(db, {
        table: TABLE,
        column: 'email_encrypted',
        direction: 'reverse',
        manifest: null,
      })
      expect(after.phase).toBe('decrypted')
    } finally {
      db.release()
    }
  })

  it('refuses a waiver on a forward column migration, recording nothing', async () => {
    await seed(10)
    const db = await pool.connect()
    try {
      const forward = await ColumnMigration.load(db, {
        table: TABLE,
        column: 'email',
        direction: 'forward',
        twin: 'email_encrypted',
        manifest: null,
      })
      await expect(
        forward.confirmDualWrites({ waiver: 'plaintext-current' }),
      ).rejects.toMatchObject({ code: 'waiver-refused' })
      const { rows } = await db.query(
        'SELECT 1 FROM cipherstash.cs_migrations WHERE column_name = $1',
        ['email'],
      )
      expect(rows).toEqual([])
    } finally {
      db.release()
    }
  })

  it('a completed forced pass meets the obligation: later plain runs are unforced again', async () => {
    await seed(300)
    await pool.query(`UPDATE ${TABLE} SET email = 'stale@example.com'`)
    expect((await run({ force: true })).completed).toBe(true)

    // The app writes a newer value to the plaintext column alone. A forced
    // run would put the older ciphertext's value back over it.
    await pool.query(
      `UPDATE ${TABLE} SET email = 'newer@example.com' WHERE id = 1`,
    )
    await run()
    const { rows } = await pool.query<{ email: string }>(
      `SELECT email FROM ${TABLE} WHERE id = 1`,
    )
    expect(rows[0]?.email).toBe('newer@example.com')
  })

  // A forced pass that skips a row must not leave its stale twin value in
  // place: the drop's coverage check (ciphertext set, plaintext NULL) would
  // not see the row, and the completed forced pass closes the obligation, so
  // `decrypt drop` would destroy the only current copy.
  it('a forced pass clears the stale twin of every row it skips, so the drop check still counts them', async () => {
    await seed(10, 5)
    // Row 3's ciphertext decrypts to an empty value (NULL_PLAINTEXT).
    await pool.query(
      `UPDATE ${TABLE} SET email_encrypted = $1::jsonb WHERE id = 3`,
      [JSON.stringify(envelope(null))],
    )
    await pool.query(`UPDATE ${TABLE} SET email = 'stale@example.com'`)

    const result = await run({ force: true })
    expect(result.completed).toBe(true)
    expect(result.rowsSkipped).toBe(3)

    const { rows } = await pool.query<{ id: string; email: string | null }>(
      `SELECT t.id::text AS id, t.email FROM ${TABLE} AS t WHERE t.id IN (3, 5, 10) ORDER BY t.id`,
    )
    expect(rows).toEqual([
      { id: '3', email: null },
      { id: '5', email: null },
      { id: '10', email: null },
    ])
    const db = await pool.connect()
    try {
      // The predicate `stash decrypt drop` refuses on.
      expect(
        await countUndecrypted(db, TABLE, 'email_encrypted', 'email'),
      ).toBe(3)
    } finally {
      db.release()
    }
  })

  it('a plain run after a forced pass failed before its first commit still overwrites every row', async () => {
    await seed(300)
    await pool.query(`UPDATE ${TABLE} SET email = 'stale@example.com'`)

    // The forced pass fails on its first chunk, so no checkpoint and no
    // cursor exist: nothing a resume could key on.
    const wrongKeyset: DecryptionClientLike = {
      bulkDecrypt: (payloads) =>
        Promise.resolve({
          data: payloads.map((payload) => ({
            id: payload.id,
            error: 'no key',
          })),
        }),
    }
    await expect(
      run({ force: true, decryptionClient: wrongKeyset }),
    ).rejects.toBeInstanceOf(UndecryptableBatchError)

    // The forced pass opened an obligation; a plain run still has to meet it.
    const finished = await run()
    expect(finished.completed).toBe(true)
    const { rows } = await pool.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM ${TABLE} WHERE email = 'stale@example.com'`,
    )
    expect(rows[0]?.n).toBe('0')
  })

  it('a --force run does not resume an unforced pass: it starts from the first row', async () => {
    await seed(300)
    await pool.query(
      `UPDATE ${TABLE} SET email = 'stale@example.com' WHERE id <= 50`,
    )
    // Kept, so the first pass is unforced.
    await confirm('plaintext-current')

    const controller = new AbortController()
    await run({
      signal: controller.signal,
      onProgress: (p) => {
        if (p.rowsProcessed >= 100) controller.abort()
      },
    })

    const forced = await run({ force: true })
    expect(forced.resumed).toBe(false)
    const { rows } = await pool.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM ${TABLE} WHERE email = 'stale@example.com'`,
    )
    expect(rows[0]?.n).toBe('0')
  })

  it('never puts a decrypted value in a write error, its message or the error event', async () => {
    await pool.query(`
      CREATE TABLE ${TABLE} (
        id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        email_encrypted jsonb,
        email integer
      )
    `)
    await pool.query(
      `INSERT INTO ${TABLE} (email_encrypted) VALUES ($1::jsonb)`,
      [JSON.stringify(envelope('secret-not-a-number'))],
    )

    const error = await run({ plaintextSqlType: 'integer' }).catch(
      (e: unknown) => e,
    )

    // Postgres's own text for this is
    //   invalid input syntax for type integer: "secret-not-a-number"
    expect(error).toBeInstanceOf(PlaintextWriteError)
    const message = error instanceof Error ? error.message : ''
    expect(message).not.toContain('secret-not-a-number')
    expect(message).toContain('SQLSTATE 22P02')
    expect(message).toContain('"email" (integer)')
    expect(error instanceof Error ? error.cause : 'n/a').toBeUndefined()

    const db = await pool.connect()
    try {
      const { rows } = await db.query<{ details: unknown }>(
        'SELECT details FROM cipherstash.cs_migrations',
      )
      expect(JSON.stringify(rows)).not.toContain('secret-not-a-number')
      const state = await progress(db, TABLE, 'email_encrypted')
      expect(state?.event).toBe('error')
      expect(state?.details).toMatchObject({
        errorName: 'PlaintextWriteError',
        sqlState: '22P02',
        plaintextSqlType: 'integer',
      })
      expect(state?.details).not.toHaveProperty('message')
    } finally {
      db.release()
    }
    expect(await plaintextCount()).toBe(0)
  })

  it.each([0, -1, 1.5, Number.NaN, MAX_DECRYPT_CHUNK_SIZE + 1])(
    'refuses chunk size %s before any request or event',
    async (chunkSize) => {
      await seed(5)

      await expect(run({ chunkSize })).rejects.toBeInstanceOf(RangeError)

      expect(stubClient.calls).toEqual([])
      const db = await pool.connect()
      try {
        expect((await latestByColumn(db)).size).toBe(0)
      } finally {
        db.release()
      }
    },
  )

  it('writes a chunk of the maximum size in one statement (2 parameters per row)', async () => {
    await seed(MAX_DECRYPT_CHUNK_SIZE)

    const result = await run({ chunkSize: MAX_DECRYPT_CHUNK_SIZE })

    expect(result.completed).toBe(true)
    expect(stubClient.calls).toEqual([MAX_DECRYPT_CHUNK_SIZE])
    expect(await plaintextCount()).toBe(MAX_DECRYPT_CHUNK_SIZE)
  }, 60_000)

  it('names the rows whose ciphertext decrypts to null in a scalar column', async () => {
    await pool.query(`
      CREATE TABLE ${TABLE} (
        id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        email_encrypted jsonb,
        email integer
      )
    `)
    await pool.query(
      `INSERT INTO ${TABLE} (email_encrypted) VALUES ($1::jsonb), ($2::jsonb)`,
      [JSON.stringify(envelope(null)), JSON.stringify(envelope(5))],
    )

    const result = await run({ plaintextSqlType: 'integer' })

    expect(result.rowsSkipped).toBe(1)
    expect(result.skippedByCode).toEqual({ NULL_PLAINTEXT: 1 })
    expect(result.nullPlaintextPks).toEqual(['1'])
  })

  it('tells an empty plaintext twin from one that already holds values', async () => {
    await seed(3)
    const db = await pool.connect()
    try {
      expect(await columnHasValues(db, TABLE, 'email')).toBe(false)
      await db.query(
        `UPDATE ${TABLE} SET email = 'stale@example.com' WHERE id = 2`,
      )
      expect(await columnHasValues(db, TABLE, 'email')).toBe(true)
    } finally {
      db.release()
    }
  })

  it('is idempotent: a re-run rewrites nothing and only retries the skipped rows', async () => {
    await seed(120, 40)
    await run()
    const before = await pool.query<{ h: string }>(
      `SELECT md5(string_agg(coalesce(email, '∅'), ',' ORDER BY id)) AS h FROM ${TABLE}`,
    )
    stubClient.calls = []

    // A fresh pass (the last event was `decrypted`, not a checkpoint) that
    // only sees the 3 still-NULL rows. They are still locked, so its one chunk
    // decrypts nothing and is refused by default…
    await expect(run()).rejects.toBeInstanceOf(UndecryptableBatchError)
    expect(stubClient.calls).toEqual([3])

    // …and with the explicit opt-in it completes, re-skipping them.
    const again = await run({ continueOnUndecryptable: true })
    expect(again.completed).toBe(true)
    expect(again.rowsProcessed).toBe(3)
    expect(again.rowsSkipped).toBe(3)
    expect(again.rowsDecrypted).toBe(0)
    const after = await pool.query<{ h: string }>(
      `SELECT md5(string_agg(coalesce(email, '∅'), ',' ORDER BY id)) AS h FROM ${TABLE}`,
    )
    expect(after.rows[0]?.h).toBe(before.rows[0]?.h)
  }, 10_000)

  it('refuses a first batch that decrypts nothing, writing nothing and recording no checkpoint', async () => {
    await seed(30, 1) // every row locked

    await expect(run()).rejects.toBeInstanceOf(UndecryptableBatchError)

    expect(await plaintextCount()).toBe(0)
    const db = await pool.connect()
    try {
      const state = await progress(db, TABLE, 'email_encrypted')
      expect(state?.event).toBe('error')
      expect(state?.cursorValue).toBeNull()
      expect(state?.details).toMatchObject({ plaintextColumn: 'email' })
      // The refused batch is recorded by counts and codes: no value, no
      // message.
      expect(state?.details).toMatchObject({
        errorName: 'UndecryptableBatchError',
        batchRows: 30,
        batchCodes: { UNKNOWN: 30 },
      })
      expect(state?.details).not.toHaveProperty('message')
    } finally {
      db.release()
    }
  })

  it('refuses to write an EQL envelope into the plaintext column (reverse leak guard)', async () => {
    await seed(5)
    const passthrough: DecryptionClientLike = {
      bulkDecrypt: (payloads) =>
        Promise.resolve({
          data: payloads.map((payload) => ({
            id: payload.id,
            data: payload.data,
          })),
        }),
    }

    await expect(run({ decryptionClient: passthrough })).rejects.toThrow(
      /EQL envelope instead of plaintext/,
    )
    expect(await plaintextCount()).toBe(0)
  })

  it('never overwrites plaintext already written by a dual-writing app, unless forced', async () => {
    await seed(10)
    // Dual-writes are live, so the app writes the plaintext column itself.
    await confirm()
    await pool.query(
      `UPDATE ${TABLE} SET email = 'newer@example.com' WHERE id = 3`,
    )

    await run()
    const { rows } = await pool.query<{ email: string }>(
      `SELECT email FROM ${TABLE} WHERE id = 3`,
    )
    expect(rows[0]?.email).toBe('newer@example.com')

    await run({ force: true })
    const forced = await pool.query<{ email: string }>(
      `SELECT email FROM ${TABLE} WHERE id = 3`,
    )
    expect(forced.rows[0]?.email).toBe('user-3@example.com')
  })

  // F1: a forced write must not overwrite a dual-write that landed while the
  // chunk's ciphertext was out for decryption.
  it('a forced pass does not overwrite a concurrent dual-write that landed during bulkDecrypt', async () => {
    await seed(10)
    // The app dual-writes row 4 — both columns — while the chunk that read its
    // old ciphertext is still in its bulkDecrypt round trip.
    const racingClient: DecryptionClientLike = {
      async bulkDecrypt(payloads) {
        await pool.query(
          `UPDATE ${TABLE} SET email_encrypted = $1::jsonb, email = $2 WHERE id = 4`,
          [JSON.stringify(envelope('newer@example.com')), 'newer@example.com'],
        )
        return stubClient.bulkDecrypt(payloads)
      },
    }

    await run({ force: true, decryptionClient: racingClient })

    const { rows } = await pool.query<{ email: string }>(
      `SELECT email FROM ${TABLE} WHERE id = 4`,
    )
    // The ciphertext now says newer@; plaintext must agree, or `decrypt drop`
    // drops the only copy of the newer value.
    expect(rows[0]?.email).toBe('newer@example.com')
  })

  // F7: a first chunk whose every row decrypts to null is not a credentials
  // problem; decryption worked.
  it('does not blame credentials when every row in the first chunk decrypts to null', async () => {
    await pool.query(`
      CREATE TABLE ${TABLE} (
        id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        email_encrypted jsonb,
        email integer
      )
    `)
    await pool.query(
      `INSERT INTO ${TABLE} (email_encrypted) VALUES ($1::jsonb), ($2::jsonb), ($3::jsonb)`,
      [
        JSON.stringify(envelope(null)),
        JSON.stringify(envelope(null)),
        JSON.stringify(envelope(7)),
      ],
    )

    // Chunk of 2: the first chunk is entirely NULL_PLAINTEXT.
    const outcome = await run({
      plaintextSqlType: 'integer',
      chunkSize: 2,
    }).catch((error: unknown) => error)

    expect(outcome).not.toBeInstanceOf(UndecryptableBatchError)
    expect(outcome).toMatchObject({
      completed: true,
      skippedByCode: { NULL_PLAINTEXT: 2 },
      nullPlaintextPks: ['1', '2'],
      rowsDecrypted: 1,
    })
  })

  it('ignores a forward checkpoint recorded under the same key — no cross-direction resume', async () => {
    await seed(50)
    const db = await pool.connect()
    try {
      await appendEvent(db, {
        tableName: TABLE,
        columnName: 'email_encrypted',
        event: 'backfill_checkpoint',
        phase: 'backfilling',
        cursorValue: '40',
        rowsProcessed: 40,
      })
    } finally {
      db.release()
    }

    const result = await run()
    expect(result.resumed).toBe(false)
    expect(result.rowsProcessed).toBe(50)
    expect(await plaintextCount()).toBe(50)
  })

  it.each([
    { type: 'integer', plaintext: 42, expected: '42' },
    {
      type: 'bigint',
      plaintext: 9007199254740993n,
      expected: '9007199254740993',
    },
    { type: 'double precision', plaintext: 0.1, expected: '0.1' },
    { type: 'boolean', plaintext: false, expected: 'false' },
    { type: 'date', plaintext: '2024-02-29', expected: '2024-02-29' },
    {
      type: 'timestamptz',
      plaintext: '2024-02-29T10:11:12.000Z',
      expected: '2024-02-29 10:11:12+00',
    },
    {
      type: 'jsonb',
      plaintext: { a: [1, 'x'], b: null },
      expected: '{"a": [1, "x"], "b": null}',
    },
    {
      type: 'jsonb',
      plaintext: 'a string document',
      expected: '"a string document"',
    },
    { type: 'character varying(32)', plaintext: 'short', expected: 'short' },
  ])(
    'writes a $type twin with the column’s declared type',
    async ({ type, plaintext, expected }) => {
      await pool.query(`
      CREATE TABLE ${TABLE} (
        id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        email_encrypted jsonb,
        email ${type}
      )
    `)
      // bigint plaintext can't round-trip through the JSON marker, so the stub
      // is bypassed for this one with a client that returns it natively.
      await pool.query(
        `INSERT INTO ${TABLE} (email_encrypted) VALUES ($1::jsonb)`,
        [JSON.stringify(envelope(null))],
      )
      const native: DecryptionClientLike = {
        bulkDecrypt: (payloads) =>
          Promise.resolve({
            data: payloads.map((payload) => ({
              id: payload.id,
              data: plaintext,
            })),
          }),
      }
      const db = await pool.connect()
      let sqlType: string | null
      try {
        sqlType = await columnSqlType(db, TABLE, 'email')
      } finally {
        db.release()
      }
      expect(sqlType).not.toBeNull()

      await run({
        decryptionClient: native,
        plaintextSqlType: sqlType as string,
      })

      const reader = await pool.connect()
      try {
        await reader.query("SET TIME ZONE 'UTC'")
        const { rows } = await reader.query<{ v: string }>(
          `SELECT email::text AS v FROM ${TABLE}`,
        )
        expect(rows[0]?.v).toBe(expected)
      } finally {
        reader.release()
      }
    },
  )

  it('lists plain AND expression indexes over a column — the EQL-term indexes decrypt drop removes', async () => {
    await seed(1)
    await pool.query(
      `CREATE INDEX users_enc_plain ON ${TABLE} (email_encrypted)`,
    )
    // The shape of an EQL functional index: the column appears only inside
    // the expression, so `indkey` alone would not find it.
    await pool.query(
      `CREATE INDEX users_enc_expr ON ${TABLE} ((email_encrypted->>'c'))`,
    )
    await pool.query(`CREATE INDEX users_other ON ${TABLE} (email)`)

    const db = await pool.connect()
    try {
      const indexes = await listColumnIndexes(db, TABLE, 'email_encrypted')
      expect(indexes.map((index) => index.name)).toEqual([
        'users_enc_expr',
        'users_enc_plain',
      ])
      expect(indexes[0]?.schema).toBe('migrate_decrypt_test')
      expect(indexes[0]?.definition).toContain('CREATE INDEX users_enc_expr')
    } finally {
      db.release()
    }
  })

  it('counts EQL v3 domain columns across every schema (the --uninstall-eql gate)', async () => {
    const db = await pool.connect()
    try {
      const baseline = await countEqlColumnsInDatabase(db)
      await db.query('CREATE DOMAIN migrate_decrypt_test.eql_v3_probe AS jsonb')
      await db.query(
        `CREATE TABLE ${TABLE} (id int PRIMARY KEY, a migrate_decrypt_test.eql_v3_probe, b migrate_decrypt_test.eql_v3_probe[], c jsonb)`,
      )
      expect(await countEqlColumnsInDatabase(db)).toBe(baseline + 2)
      await db.query(`DROP TABLE ${TABLE}`)
      await db.query('DROP DOMAIN migrate_decrypt_test.eql_v3_probe')
    } finally {
      db.release()
    }
  })
})
