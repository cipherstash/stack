/**
 * EQL v3 twin of `backfill.integration.test.ts` — the engine mechanics are
 * identical (and exhaustively covered there); THIS file pins the v3-specific
 * contract (#648/#649):
 *
 * - the leak guard (`isEncryptedPayload`) accepts BOTH v3 wire shapes — flat
 *   scalars (`{v:3, i, c}`) and SteVec documents (`{v:3, k:'sv', i, sv}`) —
 *   so a v3 client's output flows through `runBackfill` unmodified;
 * - the `$N::jsonb` write lands v3 envelopes in the target column;
 * - `countEncrypted` (the v3 verification primitive — v3 has no
 *   `eql_v2.count_encrypted_with_active_config`) counts them.
 *
 * Skipped unless `PG_TEST_URL` is set (same harness as the v2 file):
 *
 * ```
 * cd local && docker compose up -d
 * PG_TEST_URL=postgres://cipherstash:password@localhost:5432/cipherstash \
 *   pnpm -F @cipherstash/migrate test backfill-v3.integration
 * ```
 *
 * No CipherStash credentials required — payloads are deterministic v3-shaped
 * markers. End-to-end proof against a real `eql_v3_*` domain (whose CHECK
 * constraint demands real ciphertext structure) lives with the live-crypto
 * harness, not here.
 */

import 'dotenv/config'
import pg from 'pg'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import { type EncryptionClientLike, runBackfill } from '../backfill.js'
import { countEncrypted } from '../cursor.js'
import { installMigrationsSchema } from '../install.js'
import { progress } from '../state.js'
import {
  detectColumnEqlVersion,
  listEncryptedColumns,
  resolveEncryptedColumn,
} from '../version.js'

const PG_URL = process.env.PG_TEST_URL
const runIntegration = Boolean(PG_URL)

describe.skipIf(!runIntegration)('runBackfill with EQL v3 payloads', () => {
  let pool: pg.Pool

  beforeAll(async () => {
    pool = new pg.Pool({ connectionString: PG_URL, max: 4 })
    const db = await pool.connect()
    try {
      await db.query('DROP SCHEMA IF EXISTS cipherstash CASCADE')
      await db.query('DROP SCHEMA IF EXISTS migrate_v3_test CASCADE')
      await db.query('CREATE SCHEMA migrate_v3_test')
      await installMigrationsSchema(db)
    } finally {
      db.release()
    }
  })

  afterEach(async () => {
    await pool.query('DROP TABLE IF EXISTS migrate_v3_test.users')
    await pool.query('TRUNCATE cipherstash.cs_migrations')
  })

  afterAll(async () => {
    await pool.end()
  })

  /** v3 FLAT SCALAR marker — the shape `EncryptionV3` clients emit for
   * text/number columns: no `k` discriminator, top-level `c`. */
  const v3ScalarClient: EncryptionClientLike = {
    bulkEncryptModels(input) {
      return Promise.resolve({
        data: input.map((row) => ({
          __pk: row.__pk,
          email: {
            v: 3,
            i: { t: 'users', c: 'email' },
            c: `mock-v3-ciphertext:${row.email}`,
          },
        })),
      })
    },
  }

  /** v3 SteVec marker — the searchable-JSON document shape: `k: 'sv'`,
   * `sv` array, NO top-level `c`. The leak guard must accept it. */
  const v3SteVecClient: EncryptionClientLike = {
    bulkEncryptModels(input) {
      return Promise.resolve({
        data: input.map((row) => ({
          __pk: row.__pk,
          email: {
            v: 3,
            k: 'sv',
            i: { t: 'users', c: 'email' },
            sv: [{ s: 'mock-selector', t: `mock-term:${row.email}` }],
          },
        })),
      })
    },
  }

  async function seed(n: number) {
    const db = await pool.connect()
    try {
      await db.query(`
        CREATE TABLE migrate_v3_test.users (
          id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          email           text NOT NULL,
          email_encrypted jsonb
        )
      `)
      await db.query(
        `INSERT INTO migrate_v3_test.users (email)
         SELECT 'user-' || g || '@example.com' FROM generate_series(1, $1) AS g`,
        [n],
      )
    } finally {
      db.release()
    }
  }

  function backfillWith(client: EncryptionClientLike) {
    return (db: pg.PoolClient) =>
      runBackfill({
        db,
        encryptionClient: client,
        tableSchema: { tableName: 'users', build: () => ({}) },
        tableName: 'migrate_v3_test.users',
        schemaColumnKey: 'email',
        plaintextColumn: 'email',
        encryptedColumn: 'email_encrypted',
        pkColumn: 'id',
        chunkSize: 50,
      })
  }

  it('backfills v3 flat-scalar payloads end to end', async () => {
    await seed(120)
    const db = await pool.connect()
    try {
      const result = await backfillWith(v3ScalarClient)(db)
      expect(result.completed).toBe(true)
      expect(result.rowsProcessed).toBe(120)

      // countEncrypted is the v3 verification primitive (no config table).
      expect(
        await countEncrypted(db, 'migrate_v3_test.users', 'email_encrypted'),
      ).toBe(120)

      // The stored value is the v3 envelope, verbatim.
      const row = await db.query<{ enc: { v: number; c: string } }>(
        'SELECT email_encrypted AS enc FROM migrate_v3_test.users ORDER BY id LIMIT 1',
      )
      expect(row.rows[0]?.enc.v).toBe(3)
      expect(row.rows[0]?.enc.c).toContain('mock-v3-ciphertext:')

      const state = await progress(db, 'migrate_v3_test.users', 'email')
      expect(state?.phase).toBe('backfilled')
    } finally {
      db.release()
    }
  })

  it('the leak guard accepts v3 SteVec documents (sv, no top-level c)', async () => {
    await seed(30)
    const db = await pool.connect()
    try {
      const result = await backfillWith(v3SteVecClient)(db)
      expect(result.completed).toBe(true)
      expect(result.rowsProcessed).toBe(30)
      const row = await db.query<{ enc: { v: number; k: string } }>(
        'SELECT email_encrypted AS enc FROM migrate_v3_test.users ORDER BY id LIMIT 1',
      )
      expect(row.rows[0]?.enc.v).toBe(3)
      expect(row.rows[0]?.enc.k).toBe('sv')
    } finally {
      db.release()
    }
  })

  it('is idempotent for v3 exactly like v2 (encrypted IS NULL guard)', async () => {
    await seed(40)
    const db = await pool.connect()
    try {
      await backfillWith(v3ScalarClient)(db)
      const second = await backfillWith(v3ScalarClient)(db)
      expect(second.completed).toBe(true)
      expect(second.rowsProcessed).toBe(0)
      expect(
        await countEncrypted(db, 'migrate_v3_test.users', 'email_encrypted'),
      ).toBe(40)
    } finally {
      db.release()
    }
  })
})

/**
 * The domain-type resolution primitives against a REAL Postgres catalog —
 * the part unit mocks can't prove: case-exact `to_regclass` resolution for
 * quoted (Prisma-style) table names, and name-free discovery of encrypted
 * columns from their domain types. Local domains named like EQL's are
 * enough: classification keys on `pg_type.typname`, which is what a real
 * EQL install produces too.
 */
describe.skipIf(!runIntegration)(
  'EQL version resolution (real catalog)',
  () => {
    let pool: pg.Pool

    beforeAll(async () => {
      pool = new pg.Pool({ connectionString: PG_URL, max: 2 })
      await pool.query('DROP SCHEMA IF EXISTS migrate_v3_resolve CASCADE')
      await pool.query('CREATE SCHEMA migrate_v3_resolve')
      await pool.query(
        'CREATE DOMAIN migrate_v3_resolve.eql_v3_text_search_t AS jsonb',
      )
      // Mixed-case table (Prisma default naming) with a custom-named
      // encrypted column: exercises BOTH conventions this module must not
      // rely on — lowercase names and the `_encrypted` suffix.
      await pool.query(`
      CREATE TABLE migrate_v3_resolve."Users" (
        id bigint PRIMARY KEY,
        email text,
        secret_blob migrate_v3_resolve.eql_v3_text_search_t
      )
    `)
    })

    afterAll(async () => {
      await pool.query('DROP SCHEMA IF EXISTS migrate_v3_resolve CASCADE')
      await pool.end()
    })

    it('detects the version on a mixed-case (quoted) table name', async () => {
      expect(
        await detectColumnEqlVersion(
          pool as unknown as pg.ClientBase,
          'migrate_v3_resolve.Users',
          'secret_blob',
        ),
      ).toBe(3)
    })

    it('returns null (not an error) for a table that truly does not exist', async () => {
      expect(
        await detectColumnEqlVersion(
          pool as unknown as pg.ClientBase,
          'migrate_v3_resolve.users',
          'secret_blob',
        ),
      ).toBeNull()
    })

    it('lists encrypted columns from domain types alone', async () => {
      expect(
        await listEncryptedColumns(
          pool as unknown as pg.ClientBase,
          'migrate_v3_resolve.Users',
        ),
      ).toEqual([
        {
          column: 'secret_blob',
          domain: 'eql_v3_text_search_t',
          version: 3,
        },
      ])
    })

    it('resolves the encrypted counterpart with no naming convention at all', async () => {
      const info = await resolveEncryptedColumn(
        pool as unknown as pg.ClientBase,
        'migrate_v3_resolve.Users',
        'email',
      )
      expect(info?.column).toBe('secret_blob')
      expect(info?.version).toBe(3)
    })
  },
)
