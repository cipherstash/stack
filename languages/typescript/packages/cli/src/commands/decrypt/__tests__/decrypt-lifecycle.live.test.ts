/**
 * The reverse lifecycle through the real commands against live Postgres:
 * `decrypt plan`, `status`, `backfill` and `drop` each resolve the plaintext
 * twin through `ColumnMigration`, and must all name the same one. They once
 * each derived it, and disagreed on edge cases the unit tests' mocks could
 * not show.
 *
 * Only the edges are stubbed: the prompts (answered yes), the stash config
 * (this database), and the encryption client (a `bulkDecrypt` that decodes
 * deterministic markers, so no CipherStash credentials are needed). The
 * catalog reads, `cipherstash.cs_migrations`, the manifest file and the
 * generated SQL are all real.
 *
 * Gated on STASH_TEST_DATABASE_URL so the default `pnpm test` stays green
 * without a database. Locally:
 *
 *   docker compose -f local/docker-compose.postgres.yml up -d --wait
 *   export STASH_TEST_DATABASE_URL=postgres://cipherstash:password@localhost:55432/cipherstash
 *
 * Needs no EQL install: the suite's own schema declares `jsonb` domains with
 * the EQL v3 names, which is all the commands look at. It touches only its own
 * schema and the `cs_migrations` rows for its own table.
 */

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from 'vitest'

const DATABASE_URL = process.env.STASH_TEST_DATABASE_URL
const describeLive = DATABASE_URL ? describe : describe.skip

const SCHEMA = 'stash_decrypt_lifecycle'
const TABLE = 'lifecycle_users'

const { SCOPED_URL, output, record } = vi.hoisted(() => {
  const url = process.env.STASH_TEST_DATABASE_URL
  /** Everything the commands printed, in order. */
  const output: string[] = []
  return {
    /** The connection every command makes: this suite's schema first. */
    SCOPED_URL: url
      ? `${url}${url.includes('?') ? '&' : '?'}options=${encodeURIComponent('-c search_path=stash_decrypt_lifecycle')}`
      : '',
    output,
    record: (...args: unknown[]) => {
      output.push(args.map(String).join(' '))
    },
  }
})

vi.mock('@clack/prompts', () => ({
  intro: vi.fn(record),
  outro: vi.fn(record),
  note: vi.fn((body: string, title?: string) => record(title ?? '', body)),
  log: {
    info: vi.fn(record),
    warn: vi.fn(record),
    error: vi.fn(record),
    success: vi.fn(record),
    step: vi.fn(record),
  },
  confirm: vi.fn(async () => true),
  isCancel: vi.fn(() => false),
}))
vi.mock('@/config/index.js', () => ({
  loadStashConfig: vi.fn(async () => ({ databaseUrl: SCOPED_URL })),
}))
vi.mock('@/commands/encrypt/context.js', () => ({
  // Decodes {@link envelope}. Only the client is used by `decrypt backfill`.
  loadEncryptionContext: vi.fn(async () => ({
    client: {
      bulkDecrypt: async (
        payloads: Array<{ id?: string; data: { c: string } | null }>,
      ) => ({
        data: payloads.map((payload) => ({
          id: payload.id,
          data: JSON.parse(payload.data?.c ?? 'null').plaintext,
        })),
      }),
    },
  })),
  requireTable: vi.fn(),
}))

import {
  appendEvent,
  ColumnMigration,
  installMigrationsSchema,
} from '@cipherstash/migrate'
import type pg from 'pg'
import { decryptBackfillCommand } from '../backfill.js'
import { decryptDropCommand } from '../drop.js'
import { decryptPlanCommand } from '../plan.js'
import { decryptStatusCommand } from '../status.js'

/** A v3-shaped marker the stub client "decrypts" back to `plaintext`. */
function envelope(plaintext: string) {
  return {
    v: 3,
    i: { t: TABLE, c: 'email_encrypted' },
    c: JSON.stringify({ plaintext }),
  }
}

/** The status table's data rows, from the latest `decrypt status`. */
async function statusRows(): Promise<string[]> {
  output.length = 0
  await decryptStatusCommand()
  const table = output.find((line) =>
    line.startsWith('Reverse migration status'),
  )
  expect(table, output.join('\n')).toBeDefined()
  return (table ?? '').split('\n').slice(1)
}

function rowFor(rows: string[], column: string): string {
  const row = rows.find((r) => r.startsWith(`${TABLE}  ${column} `))
  expect(row, rows.join('\n')).toBeDefined()
  return row ?? ''
}

describeLive('decrypt lifecycle — live Postgres', () => {
  let client: pg.Client
  let cwd: string
  let originalCwd: string
  /** Whether `cipherstash` existed before this suite created it. */
  let trackingSchemaExisted = true

  beforeAll(async () => {
    const { default: pgModule } = await import('pg')
    client = new pgModule.Client({ connectionString: SCOPED_URL })
    await client.connect()
    originalCwd = process.cwd()
    const { rows } = await client.query(
      `SELECT 1 FROM pg_namespace WHERE nspname = 'cipherstash'`,
    )
    trackingSchemaExisted = rows.length > 0
  })

  afterAll(async () => {
    await client.query(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`)
    if (trackingSchemaExisted) {
      await client
        .query('DELETE FROM cipherstash.cs_migrations WHERE table_name = $1', [
          TABLE,
        ])
        .catch(() => undefined)
    } else {
      // Leave the database as found. A role named `cipherstash` has
      // `"$user"` first on its default search_path, so a `cipherstash` schema
      // left behind would receive the unqualified objects a later suite's EQL
      // install creates, and the installer would then refuse to reinstall.
      await client.query('DROP SCHEMA IF EXISTS cipherstash CASCADE')
    }
    await client.end().catch(() => undefined)
  })

  beforeEach(async () => {
    vi.spyOn(process, 'exit').mockImplementation((code) => {
      throw new Error(`process.exit(${code}):\n${output.join('\n')}`)
    })
    await client.query(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`)
    await client.query(`CREATE SCHEMA ${SCHEMA}`)
    for (const domain of [
      'eql_v3_text_search',
      'eql_v3_text',
      'eql_v3_text_eq',
    ]) {
      await client.query(`CREATE DOMAIN ${SCHEMA}.${domain} AS jsonb`)
    }
    await client
      .query('DELETE FROM cipherstash.cs_migrations WHERE table_name = $1', [
        TABLE,
      ])
      .catch(() => undefined)

    cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'stash-decrypt-lifecycle-'))
    process.chdir(cwd)
    output.length = 0
  })

  afterEach(() => {
    process.chdir(originalCwd)
    fs.rmSync(cwd, { recursive: true, force: true })
    vi.restoreAllMocks()
  })

  it('plan, status, backfill and drop all reverse into the twin the manifest names', async () => {
    await client.query(`
      CREATE TABLE ${TABLE} (
        id int PRIMARY KEY,
        email_encrypted eql_v3_text_search
      )
    `)
    for (let id = 1; id <= 5; id++) {
      await client.query(
        `INSERT INTO ${TABLE} (id, email_encrypted) VALUES ($1, $2)`,
        [id, JSON.stringify(envelope(`user-${id}@example.com`))],
      )
    }
    // The forward manifest names the original column `contact`, not the
    // `email` the `<name>_encrypted` convention would propose.
    fs.mkdirSync(path.join(cwd, '.cipherstash'))
    fs.writeFileSync(
      path.join(cwd, '.cipherstash', 'migrations.json'),
      JSON.stringify({
        version: 1,
        tables: {
          [TABLE]: [{ column: 'contact', encryptedColumn: 'email_encrypted' }],
        },
      }),
    )

    // Before anything: status proposes the twin plan will add.
    expect(rowFor(await statusRows(), 'email_encrypted')).toContain(
      'contact (text, to add)',
    )

    // plan writes the ADD COLUMN; apply it as the user would.
    await decryptPlanCommand({ table: TABLE, column: 'email_encrypted' })
    const [planFile] = fs.readdirSync(path.join(cwd, 'drizzle'))
    expect(planFile).toBeDefined()
    const planSql = fs.readFileSync(
      path.join(cwd, 'drizzle', planFile),
      'utf-8',
    )
    expect(planSql).toContain('ADD COLUMN IF NOT EXISTS "contact" text')
    await client.query(planSql)
    fs.rmSync(path.join(cwd, 'drizzle'), { recursive: true })

    let row = rowFor(await statusRows(), 'email_encrypted')
    expect(row).toMatch(/email_encrypted\s+eql_v3_text_search\s+contact\s/)
    expect(row).not.toContain('twin-has-values')

    await decryptBackfillCommand({
      table: TABLE,
      column: 'email_encrypted',
      confirmDualWritesDeployed: true,
    })
    const { rows: filled } = await client.query<{ n: string }>(
      `SELECT count(*) AS n FROM ${TABLE} WHERE contact = 'user-' || id || '@example.com'`,
    )
    expect(filled[0].n).toBe('5')

    row = rowFor(await statusRows(), 'email_encrypted')
    expect(row).toMatch(/contact\s+decrypted\s+\(backfill complete\)/)
    expect(row).not.toContain('forced-pass-owed')

    output.length = 0
    await decryptPlanCommand()
    expect(output.join('\n')).toContain(
      `${TABLE}.email_encrypted → contact: decrypted`,
    )

    output.length = 0
    await decryptDropCommand({ table: TABLE, column: 'email_encrypted' })
    const [dropFile] = fs.readdirSync(path.join(cwd, 'drizzle'))
    const dropSql = fs.readFileSync(
      path.join(cwd, 'drizzle', dropFile),
      'utf-8',
    )
    expect(dropSql).toContain('"contact"')
    await client.query(dropSql)
    const { rows: left } = await client.query<{ column_name: string }>(
      `SELECT column_name FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2 ORDER BY column_name`,
      [SCHEMA, TABLE],
    )
    expect(left.map((r) => r.column_name)).toEqual(['contact', 'id'])

    // The encrypted column is gone; status still shows the finished migration.
    row = rowFor(await statusRows(), 'email_encrypted')
    expect(row).toMatch(/contact\s+encrypted-dropped\s+\(dropped\)/)
    expect(row).not.toContain('encrypted-col-missing')
  })

  it('status names the fallback twin for a column called _encrypted', async () => {
    await client.query(`
      CREATE TABLE ${TABLE} (
        id int PRIMARY KEY,
        _encrypted eql_v3_text,
        email_encrypted eql_v3_text_search
      )
    `)

    const rows = await statusRows()

    expect(rowFor(rows, '_encrypted')).toContain(
      '_encrypted_plaintext (text, to add)',
    )
    expect(rowFor(rows, 'email_encrypted')).toContain('email (text, to add)')
  })

  it('status flags a twin that is itself an EQL column, which plan and backfill refuse', async () => {
    await client.query(`
      CREATE TABLE ${TABLE} (
        id int PRIMARY KEY,
        email_encrypted eql_v3_text_search,
        email eql_v3_text_eq
      )
    `)

    const row = rowFor(await statusRows(), 'email_encrypted')

    expect(row).toContain('plaintext-col-is-eql')
    expect(row).not.toContain('plaintext-col-missing')
  })

  it('status shows a column whose earlier reverse migration was superseded as starting over', async () => {
    await client.query(`
      CREATE TABLE ${TABLE} (
        id int PRIMARY KEY,
        email_encrypted eql_v3_text_search
      )
    `)
    await installMigrationsSchema(client)
    // Reversed into old_email once, then old_email was encrypted again: the
    // reverse drop is history, and the forward event after it supersedes it.
    await appendEvent(client, {
      tableName: TABLE,
      columnName: 'email_encrypted',
      event: 'encrypted_dropped',
      phase: 'encrypted-dropped',
      details: { plaintextColumn: 'old_email' },
    })
    await appendEvent(client, {
      tableName: TABLE,
      columnName: 'old_email',
      event: 'dual_writing',
      phase: 'dual-writing',
      details: { encryptedColumn: 'email_encrypted' },
    })

    const row = rowFor(await statusRows(), 'email_encrypted')

    expect(row).not.toContain('encrypted-dropped')
    expect(row).not.toContain('old_email')
    expect(row).toMatch(/email_encrypted\s+eql_v3_text_search\s+email\s/)
  })

  it('status flags a twin that already holds values, which backfill refuses without a choice', async () => {
    await client.query(`
      CREATE TABLE ${TABLE} (
        id int PRIMARY KEY,
        email_encrypted eql_v3_text_search,
        email text
      )
    `)
    await client.query(
      `INSERT INTO ${TABLE} VALUES (1, $1, 'stale@example.com')`,
      [JSON.stringify(envelope('user-1@example.com'))],
    )

    expect(rowFor(await statusRows(), 'email_encrypted')).toContain(
      'twin-has-values',
    )
    await expect(
      decryptBackfillCommand({
        table: TABLE,
        column: 'email_encrypted',
        confirmDualWritesDeployed: true,
      }),
    ).rejects.toThrow(/--force[\s\S]*--confirm-plaintext-current/)
  })
  it('status flags a twin a forward encryption is still open on, which backfill refuses', async () => {
    await client.query(`
      CREATE TABLE ${TABLE} (
        id int PRIMARY KEY,
        email_encrypted eql_v3_text_search,
        email text
      )
    `)
    await installMigrationsSchema(client)
    await appendEvent(client, {
      tableName: TABLE,
      columnName: 'email',
      event: 'dual_writing',
      phase: 'dual-writing',
      details: { encryptedColumn: 'email_encrypted' },
    })

    expect(rowFor(await statusRows(), 'email_encrypted')).toContain(
      'forward-open',
    )
    await expect(
      decryptBackfillCommand({
        table: TABLE,
        column: 'email_encrypted',
        confirmDualWritesDeployed: true,
      }),
    ).rejects.toThrow(/forward encryption/)
  })

  it('status flags a started forced pass as owed, refuses the waiver, and clears once a run finishes it', async () => {
    await client.query(`
      CREATE TABLE ${TABLE} (
        id int PRIMARY KEY,
        email_encrypted eql_v3_text_search,
        email text
      )
    `)
    for (let id = 1; id <= 3; id++) {
      await client.query(
        `INSERT INTO ${TABLE} VALUES ($1, $2, 'stale@example.com')`,
        [id, JSON.stringify(envelope(`user-${id}@example.com`))],
      )
    }
    await installMigrationsSchema(client)
    // A `--force` run over a twin that held values, interrupted after it
    // started: the forced pass is owed.
    await appendEvent(client, {
      tableName: TABLE,
      columnName: 'email_encrypted',
      event: 'decrypt_dual_writing',
      phase: 'decrypt-dual-writing',
      details: { plaintextColumn: 'email', existingTwinValues: true },
    })
    await appendEvent(client, {
      tableName: TABLE,
      columnName: 'email_encrypted',
      event: 'decrypt_started',
      phase: 'decrypting',
      details: { plaintextColumn: 'email', force: true },
    })

    expect(rowFor(await statusRows(), 'email_encrypted')).toContain(
      'forced-pass-owed',
    )
    await expect(
      decryptBackfillCommand({
        table: TABLE,
        column: 'email_encrypted',
        confirmPlaintextCurrent: true,
      }),
    ).rejects.toThrow(/forced pass .* has already started/)

    // A plain run finishes it as a forced pass, overwriting the stale values.
    await decryptBackfillCommand({ table: TABLE, column: 'email_encrypted' })
    const { rows: stale } = await client.query<{ n: string }>(
      `SELECT count(*) AS n FROM ${TABLE} WHERE email = 'stale@example.com'`,
    )
    expect(stale[0].n).toBe('0')
    expect(rowFor(await statusRows(), 'email_encrypted')).not.toContain(
      'forced-pass-owed',
    )
  })

  it('status leaves out a finished reversal whose plaintext column was encrypted again under a new name', async () => {
    // email_encrypted was decrypted into email and dropped; email was then
    // encrypted again into email_v2.
    await client.query(`
      CREATE TABLE ${TABLE} (
        id int PRIMARY KEY,
        email text,
        email_v2 eql_v3_text_search
      )
    `)
    await installMigrationsSchema(client)
    await appendEvent(client, {
      tableName: TABLE,
      columnName: 'email_encrypted',
      event: 'encrypted_dropped',
      phase: 'encrypted-dropped',
      details: { plaintextColumn: 'email' },
    })
    await appendEvent(client, {
      tableName: TABLE,
      columnName: 'email',
      event: 'dual_writing',
      phase: 'dual-writing',
      details: { encryptedColumn: 'email_v2' },
    })

    const rows = await statusRows()

    expect(
      rows.find((r) => r.startsWith(`${TABLE}  email_encrypted `)),
      rows.join('\n'),
    ).toBeUndefined()
    expect(rows.join('\n')).not.toContain('encrypted-col-missing')
    expect(rowFor(rows, 'email_v2')).toBeDefined()
  })

  it('status flags an open reversal whose encrypted column is gone as encrypted-col-missing', async () => {
    // The backfill completed, then email_encrypted was dropped outside stash
    // before `decrypt drop` generated anything.
    await client.query(`CREATE TABLE ${TABLE} (id int PRIMARY KEY, email text)`)
    await installMigrationsSchema(client)
    for (const [event, phase] of [
      ['decrypt_dual_writing', 'decrypt-dual-writing'],
      ['decrypted', 'decrypted'],
    ] as const) {
      await appendEvent(client, {
        tableName: TABLE,
        columnName: 'email_encrypted',
        event,
        phase,
        details: { plaintextColumn: 'email', force: false },
      })
    }

    const row = rowFor(await statusRows(), 'email_encrypted')

    expect(row).toMatch(/email_encrypted\s+—\s+email\s+decrypted/)
    expect(row).toContain('encrypted-col-missing')
  })

  it('status does not load a reverse migration for a column with only forward history', async () => {
    await client.query(`CREATE TABLE ${TABLE} (id int PRIMARY KEY, email text)`)
    await installMigrationsSchema(client)
    await appendEvent(client, {
      tableName: TABLE,
      columnName: 'email',
      event: 'dual_writing',
      phase: 'dual-writing',
      details: { encryptedColumn: 'email_encrypted' },
    })
    const load = vi.spyOn(ColumnMigration, 'load')

    output.length = 0
    await decryptStatusCommand()

    expect(load).not.toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ table: TABLE, column: 'email' }),
    )
    expect(output.join('\n')).not.toContain(`${TABLE}  email `)
  })

  it('the plan overview names a generated drop, an open forward migration and a twin that holds values', async () => {
    await client.query(`
      CREATE TABLE ${TABLE} (
        id int PRIMARY KEY,
        a_encrypted eql_v3_text_search,
        a text,
        b_encrypted eql_v3_text_search,
        b text,
        c_encrypted eql_v3_text_search,
        c text
      )
    `)
    await client.query(
      `INSERT INTO ${TABLE} (id, c) VALUES (1, 'stale@example.com')`,
    )
    await installMigrationsSchema(client)
    for (const [event, phase] of [
      ['decrypt_dual_writing', 'decrypt-dual-writing'],
      ['decrypted', 'decrypted'],
      ['encrypted_dropped', 'encrypted-dropped'],
    ] as const) {
      await appendEvent(client, {
        tableName: TABLE,
        columnName: 'a_encrypted',
        event,
        phase,
        details: { plaintextColumn: 'a', force: false },
      })
    }
    await appendEvent(client, {
      tableName: TABLE,
      columnName: 'b',
      event: 'dual_writing',
      phase: 'dual-writing',
      details: { encryptedColumn: 'b_encrypted' },
    })

    output.length = 0
    await decryptPlanCommand()
    const overview = output.join('\n')

    expect(overview).toContain(
      `✓ ${TABLE}.a_encrypted: encrypted-dropped (apply the generated drop migration)`,
    )
    expect(overview).toContain(
      `! ${TABLE}.b_encrypted → b text: forward encryption still open at 'dual-writing'`,
    )
    expect(overview).toContain(
      `! ${TABLE}.c_encrypted → c text: twin already holds values; the backfill needs --force or --confirm-plaintext-current`,
    )
  })
})
