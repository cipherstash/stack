/**
 * `stash decrypt drop` and `stash decrypt plan` — the two commands that
 * generate migrations for the reverse lifecycle.
 *
 * `decrypt drop` is the one irreversible step: once the encrypted column is
 * gone, any row whose plaintext twin was never filled has lost its only copy.
 * So these tests pin its gates (phase, recorded pairing, live coverage) and
 * the apply-time re-check the generated SQL carries, the same way
 * `encrypt-v3.test.ts` pins `encrypt drop`.
 */

import type { ColumnIndexInfo, OpenCounterpart } from '@cipherstash/migrate'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { DecryptPair } from '../lib/resolve-pair.js'
import {
  decrypted,
  type FakeMigration,
  fakeMigration,
  inFlight,
  reverseEvent,
} from './fake-migration.js'

const queryMock = vi.hoisted(() =>
  vi.fn(async (_sql: string): Promise<{ rows: unknown[] }> => ({ rows: [] })),
)
vi.mock('pg', () => ({
  default: {
    Client: class {
      connect = vi.fn(async () => {})
      end = vi.fn(async () => {})
      query = queryMock
    },
  },
}))

const migrateMocks = vi.hoisted(() => ({
  countUndecrypted: vi.fn(async () => 0),
  listColumnIndexes: vi.fn(async (): Promise<ColumnIndexInfo[]> => []),
  countEqlColumnsInDatabase: vi.fn(async () => 1),
  removeManifestColumn: vi.fn(async () => true),
  columnHasValues: vi.fn(async () => false),
  readManifest: vi.fn(async (): Promise<unknown> => null),
  listEncryptedColumns: vi.fn(async () => [
    { column: 'email_encrypted', domain: 'eql_v3_text_search', version: 3 },
  ]),
}))
// The forward column migration `decrypt plan` closes for a removed source.
const forwardLoad = vi.hoisted(() => vi.fn())
vi.mock('@cipherstash/migrate', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@cipherstash/migrate')>()),
  ...migrateMocks,
  ColumnMigration: { load: forwardLoad },
}))

const resolveMock = vi.hoisted(() => vi.fn())
vi.mock('../lib/resolve-pair.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/resolve-pair.js')>()),
  resolveDecryptPair: resolveMock,
}))

vi.mock('@clack/prompts', () => ({
  intro: vi.fn(),
  outro: vi.fn(),
  note: vi.fn(),
  confirm: vi.fn(async () => true),
  isCancel: vi.fn(() => false),
  log: {
    info: vi.fn(),
    success: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    step: vi.fn(),
  },
}))
vi.mock('@/config/index.js', () => ({
  loadStashConfig: vi.fn(async () => ({ databaseUrl: 'postgres://test' })),
}))
vi.mock('@/commands/encrypt/context.js', () => ({
  loadEncryptionContext: vi.fn(),
  requireTable: vi.fn(),
}))
const detectMocks = vi.hoisted(() => ({
  detectDrizzle: vi.fn(() => false),
  detectPrismaNext: vi.fn(() => false),
}))
vi.mock('@/commands/db/detect.js', () => detectMocks)
vi.mock('@/commands/init/utils.js', () => ({
  detectPackageManager: vi.fn(() => 'npm'),
  runnerCommand: vi.fn((_pm: string, ref: string) => `npx ${ref}`),
}))
vi.mock('@/commands/encrypt/drizzle-helper.js', () => ({
  scaffoldDrizzleMigration: vi.fn(async ({ name }: { name: string }) => ({
    path: `drizzle/${name}.sql`,
  })),
}))
const writeFileMock = vi.hoisted(() => vi.fn())
// Only the default export's writers are faked (migration-file.ts uses them);
// the named exports stay real because `@cipherstash/eql/sql` reads the real
// uninstall bundle through them — the `--uninstall-eql` test embeds it.
vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>()
  return {
    ...actual,
    default: { ...actual, mkdirSync: vi.fn(), writeFileSync: writeFileMock },
  }
})

import * as p from '@clack/prompts'
import { BackfillConfigError } from '@/commands/encrypt/backfill.js'
import { decryptDropCommand } from '../drop.js'
import { buildAddPlaintextSql, decryptPlanCommand } from '../plan.js'

function pair(
  overrides: Partial<Omit<DecryptPair, 'migration'>> & {
    migration?: FakeMigration
  } = {},
): DecryptPair & { migration: FakeMigration } {
  return {
    table: 'users',
    encryptedColumn: 'email_encrypted',
    domain: 'eql_v3_text_search',
    mapping: { domain: 'eql_v3_text_search', family: 'text', sqlType: 'text' },
    plaintextColumn: 'email',
    via: 'recorded',
    plaintextSqlType: 'text',
    migration: fakeMigration({ history: decrypted() }),
    ...overrides,
  }
}

/** A pair with no reverse column migration on record. */
const fresh = (overrides: Parameters<typeof pair>[0] = {}) =>
  pair({ migration: fakeMigration(), ...overrides })

const forwardOpen: OpenCounterpart = {
  direction: 'forward',
  column: 'email',
  phase: 'backfilled',
}

function spyExit() {
  return vi
    .spyOn(process, 'exit')
    .mockImplementation((() => undefined) as never)
}

const writtenSql = () => writeFileMock.mock.calls[0]?.[1] as string | undefined

describe('decrypt drop', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    resolveMock.mockResolvedValue(pair())
    migrateMocks.countUndecrypted.mockResolvedValue(0)
    migrateMocks.listColumnIndexes.mockResolvedValue([])
    migrateMocks.countEqlColumnsInDatabase.mockResolvedValue(1)
    migrateMocks.readManifest.mockResolvedValue(null)
  })

  it('verifies coverage against the RECORDED twin and drops the encrypted column', async () => {
    const dropping = pair()
    resolveMock.mockResolvedValue(dropping)
    await decryptDropCommand({ table: 'users', column: 'email_encrypted' })

    expect(migrateMocks.countUndecrypted).toHaveBeenCalledWith(
      expect.anything(),
      'users',
      'email_encrypted',
      'email',
    )
    const sql = writtenSql() ?? ''
    expect(sql).toContain('LOCK TABLE "users" IN ACCESS EXCLUSIVE MODE')
    expect(sql).toContain('"email_encrypted" IS NOT NULL')
    expect(sql).toContain('"email" IS NULL')
    expect(sql).toContain('RAISE EXCEPTION')
    expect(sql).toMatch(
      /EXECUTE 'ALTER TABLE "users" DROP COLUMN "email_encrypted"'/,
    )
    // The plaintext twin is never touched.
    expect(sql).not.toMatch(/DROP COLUMN "email"'/)
    expect(dropping.migration.recordDropGenerated).toHaveBeenCalledWith(
      expect.objectContaining({ migrationFile: expect.any(String) }),
    )
  })

  it('drops the EQL-term indexes explicitly, inside the same atomic block, and names them', async () => {
    migrateMocks.listColumnIndexes.mockResolvedValue([
      {
        schema: 'public',
        name: 'users_email_ord',
        definition:
          'CREATE INDEX users_email_ord ON public.users USING btree (eql_v3.ord_term(email_encrypted))',
      },
    ])

    await decryptDropCommand({ table: 'users', column: 'email_encrypted' })

    const sql = writtenSql() ?? ''
    const indexAt = sql.indexOf(
      `EXECUTE 'DROP INDEX IF EXISTS "public"."users_email_ord"'`,
    )
    expect(indexAt).toBeGreaterThan(sql.indexOf('RAISE EXCEPTION'))
    expect(indexAt).toBeLessThan(sql.indexOf(`EXECUTE 'ALTER TABLE`))
    expect(p.log.info).toHaveBeenCalledWith(
      expect.stringContaining('public.users_email_ord'),
    )
  })

  it('refuses while any row still has ciphertext and no plaintext — naming lock contexts as a cause', async () => {
    migrateMocks.countUndecrypted.mockResolvedValue(3)
    const exitSpy = spyExit()

    await decryptDropCommand({ table: 'users', column: 'email_encrypted' })

    expect(p.log.error).toHaveBeenCalledWith(
      expect.stringContaining('3 row(s)'),
    )
    expect(p.log.error).toHaveBeenCalledWith(
      expect.stringContaining('lock context'),
    )
    // A value cleared in the plaintext column after writes to the encrypted
    // column stopped must not be "fixed" by a backfill that restores it.
    expect(p.log.error).toHaveBeenCalledWith(
      expect.stringContaining(
        'Do NOT re-run the backfill for these: it would write the old value back',
      ),
    )
    expect(writeFileMock).not.toHaveBeenCalled()
    expect(exitSpy).toHaveBeenCalledWith(1)
    exitSpy.mockRestore()
  })

  it("requires the reverse phase 'decrypted'", async () => {
    resolveMock.mockResolvedValue(
      pair({ migration: fakeMigration({ history: inFlight() }) }),
    )
    const exitSpy = spyExit()

    await decryptDropCommand({ table: 'users', column: 'email_encrypted' })

    expect(p.log.error).toHaveBeenCalledWith(
      expect.stringContaining("Must be 'decrypted'"),
    )
    expect(migrateMocks.countUndecrypted).not.toHaveBeenCalled()
    expect(writeFileMock).not.toHaveBeenCalled()
    expect(exitSpy).toHaveBeenCalledWith(1)
    exitSpy.mockRestore()
  })

  it("refuses at 'decrypted' while a forced pass is still owed", async () => {
    const twin = { plaintextColumn: 'email' }
    const owing = pair({
      migration: fakeMigration({
        history: [
          reverseEvent('decrypt_dual_writing', 'decrypt-dual-writing'),
          reverseEvent('decrypt_started', 'decrypting', {
            details: { ...twin, force: true },
          }),
          reverseEvent('decrypted', 'decrypted', {
            details: { ...twin, force: false },
          }),
        ],
      }),
    })
    expect(owing.migration.phase).toBe('decrypted')
    resolveMock.mockResolvedValue(owing)
    const exitSpy = spyExit()

    await decryptDropCommand({ table: 'users', column: 'email_encrypted' })

    expect(p.log.error).toHaveBeenCalledWith(
      expect.stringContaining('still owes a forced pass'),
    )
    expect(writeFileMock).not.toHaveBeenCalled()
    expect(owing.migration.recordDropGenerated).not.toHaveBeenCalled()
    expect(exitSpy).toHaveBeenCalledWith(1)
    exitSpy.mockRestore()
  })

  it('refuses without a RECORDED pairing, even when a twin name could be guessed', async () => {
    resolveMock.mockResolvedValue(
      pair({
        migration: fakeMigration({
          history: [reverseEvent('decrypted', 'decrypted', { details: {} })],
        }),
      }),
    )
    const exitSpy = spyExit()

    await decryptDropCommand({ table: 'users', column: 'email_encrypted' })

    expect(p.log.error).toHaveBeenCalledWith(
      expect.stringContaining('no plaintext column is recorded'),
    )
    expect(writeFileMock).not.toHaveBeenCalled()
    expect(exitSpy).toHaveBeenCalledWith(1)
    exitSpy.mockRestore()
  })

  it('refuses when the recorded twin no longer exists', async () => {
    resolveMock.mockResolvedValue(pair({ plaintextSqlType: null }))
    const exitSpy = spyExit()

    await decryptDropCommand({ table: 'users', column: 'email_encrypted' })

    expect(p.log.error).toHaveBeenCalledWith(
      expect.stringContaining('no longer exists'),
    )
    expect(writeFileMock).not.toHaveBeenCalled()
    exitSpy.mockRestore()
  })

  it('--uninstall-eql: refused while other EQL v3 columns remain', async () => {
    migrateMocks.countEqlColumnsInDatabase.mockResolvedValue(4)
    const exitSpy = spyExit()

    await decryptDropCommand({
      table: 'users',
      column: 'email_encrypted',
      uninstallEql: true,
    })

    expect(p.log.error).toHaveBeenCalledWith(
      expect.stringContaining('3 other EQL v3 column(s) remain'),
    )
    expect(writeFileMock).not.toHaveBeenCalled()
    expect(exitSpy).toHaveBeenCalledWith(1)
    exitSpy.mockRestore()
  })

  it('--uninstall-eql: on the last column, embeds the real uninstall SQL behind an apply-time re-check', async () => {
    await decryptDropCommand({
      table: 'users',
      column: 'email_encrypted',
      uninstallEql: true,
    })

    const sql = writtenSql() ?? ''
    const dropColumnAt = sql.indexOf(`EXECUTE 'ALTER TABLE`)
    expect(dropColumnAt).toBeGreaterThan(0)
    const recheckAt = sql.indexOf('SELECT count(*) INTO remaining_eql')
    const uninstallAt = sql.indexOf(
      `EXECUTE 'DROP SCHEMA IF EXISTS eql_v3 CASCADE'`,
    )
    expect(recheckAt).toBeGreaterThan(dropColumnAt)
    expect(uninstallAt).toBeGreaterThan(recheckAt)
    expect(sql).toContain(
      `EXECUTE 'DROP SCHEMA IF EXISTS eql_v3_internal CASCADE'`,
    )
    // The public column domains survive the uninstall script by design (they
    // sit outside the disposable schemas); a full exit removes them too,
    // without CASCADE.
    const domainsAt = sql.indexOf(
      `EXECUTE 'DROP DOMAIN IF EXISTS ' || leftover.name`,
    )
    expect(domainsAt).toBeGreaterThan(uninstallAt)
    expect(sql).not.toMatch(/DROP DOMAIN[^;]*CASCADE/)
    // Everything stays inside the one DO block.
    expect(sql.indexOf('END\n$stash_decrypt_drop$;')).toBeGreaterThan(
      uninstallAt,
    )
  })

  it('keeps the forward manifest entry and never says to edit it by hand', async () => {
    migrateMocks.readManifest.mockResolvedValue({
      version: 1,
      tables: {
        users: [{ column: 'email', encryptedColumn: 'email_encrypted' }],
      },
    })

    await decryptDropCommand({ table: 'users', column: 'email_encrypted' })

    // Generating is not applying: the apply-time check can still abort.
    expect(migrateMocks.removeManifestColumn).not.toHaveBeenCalled()
    const next = vi
      .mocked(p.note)
      .mock.calls.find(([, title]) => title === 'Next')?.[0]
    // The CLI owns .cipherstash/: the entry stays, and `encrypt status`
    // shows it as `reversed`. Nothing tells the user to edit the file.
    expect(next).not.toContain('migrations.json')
    expect(next).toContain(
      'Keep writing BOTH email_encrypted and email until it is applied',
    )
  })

  it('quotes unusual identifiers through both SQL layers and sanitises the filename', async () => {
    resolveMock.mockResolvedValue(
      pair({
        table: 'tenant.weird"table',
        encryptedColumn: "o'brien_encrypted",
        plaintextColumn: 'o"brien',
        migration: fakeMigration({
          history: [
            reverseEvent('decrypted', 'decrypted', {
              details: { plaintextColumn: 'o"brien' },
            }),
          ],
        }),
      }),
    )

    await decryptDropCommand({
      table: 'tenant.weird"table',
      column: "o'brien_encrypted",
    })

    const [filePath, sql] = writeFileMock.mock.calls[0] as [string, string]
    expect(sql).toContain('LOCK TABLE "tenant"."weird""table"')
    expect(sql).toContain(`"o'brien_encrypted" IS NOT NULL`)
    expect(sql).toContain(
      `EXECUTE 'ALTER TABLE "tenant"."weird""table" DROP COLUMN "o''brien_encrypted"'`,
    )
    expect(filePath).toMatch(
      /_drop_encrypted_tenant_weird_table_o_brien_encrypted\.sql$/,
    )
  })
})

describe('decrypt plan', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    detectMocks.detectDrizzle.mockReturnValue(false)
    detectMocks.detectPrismaNext.mockReturnValue(false)
    migrateMocks.columnHasValues.mockResolvedValue(false)
    resolveMock.mockResolvedValue(
      fresh({ plaintextSqlType: null, via: 'convention' }),
    )
  })

  it('builds nullable ADD COLUMN IF NOT EXISTS with the type mapped from the domain', () => {
    const sql = buildAddPlaintextSql('users', [
      {
        encryptedColumn: 'email_encrypted',
        domain: 'eql_v3_text_search',
        plaintextColumn: 'email',
        mapping: { sqlType: 'text' },
      },
      {
        encryptedColumn: 'created_encrypted',
        domain: 'eql_v3_timestamp_ord',
        plaintextColumn: 'created',
        mapping: { sqlType: 'timestamptz' },
      },
    ])
    expect(sql).toContain(
      'ALTER TABLE "users" ADD COLUMN IF NOT EXISTS "email" text;',
    )
    expect(sql).toContain(
      'ALTER TABLE "users" ADD COLUMN IF NOT EXISTS "created" timestamptz;',
    )
    expect(sql).not.toMatch(/NOT NULL/)
  })

  it('writes the twin migration for a non-Drizzle project', async () => {
    await decryptPlanCommand({ table: 'users' })

    const [filePath, sql] = writeFileMock.mock.calls[0] as [string, string]
    expect(filePath).toMatch(/_add_plaintext_users_email\.sql$/)
    expect(sql).toContain('ADD COLUMN IF NOT EXISTS "email" text')
  })

  it('Drizzle: prints the schema lines for drizzle-kit generate and writes nothing', async () => {
    detectMocks.detectDrizzle.mockReturnValue(true)

    await decryptPlanCommand({ table: 'users' })

    expect(writeFileMock).not.toHaveBeenCalled()
    expect(p.note).toHaveBeenCalledWith(
      expect.stringContaining("email: text('email'),"),
      'Drizzle schema change',
    )
  })

  it('--dry-run prints the SQL and writes nothing', async () => {
    await decryptPlanCommand({ table: 'users', dryRun: true })

    expect(writeFileMock).not.toHaveBeenCalled()
    expect(p.note).toHaveBeenCalledWith(
      expect.stringContaining('ADD COLUMN IF NOT EXISTS "email" text'),
      'Migration (dry run — not written)',
    )
  })

  it('adds nothing for an empty twin that already exists', async () => {
    resolveMock.mockResolvedValue(fresh())

    await decryptPlanCommand({ table: 'users' })

    expect(writeFileMock).not.toHaveBeenCalled()
    expect(p.log.info).toHaveBeenCalledWith(
      expect.stringContaining('already exists'),
    )
    expect(p.log.warn).not.toHaveBeenCalled()
  })

  it('warns, with the backfill refusal text, when an existing twin already holds values', async () => {
    resolveMock.mockResolvedValue(
      fresh({ migration: fakeMigration({ twinHasValues: true }) }),
    )

    await decryptPlanCommand({ table: 'users' })

    expect(writeFileMock).not.toHaveBeenCalled()
    const warning = vi.mocked(p.log.warn).mock.calls[0]?.[0] ?? ''
    expect(warning).toContain('users.email already holds values')
    expect(warning).toContain('--force')
    expect(warning).toContain('--confirm-plaintext-current')
    expect(p.note).toHaveBeenCalledWith(
      expect.stringContaining(
        'stash decrypt backfill --table users --column email_encrypted <--force | --confirm-plaintext-current>',
      ),
      'Next',
    )
  })

  it('warns that the backfill will refuse a twin whose forward migration was never dropped', async () => {
    resolveMock.mockResolvedValue(
      fresh({
        migration: fakeMigration({
          blockedBy: forwardOpen,
          twinHasValues: true,
        }),
      }),
    )

    await decryptPlanCommand({ table: 'users' })

    const warning = vi.mocked(p.log.warn).mock.calls[0]?.[0] ?? ''
    expect(warning).toContain('`stash decrypt backfill` will refuse')
    expect(warning).toContain("still open at 'backfilled'")
    expect(warning).toContain('stash encrypt drop')
  })

  it('closes an open forward migration whose source column was removed outside stash', async () => {
    resolveMock.mockResolvedValue(
      fresh({
        plaintextSqlType: null,
        via: 'convention',
        migration: fakeMigration({ blockedBy: forwardOpen }),
      }),
    )
    const recordSourceRemoved = vi.fn(async () => ({}))
    forwardLoad.mockResolvedValue({ recordSourceRemoved })

    await decryptPlanCommand({ table: 'users' })

    expect(forwardLoad).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({
        table: 'users',
        column: 'email',
        direction: 'forward',
        twin: 'email_encrypted',
      }),
    )
    expect(recordSourceRemoved).toHaveBeenCalledWith({
      recordedBy: 'stash decrypt plan',
    })
    expect(p.log.info).toHaveBeenCalledWith(
      expect.stringContaining("still open at 'backfilled'"),
    )
    // The twin is still planned.
    const [, sql] = writeFileMock.mock.calls[0] as [string, string]
    expect(sql).toContain('ADD COLUMN IF NOT EXISTS "email" text')
  })

  it('--dry-run records nothing for a removed forward source', async () => {
    resolveMock.mockResolvedValue(
      fresh({
        plaintextSqlType: null,
        via: 'convention',
        migration: fakeMigration({ blockedBy: forwardOpen }),
      }),
    )

    await decryptPlanCommand({ table: 'users', dryRun: true })

    expect(forwardLoad).not.toHaveBeenCalled()
    expect(p.log.info).toHaveBeenCalledWith(
      expect.stringContaining('would record'),
    )
  })

  it('records nothing for a missing twin with no open forward migration', async () => {
    resolveMock.mockResolvedValue(
      fresh({ plaintextSqlType: null, via: 'convention' }),
    )

    await decryptPlanCommand({ table: 'users' })

    expect(forwardLoad).not.toHaveBeenCalled()
  })

  it('does not second-guess a twin the reverse column migration in progress filled', async () => {
    resolveMock.mockResolvedValue(
      pair({
        migration: fakeMigration({ history: inFlight(), twinHasValues: true }),
      }),
    )

    await decryptPlanCommand({ table: 'users' })

    expect(p.log.warn).not.toHaveBeenCalled()
  })

  it('overview: one line per EQL v3 column, surfacing pairings it cannot resolve', async () => {
    // `fetchPhysicalColumns`' information_schema read.
    queryMock.mockResolvedValueOnce({
      rows: [
        { table_name: 'users', column_name: 'id', domain_name: null },
        {
          table_name: 'users',
          column_name: 'email_encrypted',
          domain_name: 'eql_v3_text_search',
        },
        {
          table_name: 'users',
          column_name: 'note_encrypted',
          domain_name: 'eql_v3_text',
        },
      ],
    })
    resolveMock
      .mockResolvedValueOnce(
        fresh({ plaintextSqlType: null, via: 'convention' }),
      )
      .mockRejectedValueOnce(
        new BackfillConfigError('users.note is itself an EQL v3 column'),
      )

    await decryptPlanCommand()

    const overview = vi
      .mocked(p.note)
      .mock.calls.find(([, title]) => title === 'Reverse plan')?.[0]
    expect(overview).toContain(
      '+ users.email_encrypted (eql_v3_text_search) → email text',
    )
    expect(overview).toContain(
      '! users.note_encrypted: users.note is itself an EQL v3 column',
    )
    expect(writeFileMock).not.toHaveBeenCalled()
  })

  it('refuses a domain with no known plaintext type instead of inventing one', async () => {
    resolveMock.mockResolvedValue(
      pair({ mapping: null, domain: 'eql_v3_uuid_eq', plaintextSqlType: null }),
    )
    const exitSpy = spyExit()

    await decryptPlanCommand({ table: 'users', column: 'email_encrypted' })

    expect(p.log.error).toHaveBeenCalledWith(
      expect.stringContaining('No plaintext type is known'),
    )
    expect(writeFileMock).not.toHaveBeenCalled()
    expect(exitSpy).toHaveBeenCalledWith(1)
    exitSpy.mockRestore()
  })
})
