/**
 * `validateCommand` / `tryReadObservedState` — the top-level orchestration of
 * `stash eql validate`, which the rule suite next door cannot reach.
 *
 * A SEPARATE file from `validate.test.ts` on purpose. That one is a pure suite:
 * it calls the exported rule functions directly and mocks nothing but clack.
 * This one has to replace the config loader, the encryption-client loader and
 * the `pg` driver, and intercept `process.exit`. `vi.mock` is hoisted and
 * file-wide, so folding these in would silently apply them to every pure test
 * over there — a loader stub those rules never asked for, and a `process.exit`
 * that throws instead of exiting. Keeping the mocked half here is what keeps
 * the pure half readable as pure.
 *
 * The e2e smoke test covers `eql validate` only as far as its config load
 * failing ("Could not find stash.config.ts"), so everything past
 * `loadStashConfig` — the degraded-`getSchemas()` warning, the no-database
 * notice, the connect-error catch, and the exit-code contract — is asserted
 * here or nowhere.
 */

import type { AnyV3Table } from '@cipherstash/stack/eql/v3'
import { encryptedTable, types } from '@cipherstash/stack/eql/v3'
import type { EncryptConfig } from '@cipherstash/stack/schema'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { validateCommand } from '../validate.js'

// clack is chrome — silence it and spy on the channels the command reports
// through. Same shape as the mock in `repair.test.ts` and `validate.test.ts`.
const clack = vi.hoisted(() => ({
  spinnerInstance: { start: vi.fn(), stop: vi.fn() },
  log: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    success: vi.fn(),
    step: vi.fn(),
  },
  intro: vi.fn(),
  note: vi.fn(),
  outro: vi.fn(),
}))
vi.mock('@clack/prompts', () => ({
  spinner: vi.fn(() => clack.spinnerInstance),
  log: clack.log,
  intro: clack.intro,
  note: clack.note,
  outro: clack.outro,
}))

/**
 * The command's two inputs, both of which normally come off the user's disk
 * through jiti. Faking them is what lets the orchestration be driven through
 * states no fixture project can reach on demand: an installed
 * `@cipherstash/stack` that predates `getSchemas()`, or a config whose
 * `databaseUrl` resolved to nothing.
 */
const loaders = vi.hoisted(() => ({
  loadStashConfig: vi.fn(),
  loadEncryptSchemas: vi.fn(),
}))
vi.mock('@/config/index.js', () => ({
  loadStashConfig: loaders.loadStashConfig,
  loadEncryptSchemas: loaders.loadEncryptSchemas,
}))

// Fake the DRIVER, not `readObservedState` — the real catalogue SQL, the real
// six-way `Promise.all`, and the real `fetchPhysicalColumns` all stay under
// test, which is precisely the wiring at issue here.
const pgMock = vi.hoisted(() => ({
  connect: vi.fn(),
  query: vi.fn(),
  end: vi.fn(),
  connectionStrings: [] as (string | undefined)[],
}))
vi.mock('pg', () => ({
  default: {
    Client: vi.fn((config: { connectionString?: string }) => {
      pgMock.connectionStrings.push(config?.connectionString)
      return { connect: pgMock.connect, query: pgMock.query, end: pgMock.end }
    }),
  },
}))

/**
 * `process.exit` is intercepted by THROWING, not by returning a stub value.
 * The real call never returns, so a stub that does would let whatever follows
 * it run under assertions written for a process that had stopped.
 * `validateCommand` has no `catch`, so the sentinel unwinds straight out to
 * the test — and `rejects.toBeInstanceOf(ProcessExited)` then asserts the
 * command really did terminate there rather than merely log.
 */
class ProcessExited extends Error {
  constructor(readonly code: number | string | null | undefined) {
    super(`process.exit(${String(code)})`)
  }
}
const exitSpy = vi.spyOn(process, 'exit').mockImplementation((code): never => {
  throw new ProcessExited(code)
})

/** The blank line the command prints to separate the header from the report. */
const consoleLog = vi.spyOn(console, 'log').mockImplementation(() => {})

const CLIENT = './src/encryption/index.ts'
const DATABASE_URL = 'postgres://user:pw@localhost:5432/app'

/** The `EncryptConfig` shape the degraded, config-only path reads. */
const configWith = (columns: EncryptConfig['tables'][string]): EncryptConfig =>
  ({ v: 1, tables: { t: columns } }) as EncryptConfig

const EMPTY_CONFIG = { v: 1, tables: {} } as EncryptConfig

/**
 * Stage the command's inputs.
 *
 * `databaseUrl` defaults to empty, i.e. offline: that is the state most of
 * these tests want, and a test that needs a database has to say so — which
 * also means no test reaches a real socket by forgetting to.
 *
 * Leaving `schemas` unset is not "no tables"; it is the degraded path, exactly
 * as `loadEncryptSchemas` reports a client with no `getSchemas()`.
 */
function given(input: {
  schemas?: readonly AnyV3Table[]
  config?: EncryptConfig
  databaseUrl?: string
}): void {
  loaders.loadStashConfig.mockResolvedValue({
    client: CLIENT,
    databaseUrl: input.databaseUrl ?? '',
  })
  loaders.loadEncryptSchemas.mockResolvedValue({
    config: input.config ?? EMPTY_CONFIG,
    schemas: input.schemas,
  })
}

/**
 * Answer each catalogue read by the result ALIAS it selects, the way
 * `validate.test.ts` routes its own fake client. Not by table name: three of
 * the six reads mention `current_schema()`, so a looser match feeds one read's
 * rows to another read's parser and the mistake is invisible (an unexpected
 * shape simply parses to nothing).
 */
function respondWith(rowsByAlias: Record<string, unknown[]>): void {
  pgMock.query.mockImplementation((text: string) => {
    const alias = Object.keys(rowsByAlias).find((key) => text.includes(key))
    return Promise.resolve({ rows: alias ? rowsByAlias[alias] : [] })
  })
}

/** A database in which everything the schema declares is present and correct. */
const healthyDatabase = (
  columns: Array<{
    table_name: string
    column_name: string
    domain_name: string | null
  }>,
) => ({
  'AS eql_installed': [{ eql_installed: true }],
  'AS ore_available': [{ ore_available: true }],
  'AS searched_schema': [
    { searched_schema: 'public', connected_role: 'app_rw' },
  ],
  'AS relation_schema': [
    ...new Set(columns.map((column) => column.table_name)),
  ].map((table_name) => ({
    table_name,
    relation_schema: 'public',
    is_searched_schema: true,
  })),
  'information_schema.columns': columns,
  pg_get_indexdef: [],
})

beforeEach(() => {
  vi.clearAllMocks()
  // Implementations, unlike call records, survive `clearAllMocks` — reset the
  // driver doubles so one test's routing table cannot answer the next one's
  // queries.
  pgMock.query.mockReset().mockResolvedValue({ rows: [] })
  pgMock.connect.mockReset().mockResolvedValue(undefined)
  pgMock.end.mockReset().mockResolvedValue(undefined)
  pgMock.connectionStrings.length = 0
})

describe('validateCommand — loading', () => {
  it('threads the CLI flags into the config load and loads the declared client', async () => {
    given({
      schemas: [encryptedTable('users', { email: types.TextSearch('email') })],
    })

    await validateCommand({ databaseUrl: 'postgres://flag', supabase: true })

    // Both flags exist to reach the user's own `resolveDatabaseUrl()` during
    // config evaluation; dropping either here is silent, because the command
    // still works against whatever `DATABASE_URL` happens to be exported.
    expect(loaders.loadStashConfig).toHaveBeenCalledWith({
      databaseUrlFlag: 'postgres://flag',
      supabase: true,
    })
    expect(loaders.loadEncryptSchemas).toHaveBeenCalledWith(CLIENT)
  })

  it.each([
    {
      name: 'pluralises the table and column counts',
      schemas: [
        encryptedTable('users', {
          email: types.TextSearch('email'),
          age: types.IntegerOrd('age'),
        }),
        encryptedTable('orders', { total: types.IntegerOrd('total') }),
      ],
      expected: 'Schema loaded: 2 tables, 3 encrypted columns',
    },
    {
      name: 'keeps both counts singular for one column on one table',
      schemas: [encryptedTable('users', { email: types.TextSearch('email') })],
      expected: 'Schema loaded: 1 table, 1 encrypted column',
    },
  ])('$name', async ({ schemas, expected }) => {
    given({ schemas })

    await validateCommand({})

    expect(clack.log.success).toHaveBeenCalledWith(expected)
  })

  /**
   * The CLI and the project's `@cipherstash/stack` version independently, so a
   * client with no `getSchemas()` is a real customer state. It must degrade to
   * the config-only rules and SAY which rules that cost — silently running a
   * subset would report a clean bill of health for checks that never ran.
   */
  it('warns that the domain checks were skipped when getSchemas() is unavailable', async () => {
    given({
      config: configWith({
        email: { cast_as: 'string', indexes: { unique: {} } },
      }),
    })

    await validateCommand({})

    expect(clack.log.warn).toHaveBeenCalledWith(
      expect.stringContaining('does not expose `getSchemas()`'),
    )
    // And the columns still came from somewhere: the config-only collection.
    expect(clack.log.success).toHaveBeenCalledWith(
      'Schema loaded: 1 table, 1 encrypted column',
    )
  })

  // The discriminating half — without it, a warning printed unconditionally
  // would pass the test above and tell every user their domain checks were
  // skipped when they were not.
  it('says nothing about getSchemas() when the client exposes it', async () => {
    given({
      schemas: [encryptedTable('users', { email: types.TextSearch('email') })],
    })

    await validateCommand({})

    expect(clack.log.warn).not.toHaveBeenCalled()
  })
})

describe('validateCommand — reaching the database', () => {
  /**
   * The schema rules are worth running on a laptop with no database up, so a
   * missing URL downgrades to schema-only rather than failing. Silence would
   * be the bug: the user would read a clean report as "no drift" when drift
   * was never looked for.
   */
  it('skips the database checks, and says so, when no database URL resolved', async () => {
    given({
      schemas: [encryptedTable('users', { email: types.TextSearch('email') })],
      databaseUrl: '',
    })

    await expect(validateCommand({})).resolves.toBeUndefined()

    expect(clack.log.info).toHaveBeenCalledWith(
      expect.stringContaining('No database URL resolved'),
    )
    // Actionable, not just apologetic.
    expect(clack.log.info).toHaveBeenCalledWith(
      expect.stringContaining('--database-url'),
    )
    // Stronger than "did not read": no connection was opened at all.
    expect(pgMock.connectionStrings).toEqual([])
    expect(pgMock.connect).not.toHaveBeenCalled()
    expect(exitSpy).not.toHaveBeenCalled()
  })

  /**
   * Same posture for a URL that is present but unreachable — and this is the
   * half that has to be checked twice. Degrading means returning `undefined`,
   * NOT handing the rules a blank `ObservedState`: an all-empty observation
   * reads as `eqlInstalled: false`, which is an error, which would exit 1 over
   * a database nobody ever managed to read.
   */
  it('degrades to the schema checks when the database cannot be reached', async () => {
    given({
      schemas: [encryptedTable('users', { email: types.TextSearch('email') })],
      databaseUrl: DATABASE_URL,
    })
    pgMock.connect.mockRejectedValue(
      new Error('connect ECONNREFUSED 127.0.0.1:5432'),
    )

    await expect(validateCommand({})).resolves.toBeUndefined()

    expect(clack.log.info).toHaveBeenCalledWith(
      expect.stringContaining(
        'Could not read the database (connect ECONNREFUSED 127.0.0.1:5432)',
      ),
    )
    // The schema rules found nothing, and the unreachable database added
    // nothing — a skipped database check is never itself a failure.
    expect(clack.log.error).not.toHaveBeenCalled()
    expect(clack.outro).toHaveBeenCalledWith('No issues found.')
    expect(exitSpy).not.toHaveBeenCalled()
    // The socket is closed on the failing path too.
    expect(pgMock.end).toHaveBeenCalled()
  })

  // A query that fails after a successful connect lands in the same catch, and
  // must be reported the same way: the read is what matters, not which half of
  // it broke.
  it('degrades the same way when the catalogue read itself fails', async () => {
    given({
      schemas: [encryptedTable('users', { email: types.TextSearch('email') })],
      databaseUrl: DATABASE_URL,
    })
    pgMock.query.mockRejectedValue(
      Object.assign(new Error('permission denied for schema pg_catalog'), {
        code: '42501',
      }),
    )

    await expect(validateCommand({})).resolves.toBeUndefined()

    expect(clack.log.info).toHaveBeenCalledWith(
      expect.stringContaining('permission denied for schema pg_catalog'),
    )
    expect(exitSpy).not.toHaveBeenCalled()
  })

  /**
   * The happy path: connect, read, and let the database rules run. Asserted
   * through a drift the schema rules alone cannot produce, so it cannot pass
   * on a build where `readObservedState` was never called.
   */
  it('validates against the live database when it can connect', async () => {
    given({
      schemas: [encryptedTable('users', { email: types.TextSearch('email') })],
      databaseUrl: DATABASE_URL,
    })
    respondWith(
      healthyDatabase([
        // The migration wrote the equality domain; the schema declares search.
        {
          table_name: 'users',
          column_name: 'email',
          domain_name: 'eql_v3_text_eq',
        },
      ]),
    )

    await expect(validateCommand({})).rejects.toBeInstanceOf(ProcessExited)

    expect(pgMock.connectionStrings).toEqual([DATABASE_URL])
    expect(clack.log.error).toHaveBeenCalledWith(
      expect.stringContaining(
        'users.email: Declared `public.eql_v3_text_search` but the database column is `eql_v3_text_eq`',
      ),
    )
    expect(exitSpy).toHaveBeenCalledWith(1)
    expect(pgMock.end).toHaveBeenCalled()
  })

  // The other side of the same wiring: a database that agrees with the schema
  // must produce no database findings, so the drift assertion above is a fact
  // about the read and not about the fixture always disagreeing.
  it('reports no drift when the live database matches the declaration', async () => {
    given({
      schemas: [encryptedTable('users', { email: types.TextSearch('email') })],
      databaseUrl: DATABASE_URL,
    })
    respondWith(
      healthyDatabase([
        {
          table_name: 'users',
          column_name: 'email',
          domain_name: 'eql_v3_text_search',
        },
      ]),
    )

    await expect(validateCommand({})).resolves.toBeUndefined()

    // Pinned against the read actually happening: "no findings" is also what a
    // command that never opened the database would print, so the six catalogue
    // reads are what make this a statement about a clean database.
    expect(pgMock.query).toHaveBeenCalledTimes(6)
    expect(clack.log.error).not.toHaveBeenCalled()
    expect(exitSpy).not.toHaveBeenCalled()
  })
})

/**
 * The exit-code contract. `reportIssues` returning `true` on an error already
 * has coverage next door; what is asserted here is the WIRING from that
 * boolean to the process's exit status — the only thing CI can see.
 */
describe('validateCommand — exit code', () => {
  it('exits 1 when the report contains an error', async () => {
    // A searchable boolean. No `types.*` factory can build one, so it arrives
    // on the config-only path — and it is an error: with two possible values,
    // an equality term is a direct read of the plaintext.
    given({
      config: configWith({
        flag: { cast_as: 'boolean', indexes: { unique: {} } },
      }),
    })

    await expect(validateCommand({})).rejects.toBeInstanceOf(ProcessExited)

    expect(clack.log.error).toHaveBeenCalledWith(
      expect.stringContaining('searchable boolean column leaks'),
    )
    expect(exitSpy).toHaveBeenCalledTimes(1)
    expect(exitSpy).toHaveBeenCalledWith(1)
  })

  /**
   * The discriminating half, and the reason both directions are pinned: an
   * unconditional `process.exit(1)` after the report would pass the test above
   * and turn every portability warning and every "no functional index" hint
   * into a red build.
   */
  it('does not exit when the worst finding is a warning or an info', async () => {
    given({
      schemas: [
        encryptedTable('t', {
          age: types.IntegerOrdOre('age'), // warning: ORE needs a superuser
          notes: types.Text('notes'), // info: storage-only
        }),
      ],
    })

    await expect(validateCommand({})).resolves.toBeUndefined()

    // Non-vacuous: findings really were produced and really were printed, so
    // "did not exit" is a statement about the gate and not about an empty run.
    expect(clack.log.warn).toHaveBeenCalledWith(
      expect.stringContaining(
        't.age: eql_v3_integer_ord_ore needs the ORE btree operator class',
      ),
    )
    expect(clack.log.info).toHaveBeenCalledWith(
      expect.stringContaining('t.notes: Storage-only column'),
    )
    expect(clack.outro).toHaveBeenCalledWith('No errors found. 1 warning.')
    expect(exitSpy).not.toHaveBeenCalled()
  })

  /**
   * Zero findings returns before the report is printed at all. Worth its own
   * test because the two paths render the SAME outro — only the blank-line
   * separator, which exists solely to precede a list of issues, tells them
   * apart.
   */
  it('closes with "No issues found." without printing a report', async () => {
    given({
      schemas: [encryptedTable('users', { email: types.TextSearch('email') })],
    })

    await expect(validateCommand({})).resolves.toBeUndefined()

    expect(clack.outro).toHaveBeenCalledTimes(1)
    expect(clack.outro).toHaveBeenCalledWith('No issues found.')
    expect(consoleLog).not.toHaveBeenCalled()
    expect(exitSpy).not.toHaveBeenCalled()
  })
})
