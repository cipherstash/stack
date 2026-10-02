import { encryptedTable, types } from '@cipherstash/stack/eql/v3'
import type { EncryptConfig } from '@cipherstash/stack/schema'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  collectDeclaredColumns,
  collectDeclaredColumnsFromConfig,
  expectedExtractors,
  type ObservedState,
  parseIndexedExtractors,
  readObservedState,
  reportIssues,
  type ValidationIssue,
  validateSchemas,
} from '../validate.js'

// clack is chrome — silence it and spy on the channels `reportIssues` prints
// through. Same shape as the mock in `repair.test.ts`; `spinner` and `intro`
// are here because the module under test imports the whole namespace.
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
 * Built from real `encryptedTable` / `types.*` schemas, not hand-written
 * encrypt configs. The rules key off the concrete domain, which only the real
 * factories produce — a hand-built fixture would let a factory change drift
 * away from what validate is told to expect.
 *
 * The database rules take their facts through an injected {@link ObservedState}
 * rather than a live connection, so drift, ORE availability and missing
 * functional indexes all have coverage with no database.
 */

/** An `ObservedState` in which everything the schema declares is present and correct. */
function observing(
  columns: Record<string, Record<string, string | null>>,
  overrides: Partial<ObservedState> = {},
): ObservedState {
  return {
    eqlInstalled: true,
    oreAvailable: true,
    searchedSchema: 'public',
    connectedRole: 'app_rw',
    elsewhere: new Map(),
    // A table whose columns `information_schema` reports is by definition one
    // `pg_class` has too, so the default tracks the visible set. Overriding
    // just this one is what produces the privilege-invisible case.
    searchedSchemaRelations: new Set(Object.keys(columns)),
    columns: new Map(
      Object.entries(columns).map(([table, cols]) => [
        table,
        new Map(Object.entries(cols)),
      ]),
    ),
    indexedExtractors: new Map(),
    ...overrides,
  }
}

/**
 * A one-table encrypt config, for the degraded config-only collection path.
 *
 * This is the shape `collectDeclaredColumnsFromConfig` reads when the project's
 * `@cipherstash/stack` predates `getSchemas()`, so every column it yields has
 * `eqlType: undefined` — which is exactly what the domain-less renderings of
 * the database findings need, and why this lives at module scope rather than
 * inside the hand-authored-config block that first needed it.
 */
const configWith = (columns: EncryptConfig['tables'][string]): EncryptConfig =>
  ({ v: 1, tables: { t: columns } }) as EncryptConfig

/** Every functional index a set of declared columns could want. */
function fullyIndexed(
  columns: ReturnType<typeof collectDeclaredColumns>,
): Map<string, Set<string>> {
  return new Map(
    columns.map((column) => [
      `${column.table}.${column.column}`,
      new Set(expectedExtractors(column.indexes)),
    ]),
  )
}

describe('the regression this command was rewritten for', () => {
  it('reports nothing for the default ordering domains', () => {
    // EQL v2's `hasAnyIndex` checked `ore` / `unique` / `match` / `ste_vec` and
    // never learned about `ope`. EQL v3's `_ord` domains emit `ope`, so both of
    // these were reported as "Column is encrypted but has no indexes — it will
    // not be searchable" — for two of the most ordinary columns anyone writes.
    const users = encryptedTable('users', {
      age: types.IntegerOrd('age'),
      createdAt: types.TimestampOrd('created_at'),
    })

    expect(validateSchemas(collectDeclaredColumns([users]))).toEqual([])
  })

  it('still reports a genuinely storage-only column', () => {
    const users = encryptedTable('users', {
      notes: types.Text('notes'),
    })

    expect(validateSchemas(collectDeclaredColumns([users]))).toEqual([
      {
        severity: 'info',
        table: 'users',
        column: 'notes',
        message: expect.stringContaining('Storage-only column'),
      },
    ])
  })
})

describe('collectDeclaredColumns', () => {
  it('flattens the tuple, keyed by DB column name and carrying the domain', () => {
    const users = encryptedTable('users', {
      email: types.TextSearch('email'),
      // camelCase property, snake_case column: the DB name is what the
      // database reports back, so it is what must be collected.
      createdAt: types.TimestampOrd('created_at'),
    })
    const orders = encryptedTable('orders', {
      total: types.NumericOrd('total'),
    })

    expect(collectDeclaredColumns([users, orders])).toEqual([
      {
        table: 'users',
        column: 'email',
        eqlType: 'public.eql_v3_text_search',
        cast_as: 'string',
        queryable: true,
        indexes: expect.objectContaining({ unique: expect.anything() }),
      },
      {
        table: 'users',
        column: 'created_at',
        eqlType: 'public.eql_v3_timestamp_ord',
        cast_as: 'timestamp',
        queryable: true,
        indexes: { ope: {} },
      },
      {
        table: 'orders',
        column: 'total',
        eqlType: 'public.eql_v3_numeric_ord',
        cast_as: 'number',
        queryable: true,
        indexes: { ope: {} },
      },
    ])
  })
})

describe('schema rules (no database)', () => {
  const cases: Array<{
    name: string
    columns: ReturnType<typeof collectDeclaredColumns>
    expected: Array<{ severity: string; column?: string; match: RegExp }>
  }> = [
    {
      name: 'a fully searchable text column is clean',
      columns: collectDeclaredColumns([
        encryptedTable('users', { email: types.TextSearch('email') }),
      ]),
      expected: [],
    },
    {
      name: 'equality, match and json domains are clean',
      columns: collectDeclaredColumns([
        encryptedTable('users', {
          email: types.TextEq('email'),
          bio: types.TextMatch('bio'),
          profile: types.Json('profile'),
        }),
      ]),
      expected: [],
    },
    {
      name: 'an _ord_ore domain warns about the superuser-only operator class',
      columns: collectDeclaredColumns([
        encryptedTable('users', { age: types.IntegerOrdOre('age') }),
      ]),
      expected: [
        {
          severity: 'warning',
          column: 'age',
          match: /eql_v3_integer_ord_ore needs the ORE btree operator class/,
        },
      ],
    },
    {
      name: 'the _ord_ore warning names the OPE twin to switch to',
      columns: collectDeclaredColumns([
        encryptedTable('t', { at: types.TimestampOrdOre('at') }),
      ]),
      expected: [
        {
          severity: 'warning',
          column: 'at',
          match: /Use eql_v3_timestamp_ord unless/,
        },
      ],
    },
    {
      name: 'storage-only domains are reported as Info, one per column',
      columns: collectDeclaredColumns([
        encryptedTable('users', {
          notes: types.Text('notes'),
          verified: types.Boolean('verified'),
        }),
      ]),
      expected: [
        { severity: 'info', column: 'notes', match: /Storage-only column/ },
        { severity: 'info', column: 'verified', match: /Storage-only column/ },
      ],
    },
  ]

  it.each(cases)('$name', ({ columns, expected }) => {
    const issues = validateSchemas(columns)

    expect(issues).toHaveLength(expected.length)
    for (const [i, want] of expected.entries()) {
      expect(issues[i].severity).toBe(want.severity)
      if (want.column) expect(issues[i].column).toBe(want.column)
      expect(issues[i].message).toMatch(want.match)
    }
  })

  it('reports every domain in the catalog without crashing', () => {
    // A blunt sweep: whatever the rules decide, no factory may throw and every
    // issue must name a real column. Guards against a rule that dereferences a
    // field only some domains carry.
    const table = encryptedTable('everything', {
      a: types.Integer('a'),
      b: types.IntegerEq('b'),
      c: types.IntegerOrd('c'),
      d: types.IntegerOrdOre('d'),
      e: types.Text('e'),
      f: types.TextEq('f'),
      g: types.TextMatch('g'),
      h: types.TextOrd('h'),
      i: types.TextOrdOre('i'),
      j: types.TextSearch('j'),
      k: types.Boolean('k'),
      l: types.Json('l'),
      m: types.BigintOrd('m'),
      n: types.DateOrd('n'),
      o: types.RealOrd('o'),
      p: types.DoubleOrd('p'),
      q: types.SmallintOrd('q'),
      r: types.NumericOrd('r'),
    })
    const columns = collectDeclaredColumns([table])
    const issues = validateSchemas(columns)

    const declared = new Set(columns.map((column) => column.column))
    for (const issue of issues) {
      expect(declared.has(issue.column ?? '')).toBe(true)
    }
    // No error is constructible through `types.*` — every finding here is a
    // Warning (the two `_ord_ore` domains) or an Info (the three storage-only
    // ones).
    expect(issues.filter((issue) => issue.severity === 'error')).toEqual([])
    expect(issues.filter((issue) => issue.severity === 'warning')).toHaveLength(
      2,
    )
    expect(issues.filter((issue) => issue.severity === 'info')).toHaveLength(3)
  })
})

describe('schema rules that guard hand-authored configs', () => {
  /**
   * Neither of these is constructible through `types.*` — `types.Boolean` is
   * storage-only by construction and `match` is emitted only by text domains.
   * They exist for an encrypt config written by hand or emitted by an older
   * generator, so they are exercised through the config-only collection path,
   * which is the one such a config actually arrives on.
   */
  it('rejects a searchable boolean', () => {
    const columns = collectDeclaredColumnsFromConfig(
      configWith({ flag: { cast_as: 'boolean', indexes: { unique: {} } } }),
    )

    expect(validateSchemas(columns)).toEqual([
      {
        severity: 'error',
        table: 't',
        column: 'flag',
        message: expect.stringContaining('searchable boolean column leaks'),
      },
    ])
  })

  it('rejects a match index on a non-text domain', () => {
    const columns = collectDeclaredColumnsFromConfig(
      configWith({ n: { cast_as: 'number', indexes: { match: {} } } }),
    )

    expect(validateSchemas(columns)).toEqual([
      {
        severity: 'error',
        table: 't',
        column: 'n',
        message: expect.stringContaining('Free-text match needs a text domain'),
      },
    ])
  })

  it('rejects ste_vec without a json cast', () => {
    // `prefix` is required on a `ste_vec` index and `EncryptedTable.build()`
    // rewrites its `'enabled'` sentinel to `${table}/${column}`, so a real
    // emitted config carries `'t/doc'` here. It is beside the point of this
    // test — the rule keys off `cast_as` — but the config is a typed value and
    // spelling it right is cheaper than a cast that erases the type.
    const columns = collectDeclaredColumnsFromConfig(
      configWith({
        doc: { cast_as: 'string', indexes: { ste_vec: { prefix: 't/doc' } } },
      }),
    )

    expect(validateSchemas(columns)).toEqual([
      {
        severity: 'error',
        table: 't',
        column: 'doc',
        message: expect.stringContaining('Encrypted-JSONB search needs'),
      },
    ])
  })

  it('cannot report domain rules without a domain', () => {
    // The degraded path drops `eqlType`, so the ORE steer must not fire on a
    // config-only load — it would have nothing to base the claim on.
    const columns = collectDeclaredColumnsFromConfig(
      configWith({ age: { cast_as: 'number', indexes: { ore: {} } } }),
    )

    expect(validateSchemas(columns)).toEqual([])
  })
})

describe('database rules', () => {
  const users = encryptedTable('users', {
    email: types.TextSearch('email'),
    age: types.IntegerOrd('age'),
  })
  const columns = collectDeclaredColumns([users])
  const healthy = {
    users: {
      email: 'eql_v3_text_search',
      age: 'eql_v3_integer_ord',
    },
  }

  it('is silent when the database matches the schema and is fully indexed', () => {
    const observed = observing(healthy, {
      indexedExtractors: fullyIndexed(columns),
    })

    expect(validateSchemas(columns, observed)).toEqual([])
  })

  /**
   * A bare declared name resolves through `search_path`, so when the same name
   * exists in the searched schema AND somewhere else, the declaration does not
   * pin which relation the application actually reads — `auth.users` versus
   * `public.users` on Supabase is the case everyone meets. Validate checked one
   * of them and said nothing about having chosen.
   *
   * Info, not warning, for three reasons: `info` does not touch the exit code;
   * `auth.users` exists in every Supabase project, so a warning would report
   * healthy projects as not-clean; and the warning bucket means "nothing was
   * checked", whereas this run did check something and is qualifying WHICH.
   *
   * The fixture is the healthy one above, byte for byte, plus the `elsewhere`
   * override — that test asserts `toEqual([])`, so it is simultaneously the
   * proof this finding is new and the negative control against the rule
   * degenerating into "always fires".
   */
  it('notes which relation it checked when the table name is shadowed', () => {
    const observed = observing(healthy, {
      indexedExtractors: fullyIndexed(columns),
      elsewhere: new Map([['users', ['auth']]]),
    })

    const issues = validateSchemas(columns, observed)

    expect(issues).toEqual([
      {
        severity: 'info',
        table: 'users',
        message: expect.stringContaining('also exists in schema "auth"'),
      },
    ])
    // Naming only the others leaves the reader no better off: the finding has
    // to say which relation the findings around it actually describe.
    expect(issues[0].message).toContain('"public"."users"')
    expect(issues[0].message).toContain('search_path%3Dauth')
  })

  it('names every other schema holding the shadowed name', () => {
    const observed = observing(healthy, {
      indexedExtractors: fullyIndexed(columns),
      elsewhere: new Map([['users', ['auth', 'archive']]]),
    })

    const [issue] = validateSchemas(columns, observed)

    expect(issue.message).toContain('"auth" / "archive"')
  })

  /**
   * The finding qualifies the column findings for its table, so it has to
   * precede them — the ordering contract `validateSchemas` documents. Asserted
   * structurally rather than by message, so a finding appended after the column
   * loop (the obvious way to write this rule) fails here.
   */
  it('places the shadowing note ahead of the column findings it qualifies', () => {
    const observed = observing(healthy, {
      elsewhere: new Map([['users', ['auth']]]),
    })

    expect(
      validateSchemas(columns, observed).map((issue) => [
        issue.severity,
        issue.column,
      ]),
    ).toEqual([
      ['info', undefined],
      ['info', 'email'],
      ['info', 'age'],
    ])
  })

  /**
   * The unreachable branch already reports a table that is ONLY elsewhere, and
   * says far more about it than this rule could. Both firing would print two
   * findings that contradict each other on whether anything was checked.
   */
  it('says nothing when the table is only elsewhere, leaving that to the warning', () => {
    const observed = observing(
      {},
      {
        elsewhere: new Map([['users', ['app']]]),
        indexedExtractors: fullyIndexed(columns),
      },
    )

    const issues = validateSchemas(columns, observed)

    expect(issues).toHaveLength(1)
    expect(issues[0].severity).toBe('warning')
  })

  /**
   * A table absent from the privilege-filtered `columns` read is FOUR different
   * situations, and only the last is a failure of the project's migrations:
   *
   * - declared `schema.table`, which neither read can match (its own finding);
   * - present in the searched schema but invisible to the role (a grant);
   * - present in another schema — Prisma `multiSchema`, a tenant schema — so
   *   the project is healthy and merely pointed at the wrong `search_path`;
   * - present nowhere, so the migration genuinely has not run.
   *
   * Only the last may fail the command. This case is the third.
   */
  it('warns, naming the schema that has the table, when it is merely elsewhere', () => {
    const observed = observing(
      {},
      {
        elsewhere: new Map([['users', ['app']]]),
        indexedExtractors: fullyIndexed(columns),
      },
    )

    expect(validateSchemas(columns, observed)).toEqual([
      {
        severity: 'warning',
        table: 'users',
        message: expect.stringContaining(
          'exists in schema "app", not in "public"',
        ),
      },
    ])
  })

  it('errors when the table exists in no schema at all', () => {
    const observed = observing({}, { indexedExtractors: fullyIndexed(columns) })

    expect(validateSchemas(columns, observed)).toEqual([
      {
        severity: 'error',
        table: 'users',
        message: expect.stringContaining('does not exist in any schema'),
      },
    ])
  })

  /**
   * The third state, and the one that produced a confidently-wrong Error.
   *
   * `columns` comes from `information_schema`, which PostgreSQL filters to
   * objects the connected role has privileges on; `searchedSchemaRelations`
   * comes from `pg_class`, which it does not filter. A table in the second and
   * not the first exists, in the schema being searched, and the role simply
   * cannot see it — so "the migration that creates it has not been applied" is
   * a false statement that sends someone to re-run a migration that already
   * ran. It is a grant, and this is not a failure of the schema.
   */
  it('warns about privileges — not a missing migration — for a table the role cannot see', () => {
    const observed = observing(
      {},
      {
        searchedSchemaRelations: new Set(['users']),
        connectedRole: 'app_readonly',
      },
    )

    const issues = validateSchemas(columns, observed)

    expect(issues).toEqual([
      {
        severity: 'warning',
        table: 'users',
        message: expect.stringContaining('not visible to the connected role'),
      },
    ])
    expect(issues[0].message).toContain('"app_readonly"')
    // The remedy is runnable, and names the role to grant to.
    expect(issues[0].message).toContain(
      'GRANT SELECT ON "users" TO "app_readonly"',
    )
    expect(issues[0].message).not.toContain('does not exist in any schema')
  })

  it('still names the schema it searched when the role is unknown', () => {
    const observed = observing(
      {},
      {
        searchedSchema: 'tenant_7',
        searchedSchemaRelations: new Set(['users']),
        connectedRole: undefined,
      },
    )

    const [issue] = validateSchemas(columns, observed)

    expect(issue.severity).toBe('warning')
    expect(issue.message).toContain('exists in schema "tenant_7"')
    expect(issue.message).not.toContain('undefined')
  })

  /**
   * A name can be both invisible here and visible in another schema. The
   * privilege reading wins: the table the declaration means is the one in the
   * searched schema, and telling someone to re-point `search_path` at an
   * unrelated same-named relation is the wrong instruction.
   */
  it('prefers the privilege reading over the wrong-search_path one', () => {
    const observed = observing(
      {},
      {
        searchedSchemaRelations: new Set(['users']),
        elsewhere: new Map([['users', ['archive']]]),
      },
    )

    const [issue] = validateSchemas(columns, observed)

    expect(issue.message).toContain('not visible to the connected role')
    expect(issue.message).not.toContain('search_path%3D')
  })

  /**
   * `@cipherstash/migrate` accepts `schema.table` (`splitTableName` in
   * `packages/migrate/src/version.ts`), so the spelling reaches validate — but
   * the literal `'app.users'` is compared whole against a bare
   * `information_schema.columns.table_name`, matches nothing, and was reported
   * as a missing table. Saying nothing could be checked is honest; saying the
   * migration never ran is not.
   */
  it('says a schema-qualified table name cannot be checked, rather than reporting it missing', () => {
    const qualified = collectDeclaredColumns([
      encryptedTable('app.users', { email: types.TextEq('email') }),
    ])

    const issues = validateSchemas(qualified, observing({}))

    expect(issues).toEqual([
      {
        severity: 'warning',
        table: 'app.users',
        message: expect.stringContaining('schema-qualified'),
      },
    ])
    expect(issues[0].message).not.toContain('does not exist in any schema')
    // The way out, named: drop the qualifier and point the connection there.
    expect(issues[0].message).toContain('search_path%3Dapp')
  })

  it('says nothing about a qualified name when there is no database to check against', () => {
    const qualified = collectDeclaredColumns([
      encryptedTable('app.users', { email: types.TextEq('email') }),
    ])

    // The finding describes what the DATABASE pass could not do, so with no
    // database pass there is nothing to report.
    expect(validateSchemas(qualified)).toEqual([])
  })

  /**
   * The same reason `validateSchemas` collapses the EQL-not-installed finding:
   * one fact explains every column, and repeating it per column buries it. A
   * twenty-column table produced twenty identical paragraphs.
   */
  it('reports an absent table once, not once per column', () => {
    const wide = encryptedTable('wide', {
      a: types.TextEq('a'),
      b: types.TextEq('b'),
      c: types.TextEq('c'),
    })
    const observed = observing({})

    const issues = validateSchemas(collectDeclaredColumns([wide]), observed)

    expect(issues).toHaveLength(1)
    expect(issues[0].column).toBeUndefined()
  })

  it('still reports each absent table separately', () => {
    const a = encryptedTable('a', { x: types.TextEq('x') })
    const b = encryptedTable('b', { y: types.TextEq('y') })

    const issues = validateSchemas(
      collectDeclaredColumns([a, b]),
      observing({}),
    )

    expect(issues.map((issue) => issue.table)).toEqual(['a', 'b'])
  })

  it('names both schemas — the one searched and the one that has the table', () => {
    const observed = observing(
      {},
      {
        searchedSchema: 'tenant_7',
        elsewhere: new Map([['users', ['app']]]),
        indexedExtractors: fullyIndexed(columns),
      },
    )

    const [issue] = validateSchemas(columns, observed)

    expect(issue.message).toContain('exists in schema "app"')
    expect(issue.message).toContain('not in "tenant_7"')
    // The remedy has to name the schema to point at, not a placeholder.
    expect(issue.message).toContain('search_path%3Dapp')
  })

  it('reports a declared column the table does not have', () => {
    const observed = observing(
      { users: { email: 'eql_v3_text_search' } },
      { indexedExtractors: fullyIndexed(columns) },
    )

    expect(validateSchemas(columns, observed)).toEqual([
      {
        severity: 'error',
        table: 'users',
        column: 'age',
        message: expect.stringContaining(
          'does not exist on table "users". Add it in a migration with the `public.eql_v3_integer_ord` type',
        ),
      },
    ])
  })

  /**
   * The same finding on the degraded config-only path — an old
   * `@cipherstash/stack` with no `getSchemas()`, and a reachable database. That
   * combination is the whole reason the domain-less fallback exists, and it was
   * reachable only in production: every other config-only test calls
   * `validateSchemas` with no `observed`, so the database rules never ran, and
   * every database-rule test uses real `types.*` columns, which always carry a
   * domain.
   *
   * Asserted as a whole string, not a substring: the point of the test is which
   * ARM of `${domain ? ... : 'declared EQL'}` rendered, and only an exact match
   * can tell them apart.
   */
  it('names no domain in the migration hint when the degraded path has none', () => {
    const domainless = collectDeclaredColumnsFromConfig(
      configWith({ age: { cast_as: 'number', indexes: { ope: {} } } }),
    )
    const observed = observing({ t: { other: 'eql_v3_integer_ord' } })

    expect(validateSchemas(domainless, observed)).toEqual([
      {
        severity: 'error',
        table: 't',
        column: 'age',
        message:
          'Column "age" is declared in your encryption schema but does not exist on table "t". Add it in a migration with the declared EQL type.',
      },
    ])
  })

  it('reports a column that is still plain', () => {
    const observed = observing(
      { users: { email: 'eql_v3_text_search', age: null } },
      { indexedExtractors: fullyIndexed(columns) },
    )

    expect(validateSchemas(columns, observed)).toEqual([
      {
        severity: 'error',
        table: 'users',
        column: 'age',
        message: expect.stringContaining('is a plain (non-EQL) column'),
      },
    ])
  })

  /**
   * The degraded-path twin of the test above, for the same reason. Note that
   * `stringContaining('is a plain (non-EQL) column')` — what that test asserts —
   * matches BOTH renderings, so it could never have caught the domain-less arm
   * dropping out. The sentence has to be asserted whole.
   */
  it('claims no domain in the plain-column finding when the degraded path has none', () => {
    const domainless = collectDeclaredColumnsFromConfig(
      configWith({ age: { cast_as: 'number', indexes: { ope: {} } } }),
    )
    const observed = observing(
      { t: { age: null } },
      { indexedExtractors: fullyIndexed(domainless) },
    )

    expect(validateSchemas(domainless, observed)).toEqual([
      {
        severity: 'error',
        table: 't',
        column: 'age',
        message:
          'Column "age" is a plain (non-EQL) column in the database, but your schema declares it encrypted. Encrypted payloads written to it are unconstrained and unqueryable.',
      },
    ])
  })

  it('reports a domain that has drifted from the declaration', () => {
    const observed = observing(
      {
        users: {
          email: 'eql_v3_text_search',
          // A migration wrote the ORE twin; the schema says OPE.
          age: 'eql_v3_integer_ord_ore',
        },
      },
      { indexedExtractors: fullyIndexed(columns) },
    )

    expect(validateSchemas(columns, observed)).toEqual([
      {
        severity: 'error',
        table: 'users',
        column: 'age',
        message: expect.stringContaining(
          'Declared `public.eql_v3_integer_ord` but the database column is `eql_v3_integer_ord_ore`',
        ),
      },
    ])
  })

  it('upgrades the _ord_ore warning to an error when the operator class is absent', () => {
    const ore = encryptedTable('t', { age: types.IntegerOrdOre('age') })
    const oreColumns = collectDeclaredColumns([ore])
    const observed = observing(
      { t: { age: 'eql_v3_integer_ord_ore' } },
      {
        oreAvailable: false,
        indexedExtractors: fullyIndexed(oreColumns),
      },
    )

    const issues = validateSchemas(oreColumns, observed)

    expect(issues).toEqual([
      {
        severity: 'error',
        table: 't',
        column: 'age',
        message: expect.stringContaining('is unusable in this database'),
      },
    ])
    // Not both: the static Warning is superseded, not stacked on top of.
    expect(issues.filter((issue) => issue.severity === 'warning')).toEqual([])
  })

  it('says nothing about ORE when the operator class is present', () => {
    const ore = encryptedTable('t', { age: types.IntegerOrdOre('age') })
    const oreColumns = collectDeclaredColumns([ore])
    const observed = observing(
      { t: { age: 'eql_v3_integer_ord_ore' } },
      { indexedExtractors: fullyIndexed(oreColumns) },
    )

    expect(validateSchemas(oreColumns, observed)).toEqual([])
  })

  it('reports each missing functional index with a runnable CREATE INDEX', () => {
    const observed = observing(healthy, {
      indexedExtractors: new Map([['users.email', new Set(['eq_term'])]]),
    })

    const issues = validateSchemas(columns, observed)

    expect(issues).toHaveLength(2)
    expect(issues[0]).toMatchObject({
      severity: 'info',
      table: 'users',
      column: 'email',
    })
    // `eq_term` is indexed; `ord_term` and `match_term` are not.
    expect(issues[0].message).toContain(
      '`eql_v3.ord_term` / `eql_v3.match_term`',
    )
    expect(issues[0].message).not.toContain('eql_v3.eq_term')
    expect(issues[1].message).toContain(
      'CREATE INDEX ON "users" (eql_v3.ord_term("age"));',
    )
  })

  it('asks for no index on a storage-only column', () => {
    const table = encryptedTable('t', { notes: types.Text('notes') })
    const storageOnly = collectDeclaredColumns([table])
    const observed = observing({ t: { notes: 'eql_v3_text' } })

    const issues = validateSchemas(storageOnly, observed)

    expect(issues).toHaveLength(1)
    expect(issues[0].message).toMatch(/Storage-only column/)
  })

  it('asks for no scalar index on an encrypted-JSONB column', () => {
    // `types.Json` is served by a GIN index over the column, not by a scalar
    // extractor, so the missing-extractor finding must not fire on it.
    const table = encryptedTable('t', { profile: types.Json('profile') })
    const json = collectDeclaredColumns([table])
    const observed = observing({ t: { profile: 'eql_v3_json_search' } })

    expect(validateSchemas(json, observed)).toEqual([])
  })

  it('reports a missing EQL install once and drops the per-column checks', () => {
    const observed = observing({}, { eqlInstalled: false, oreAvailable: false })
    const issues = validateSchemas(columns, observed)

    expect(issues).toEqual([
      {
        severity: 'error',
        message: expect.stringContaining('EQL v3 is not installed'),
      },
    ])
    // Not "table users does not exist" ×2 and "ORE unavailable" on top: one
    // fact explains all of them, and it names the fix.
    expect(issues.every((issue) => issue.table === undefined)).toBe(true)
  })
})

describe('expectedExtractors', () => {
  it.each([
    ['TextSearch', types.TextSearch, ['eq_term', 'ord_term', 'match_term']],
    ['TextOrd', types.TextOrd, ['eq_term', 'ord_term']],
    ['TextOrdOre', types.TextOrdOre, ['eq_term', 'ord_term_ore']],
    ['TextEq', types.TextEq, ['eq_term']],
    ['TextMatch', types.TextMatch, ['match_term']],
    ['IntegerOrd', types.IntegerOrd, ['ord_term']],
    ['IntegerOrdOre', types.IntegerOrdOre, ['ord_term_ore']],
    ['Text', types.Text, []],
    ['Json', types.Json, []],
  ] as const)('%s', (_name, factory, expected) => {
    expect(expectedExtractors(factory('c').build().indexes)).toEqual(expected)
  })
})

describe('parseIndexedExtractors', () => {
  it('reads a plain expression index', () => {
    const parsed = parseIndexedExtractors([
      {
        table: 'users',
        indexdef:
          'CREATE INDEX users_email_eq ON public.users USING btree (eql_v3.eq_term(email))',
      },
    ])

    expect(parsed.get('users.email')).toEqual(new Set(['eq_term']))
  })

  it('does not confuse ord_term_ore with ord_term', () => {
    const parsed = parseIndexedExtractors([
      {
        table: 't',
        indexdef:
          'CREATE INDEX i ON public.t USING btree (eql_v3.ord_term_ore(a))',
      },
    ])

    expect(parsed.get('t.a')).toEqual(new Set(['ord_term_ore']))
  })

  it('sees through a cast, whose nested parens a first-)-wins scan would truncate', () => {
    const parsed = parseIndexedExtractors([
      {
        table: 'users',
        indexdef:
          'CREATE INDEX i ON public.users USING btree (eql_v3.ord_term((email)::public.eql_v3_text_ord))',
      },
    ])

    expect(parsed.get('users.email')).toEqual(new Set(['ord_term']))
    // The cast target must not be recorded as a column of its own.
    expect(parsed.has('users.eql_v3_text_ord')).toBe(false)
  })

  it('unwraps a quoted identifier', () => {
    const parsed = parseIndexedExtractors([
      {
        table: 'users',
        indexdef:
          'CREATE INDEX i ON public.users USING btree (eql_v3.match_term("Email Address"))',
      },
    ])

    expect(parsed.get('users.Email Address')).toEqual(new Set(['match_term']))
  })

  it('collects several extractors across several indexes on one table', () => {
    const parsed = parseIndexedExtractors([
      {
        table: 'users',
        indexdef:
          'CREATE INDEX a ON public.users USING btree (eql_v3.eq_term(email))',
      },
      {
        table: 'users',
        indexdef:
          'CREATE INDEX b ON public.users USING btree (eql_v3.ord_term(email))',
      },
      {
        table: 'users',
        indexdef:
          'CREATE INDEX c ON public.users USING btree (eql_v3.ord_term(age))',
      },
    ])

    expect(parsed.get('users.email')).toEqual(new Set(['eq_term', 'ord_term']))
    expect(parsed.get('users.age')).toEqual(new Set(['ord_term']))
  })

  it('ignores an index that engages no extractor', () => {
    const parsed = parseIndexedExtractors([
      {
        table: 'users',
        indexdef:
          'CREATE UNIQUE INDEX users_pkey ON public.users USING btree (id)',
      },
    ])

    expect(parsed.size).toBe(0)
  })
})

describe('the encrypt config is user code, not a typed value', () => {
  /**
   * `getEncryptConfig()` is read out of the USER's node_modules through jiti,
   * so its runtime shape is whatever their client hands back — the zod types
   * that make `indexes` non-optional never run here. A column missing the key
   * entirely must degrade to "no indexes", not throw on `column.indexes.match`
   * partway through the rule list.
   */
  it('survives a config column with no indexes key at all', () => {
    const config = {
      v: 1,
      tables: { users: { email: { cast_as: 'string' } } },
    } as unknown as EncryptConfig

    const columns = collectDeclaredColumnsFromConfig(config)

    expect(() => validateSchemas(columns)).not.toThrow()
    expect(validateSchemas(columns)).toEqual([
      {
        severity: 'info',
        table: 'users',
        column: 'email',
        message: expect.stringContaining('Storage-only column'),
      },
    ])
  })
})

describe('the CREATE INDEX suggestion is meant to be pasted', () => {
  /**
   * The Info finding hands the user runnable SQL. A column name containing a
   * double quote has to be doubled inside the quoted identifier, the same way
   * `identifiersIn` un-doubles it on the read side — otherwise the suggestion
   * pastes as a syntax error at best.
   */
  it('doubles a quote embedded in an identifier', () => {
    const table = encryptedTable('we"ird', { 'a"b': types.TextEq('a"b') })
    const columns = collectDeclaredColumns([table])
    const observed = observing({ 'we"ird': { 'a"b': 'eql_v3_text_eq' } })

    const [issue] = validateSchemas(columns, observed)

    expect(issue.severity).toBe('info')
    expect(issue.message).toContain(
      'CREATE INDEX ON "we""ird" (eql_v3.eq_term("a""b"));',
    )
  })
})

describe('readObservedState', () => {
  /**
   * The index read used to scan every index in the schema and hand each
   * `pg_get_indexdef()` to the parser, to answer a question about a handful of
   * declared columns. On a large schema that is thousands of definitions
   * fetched and regex-parsed for nothing.
   */
  it('constrains the index scan to the declared tables', async () => {
    const queries: Array<{ text: string; values?: unknown[] }> = []
    const client = {
      query: (text: string, values?: unknown[]) => {
        queries.push({ text, values })
        return Promise.resolve({ rows: [] })
      },
    } as unknown as Parameters<typeof readObservedState>[0]

    await readObservedState(client, ['users', 'orders'])

    const indexQuery = queries.find((q) => q.text.includes('pg_get_indexdef'))

    expect(indexQuery).toBeDefined()
    expect(indexQuery?.text).toMatch(/relname\s*=\s*ANY/)
    expect(indexQuery?.values).toEqual([['users', 'orders']])
  })

  /**
   * Routed on the result ALIAS each query selects, not on a substring that
   * several of them share: `current_schema()` also appears in the index read,
   * so an `includes('current_schema')` fake fed schema rows to the index
   * parser and only survived because `RegExp.exec(undefined)` matches nothing.
   */
  const fakeClient = (rowsFor: Record<string, unknown[]>) =>
    ({
      query: (text: string) => {
        const alias = Object.keys(rowsFor).find((key) => text.includes(key))
        return Promise.resolve({ rows: alias ? rowsFor[alias] : [] })
      },
    }) as unknown as Parameters<typeof readObservedState>[0]

  it('reports the schema it searched', async () => {
    const observed = await readObservedState(
      fakeClient({ 'AS searched_schema': [{ searched_schema: 'tenant_7' }] }),
      ['users'],
    )

    expect(observed.searchedSchema).toBe('tenant_7')
  })

  it('falls back to public when current_schema() answers nothing', async () => {
    const observed = await readObservedState(fakeClient({}), ['users'])

    expect(observed.searchedSchema).toBe('public')
  })

  /**
   * The lookup that separates "your search_path is wrong" from "you never ran
   * the migration". Without it both look identical and validate has to hedge.
   */
  it('collects the other schemas a declared table lives in', async () => {
    const observed = await readObservedState(
      fakeClient({
        'AS relation_schema': [
          {
            table_name: 'users',
            relation_schema: 'app',
            is_searched_schema: false,
          },
          {
            table_name: 'users',
            relation_schema: 'archive',
            is_searched_schema: false,
          },
        ],
      }),
      ['users'],
    )

    expect(observed.elsewhere.get('users')).toEqual(['app', 'archive'])
  })

  /**
   * The relation lookup used to exclude `current_schema()` in SQL, so a table
   * present there but invisible to the role appeared in NEITHER read and got
   * "does not exist in any schema". It now returns the searched schema too, and
   * the two destinations are what tell the three states apart.
   */
  it('separates a relation in the searched schema from one merely elsewhere', async () => {
    const observed = await readObservedState(
      fakeClient({
        'AS relation_schema': [
          {
            table_name: 'users',
            relation_schema: 'public',
            is_searched_schema: true,
          },
          {
            table_name: 'orders',
            relation_schema: 'archive',
            is_searched_schema: false,
          },
        ],
      }),
      ['users', 'orders'],
    )

    expect(observed.searchedSchemaRelations).toEqual(new Set(['users']))
    expect(observed.elsewhere).toEqual(new Map([['orders', ['archive']]]))
  })

  it('reads the role the privilege finding has to name', async () => {
    const observed = await readObservedState(
      fakeClient({
        'AS searched_schema': [
          { searched_schema: 'public', connected_role: 'app_readonly' },
        ],
      }),
      ['users'],
    )

    expect(observed.connectedRole).toBe('app_readonly')
  })

  /**
   * The relation lookup scans EVERY schema, and `information_schema` publishes
   * views named `columns`, `domains`, `parameters`, `routines`, `sequences`,
   * `tables` and `triggers` — every one of them a plausible application table
   * name. So a project that declares `domains` and has NOT run the migration
   * matched the system view, landed in `elsewhere`, and was told its table
   * "exists in schema information_schema — point your connection there". That
   * is absurd advice, and because it is a warning rather than an error it also
   * flips the exit code from 1 to 0: the unapplied migration ships silently.
   *
   * Verified against a live PostgreSQL 14: the unfiltered query returns all
   * seven of those names out of `information_schema`, and returns none of them
   * once the two predicates below are added.
   *
   * The fake stands in for the catalogue by honouring the query's own exclusion
   * predicates, which is what a real server does.
   */
  it('does not mistake an information_schema view for a declared table', async () => {
    const excludesSystemSchemas = (text: string) =>
      /nspname\s*!~\s*'\^pg_'/.test(text) &&
      /nspname\s*<>\s*'information_schema'/.test(text)

    const client = {
      query: (text: string) =>
        Promise.resolve({
          rows:
            text.includes('AS relation_schema') && !excludesSystemSchemas(text)
              ? [
                  {
                    table_name: 'domains',
                    relation_schema: 'information_schema',
                    is_searched_schema: false,
                  },
                ]
              : [],
        }),
    } as unknown as Parameters<typeof readObservedState>[0]

    const declared = collectDeclaredColumns([
      encryptedTable('domains', { name: types.TextEq('name') }),
    ])
    const observed = await readObservedState(client, ['domains'])

    expect(observed.elsewhere.get('domains')).toBeUndefined()

    const [issue] = validateSchemas(declared, {
      ...observed,
      eqlInstalled: true,
    })

    // The migration genuinely has not run, so this must fail the command.
    expect(issue.severity).toBe('error')
    expect(issue.message).toContain('does not exist in any schema')
    expect(issue.message).not.toContain('information_schema')
  })

  /**
   * The predicates asserted as SQL text, alongside the behavioural test above:
   * that one can only prove the rows are gone, not that they were excluded for
   * the right reason on a server whose catalogue this fake does not model.
   */
  it('excludes the system schemas from the relation lookup', async () => {
    const queries: string[] = []
    const client = {
      query: (text: string) => {
        queries.push(text)
        return Promise.resolve({ rows: [] })
      },
    } as unknown as Parameters<typeof readObservedState>[0]

    await readObservedState(client, ['users'])

    const lookup = queries.find((text) => text.includes('AS relation_schema'))

    expect(lookup).toBeDefined()
    // The regex form, not `NOT LIKE 'pg\_%'`: this SQL is a JS template
    // literal, which collapses `\_` to a bare `_` — a LIKE wildcard that also
    // swallows `pgbouncer`, `pgsodium` and every other real `pg`-prefixed
    // schema. Confirmed both in node and against PostgreSQL 14.
    expect(lookup).toMatch(/nspname\s*!~\s*'\^pg_'/)
    expect(lookup).toMatch(/nspname\s*<>\s*'information_schema'/)
  })

  it('asks for the schemas of exactly the declared tables', async () => {
    const queries: Array<{ text: string; values?: unknown[] }> = []
    const client = {
      query: (text: string, values?: unknown[]) => {
        queries.push({ text, values })
        return Promise.resolve({ rows: [] })
      },
    } as unknown as Parameters<typeof readObservedState>[0]

    await readObservedState(client, ['users', 'orders'])

    const lookup = queries.find((q) => q.text.includes('AS relation_schema'))

    expect(lookup?.values).toEqual([['users', 'orders']])
  })

  /**
   * The six queries go out through one `Promise.all` and come back positionally
   * destructured, so a reordered array or a renamed result alias moves a field
   * onto the wrong read and it silently takes its falsy default. Two of those
   * defaults are loud-wrong on a healthy database: `eqlInstalled: false` prints
   * "run `stash eql install`" and skips every database check, and an empty
   * `columns` reports every declared table as never-migrated and exits 1.
   *
   * Nothing else covers it — `fetchPhysicalColumns` has no test of its own and
   * swallows every exception into an empty map, so `columns` is asserted by
   * CONTENT here. A presence-only assertion passes vacuously against that catch.
   */
  it('maps each query onto the field it feeds', async () => {
    const observed = await readObservedState(
      fakeClient({
        'AS eql_installed': [{ eql_installed: true }],
        'AS ore_available': [{ ore_available: true }],
        'AS searched_schema': [
          { searched_schema: 'tenant_7', connected_role: 'app_rw' },
        ],
        'AS relation_schema': [
          {
            table_name: 'users',
            relation_schema: 'tenant_7',
            is_searched_schema: true,
          },
          {
            table_name: 'users',
            relation_schema: 'archive',
            is_searched_schema: false,
          },
        ],
        'information_schema.columns': [
          {
            table_name: 'users',
            column_name: 'email',
            domain_name: 'eql_v3_text_search',
          },
          { table_name: 'users', column_name: 'id', domain_name: null },
        ],
        'AS indexdef': [
          {
            table_name: 'users',
            indexdef:
              'CREATE INDEX i ON tenant_7.users USING btree (eql_v3.eq_term(email))',
          },
        ],
      }),
      ['users'],
    )

    expect(observed).toEqual({
      eqlInstalled: true,
      oreAvailable: true,
      searchedSchema: 'tenant_7',
      connectedRole: 'app_rw',
      elsewhere: new Map([['users', ['archive']]]),
      searchedSchemaRelations: new Set(['users']),
      columns: new Map([
        [
          'users',
          new Map([
            ['email', 'eql_v3_text_search'],
            ['id', null],
          ]),
        ],
      ]),
      indexedExtractors: new Map([['users.email', new Set(['eq_term'])]]),
    })
  })
})

describe('reportIssues', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  /**
   * The three shapes this command produces. v2 only ever produced the third,
   * and its formatter prefixed every line unconditionally — under that
   * formatter the first two render as `undefined.undefined: EQL v3 is not
   * installed` and `users.undefined: Table "users" exists in schema "app"`.
   * The rules tests assert those two shapes exist; this is what asserts they
   * reach a user intact.
   */
  const issues: ValidationIssue[] = [
    { severity: 'error', message: 'EQL v3 is not installed' },
    {
      severity: 'warning',
      table: 'users',
      message: 'Table "users" exists in schema "app"',
    },
    {
      severity: 'info',
      table: 'users',
      column: 'email',
      message: 'Storage-only column',
    },
  ]

  const printed = () => [
    ...clack.log.error.mock.calls,
    ...clack.log.warn.mock.calls,
    ...clack.log.info.mock.calls,
  ]

  it('prints each severity through its own channel, prefixing only the column-level line', () => {
    reportIssues(issues)

    expect(clack.log.error.mock.calls).toEqual([['EQL v3 is not installed']])
    expect(clack.log.warn.mock.calls).toEqual([
      ['Table "users" exists in schema "app"'],
    ])
    expect(clack.log.info.mock.calls).toEqual([
      ['users.email: Storage-only column'],
    ])
  })

  it('never renders an absent table or column as "undefined"', () => {
    reportIssues(issues)

    expect(printed()).not.toHaveLength(0)
    for (const [line] of printed()) {
      expect(line).not.toContain('undefined')
    }
  })

  it('returns true — the exit-1 gate — and counts the outro when an error is present', () => {
    expect(reportIssues(issues)).toBe(true)
    expect(clack.outro).toHaveBeenCalledWith('1 error, 1 warning.')
  })

  it('returns false when nothing is an error', () => {
    const noErrors = issues.filter((issue) => issue.severity !== 'error')

    expect(reportIssues(noErrors)).toBe(false)
    expect(clack.outro).toHaveBeenCalledWith('No errors found. 1 warning.')
  })

  it('still says something when every finding is Info', () => {
    expect(reportIssues(issues.slice(2))).toBe(false)
    expect(clack.outro).toHaveBeenCalledWith('No errors or warnings. 1 info.')
  })

  it('says so when there is nothing to report', () => {
    expect(reportIssues([])).toBe(false)
    expect(clack.outro).toHaveBeenCalledWith('No issues found.')
  })
})
