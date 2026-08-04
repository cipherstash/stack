import { encryptedTable, types } from '@cipherstash/stack/eql/v3'
import type { EncryptConfig } from '@cipherstash/stack/schema'
import { describe, expect, it } from 'vitest'
import {
  collectDeclaredColumns,
  collectDeclaredColumnsFromConfig,
  expectedExtractors,
  type ObservedState,
  parseIndexedExtractors,
  readObservedState,
  validateSchemas,
} from '../validate.js'

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
    elsewhere: new Map(),
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
  const configWith = (
    columns: EncryptConfig['tables'][string],
  ): EncryptConfig => ({ v: 1, tables: { t: columns } }) as EncryptConfig

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
    const columns = collectDeclaredColumnsFromConfig(
      configWith({ doc: { cast_as: 'string', indexes: { ste_vec: {} } } }),
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
   * A table absent from `current_schema()` is TWO different situations, and
   * `elsewhere` is what separates them.
   *
   * Found under another schema, the project is healthy and merely pointed at
   * the wrong `search_path` (Prisma `multiSchema`, a tenant schema, a
   * `schema.table` name in `encryptedTable` that the reader compares whole
   * against a bare `table_name`). Found under none, the migration genuinely
   * has not run. The first must not fail the command; the second must.
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
        'AS other_schema': [
          { table_name: 'users', other_schema: 'app' },
          { table_name: 'users', other_schema: 'archive' },
        ],
      }),
      ['users'],
    )

    expect(observed.elsewhere.get('users')).toEqual(['app', 'archive'])
  })

  it('asks for the other schemas of exactly the declared tables', async () => {
    const queries: Array<{ text: string; values?: unknown[] }> = []
    const client = {
      query: (text: string, values?: unknown[]) => {
        queries.push({ text, values })
        return Promise.resolve({ rows: [] })
      },
    } as unknown as Parameters<typeof readObservedState>[0]

    await readObservedState(client, ['users', 'orders'])

    const lookup = queries.find((q) => q.text.includes('AS other_schema'))

    expect(lookup?.values).toEqual([['users', 'orders']])
  })
})
