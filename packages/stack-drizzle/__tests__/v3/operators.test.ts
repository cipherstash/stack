import { needleFor } from '@cipherstash/test-kit'
import {
  eqlTypeSlug as slug,
  typedEntries,
  V3_MATRIX,
} from '@cipherstash/test-kit/catalog'
import {
  eq as drizzleEq,
  exists,
  isNotNull,
  isNull,
  not,
  notExists,
  type SQL,
  type SQLWrapper,
  sql,
} from 'drizzle-orm'
import { integer, PgDialect, pgTable } from 'drizzle-orm/pg-core'
import { describe, expect, it, vi } from 'vitest'
import { makeEqlV3Column } from '../../src/v3/column'
import {
  createEncryptionOperatorsV3,
  EncryptionOperatorError,
} from '../../src/v3/operators'
import { extractEncryptionSchemaV3 } from '../../src/v3/schema-extraction'
import { types } from '../../src/v3/types'

// A query TERM (from `encryptQuery`), not a storage envelope: it carries index
// terms but NO ciphertext `c` — that is the whole point of the encrypt →
// encryptQuery move. The operator layer casts it to the column's query domain.
const TERM = { hm: 'h', v: 3 }
const TERM_JSON = JSON.stringify(TERM)
const lockContext = { identityClaim: 'user-123' }
const audit = { metadata: { actor: 'test' } }

// The `eql_v3.query_<domain>` type an operand for a matrix column casts to.
// `slug('public.eql_v3_text_eq')` → `eql_v3_text_eq`; stripping the `eql_v3_`
// prefix yields the domain suffix the query type is named for (`text_eq` →
// `eql_v3.query_text_eq`).
const qcast = (eqlType: string): string =>
  `eql_v3.query_${slug(eqlType).replace(/^eql_v3_/, '')}`

type TermResult = { data: unknown } | { failure: { message: string } }

function chainable(result: Promise<TermResult>) {
  const op = result as Promise<TermResult> & {
    withLockContext: ReturnType<typeof vi.fn>
    audit: ReturnType<typeof vi.fn>
  }
  op.withLockContext = vi.fn(() => op)
  op.audit = vi.fn(() => op)
  return op
}

// The double now models `encryptQuery` in BOTH its forms: the single
// `(value, opts)` form used by scalar/JSON operands, and the batch `(terms[])`
// form used by inArray/notInArray. `termImpl` maps a plaintext value to the
// query term the crossing would return (defaulting to a constant `TERM`); the
// batch form applies it position-for-position so callers can pin ordering.
function setup(termImpl: (value?: unknown) => unknown = () => TERM) {
  const encryptQuery = vi.fn((valueOrTerms: unknown, opts?: unknown) => {
    // Route exactly as the real client does (packages/stack/src/encryption/
    // index.ts): batch ONLY when no opts are supplied AND the arg is a term
    // array. An array-valued single query WITH opts (e.g. a searchableJson
    // array needle) must take the single path here too, or the double would
    // diverge from production for that shape.
    if (opts === undefined && Array.isArray(valueOrTerms)) {
      const terms = valueOrTerms as Array<{ value: unknown }>
      return chainable(
        Promise.resolve({ data: terms.map((t) => termImpl(t.value)) }),
      )
    }
    return chainable(Promise.resolve({ data: termImpl(valueOrTerms) }))
  })
  // The factory's `client` parameter is the structural `{ encryptQuery }`
  // surface, so this hand-rolled double satisfies it with no cast.
  const client = { encryptQuery }
  const ops = createEncryptionOperatorsV3(client, { lockContext, audit })
  const dialect = new PgDialect()
  const render = (s: unknown) => dialect.sqlToQuery(s as SQL)
  return { ops, encryptQuery, render }
}

const matrixEntries = typedEntries(V3_MATRIX)
const matrixTable = pgTable(
  'matrix_users',
  Object.fromEntries(
    matrixEntries.map(([eqlType, spec]) => [
      slug(eqlType),
      makeEqlV3Column(spec.builder(slug(eqlType))),
    ]),
  ) as never,
)
const matrixColumn = (eqlType: string) =>
  (matrixTable as Record<string, SQLWrapper>)[slug(eqlType)]
const sampleFor = (spec: (typeof V3_MATRIX)[keyof typeof V3_MATRIX]) =>
  spec.samples[0]

const equalityDomains = matrixEntries.filter(
  ([, spec]) => spec.indexes.unique || spec.indexes.ore || spec.indexes.ope,
)
const orderDomains = matrixEntries.filter(
  ([, spec]) => spec.indexes.ore || spec.indexes.ope,
)
const matchDomains = matrixEntries.filter(([, spec]) => spec.indexes.match)
// Domains with NO scalar query index (unique/ore/ope/match), so `eq`/`ne`/
// ordering all throw. This is the truly storage-only scalar domains PLUS
// `eql_v3_json` — json is a QUERYABLE domain (containment), it just answers no
// scalar op, so it lands here for the eq/order rejection checks.
const nonScalarQueryDomains = matrixEntries.filter(
  ([, spec]) =>
    !spec.indexes.unique &&
    !spec.indexes.ore &&
    !spec.indexes.ope &&
    !spec.indexes.match,
)
// Of those, the ones that also reject `contains` — i.e. everything except json.
// json answers `contains` via `@>`, so it is excluded here and gets its own
// positive assertion in the JSON containment describe above.
const noContainmentDomains = nonScalarQueryDomains.filter(
  ([, spec]) => !spec.indexes.ste_vec,
)

const users = pgTable('users', {
  id: integer().primaryKey(),
  email: types.TextSearch('email'),
  nickname: types.TextEq('nickname'),
  textMatch: types.TextMatch('text_match'),
  textOrd: types.TextOrd('text_ord'),
  textOrdOre: types.TextOrdOre('text_ord_ore'),
  int2Age: types.SmallintOrd('int2_age'),
  age: types.IntegerOrd('age'),
  createdOn: types.DateOrd('created_on'),
  createdAt: types.TimestampOrd('created_at'),
  amount: types.NumericOrd('amount'),
  score4: types.RealOrd('score4'),
  score8: types.DoubleOrd('score8'),
  flag: types.Boolean('flag'),
})

describe('createEncryptionOperatorsV3 - equality', () => {
  it.each(
    equalityDomains,
  )('%s eq emits the latest two-arg eql_v3.eq with a query-term operand', async (eqlType, spec) => {
    const { ops, encryptQuery, render } = setup()
    const q = render(await ops.eq(matrixColumn(eqlType), sampleFor(spec)))

    expect(q.sql).toContain(
      `eql_v3.eq("matrix_users"."${slug(eqlType)}", $1::${qcast(eqlType)})`,
    )
    expect(q.params).toEqual([TERM_JSON])
    expect(encryptQuery.mock.calls[0]?.[1]?.column.getName()).toBe(
      slug(eqlType),
    )
    expect(encryptQuery.mock.calls[0]?.[1]?.queryType).toBe('equality')
  })

  it.each(equalityDomains)('%s ne emits eql_v3.neq', async (eqlType, spec) => {
    const { ops, encryptQuery, render } = setup()
    const q = render(await ops.ne(matrixColumn(eqlType), sampleFor(spec)))

    expect(q.sql).toContain(
      `eql_v3.neq("matrix_users"."${slug(eqlType)}", $1::${qcast(eqlType)})`,
    )
    expect(q.params).toEqual([TERM_JSON])
    expect(encryptQuery.mock.calls[0]?.[1]?.column.getName()).toBe(
      slug(eqlType),
    )
    expect(encryptQuery.mock.calls[0]?.[1]?.queryType).toBe('equality')
  })

  it('same-named columns on different tables use their own equality capability', async () => {
    const accounts = pgTable('accounts', {
      email: types.TextEq('email'),
    })
    pgTable('metrics', {
      email: types.IntegerOrd('email'),
    })
    const { ops, render } = setup()

    const q = render(await ops.eq(accounts.email, 'ada@example.com'))

    expect(q.sql).toContain(
      'eql_v3.eq("accounts"."email", $1::eql_v3.query_text_eq)',
    )
  })

  it('does not reuse a cached extracted schema across distinct pgTable objects with the same SQL name', async () => {
    const first = pgTable('shared', {
      email: types.TextEq('email'),
    })
    const second = pgTable('shared', {
      age: types.IntegerOrd('age'),
    })
    const { ops, encryptQuery } = setup()

    await ops.eq(first.email, 'ada@example.com')
    await ops.eq(second.age, 37)

    expect(encryptQuery.mock.calls[1]?.[1]?.table.build()).toEqual(
      extractEncryptionSchemaV3(second).build(),
    )
  })

  it('passes default lock context and audit to operand encryption', async () => {
    const { ops, encryptQuery } = setup()
    await ops.eq(users.nickname, 'ada')
    const op = encryptQuery.mock.results[0]?.value
    expect(op.withLockContext).toHaveBeenCalledWith(lockContext)
    expect(op.audit).toHaveBeenCalledWith(audit)
  })

  it('per-call lock context and audit override constructor defaults', async () => {
    const { ops, encryptQuery } = setup()
    const callLockContext = { identityClaim: 'user-456' }
    const callAudit = { metadata: { actor: 'override' } }

    await ops.eq(users.nickname, 'ada', {
      lockContext: callLockContext,
      audit: callAudit,
    })

    const op = encryptQuery.mock.results[0]?.value
    expect(op.withLockContext).toHaveBeenCalledWith(callLockContext)
    expect(op.withLockContext).not.toHaveBeenCalledWith(lockContext)
    expect(op.audit).toHaveBeenCalledWith(callAudit)
    expect(op.audit).not.toHaveBeenCalledWith(audit)
  })
})

describe('createEncryptionOperatorsV3 - comparison & range', () => {
  it.each([
    ['gt', 'eql_v3.gt'],
    ['gte', 'eql_v3.gte'],
    ['lt', 'eql_v3.lt'],
    ['lte', 'eql_v3.lte'],
  ] as const)('%s emits %s for every ORE domain', async (op, fn) => {
    for (const [eqlType, spec] of orderDomains) {
      const { ops, encryptQuery, render } = setup()
      const q = render(await ops[op](matrixColumn(eqlType), sampleFor(spec)))

      expect(q.sql).toContain(
        `${fn}("matrix_users"."${slug(eqlType)}", $1::${qcast(eqlType)})`,
      )
      expect(q.params).toEqual([TERM_JSON])
      expect(encryptQuery.mock.calls[0]?.[1]?.column.getName()).toBe(
        slug(eqlType),
      )
      expect(encryptQuery.mock.calls[0]?.[1]?.queryType).toBe('orderAndRange')
    }
  })

  it.each(
    orderDomains,
  )('%s between emits a bounded range with two query-term operands', async (eqlType, spec) => {
    const { ops, render } = setup()
    const value = sampleFor(spec)
    const q = render(await ops.between(matrixColumn(eqlType), value, value))

    expect(q.sql).toContain(
      `eql_v3.gte("matrix_users"."${slug(eqlType)}", $1::${qcast(eqlType)})`,
    )
    expect(q.sql).toContain(
      `eql_v3.lte("matrix_users"."${slug(eqlType)}", $2::${qcast(eqlType)})`,
    )
    expect(q.params).toEqual([TERM_JSON, TERM_JSON])
  })

  it.each(
    orderDomains,
  )('%s notBetween wraps the range in NOT (...)', async (eqlType, spec) => {
    const { ops, render } = setup()
    const value = sampleFor(spec)
    const q = render(await ops.notBetween(matrixColumn(eqlType), value, value))

    expect(q.sql).toMatch(/^not \(/i)
    expect(q.sql).toContain(
      `eql_v3.gte("matrix_users"."${slug(eqlType)}", $1::${qcast(eqlType)})`,
    )
    expect(q.sql).toContain(
      `eql_v3.lte("matrix_users"."${slug(eqlType)}", $2::${qcast(eqlType)})`,
    )
    expect(q.params).toEqual([TERM_JSON, TERM_JSON])
  })

  // Every other `between` case passes identical bounds against a constant
  // encrypt stub, so the operand never reaches an assertion and a min/max
  // transposition inside `range` is invisible. Echo the plaintext through the
  // stub instead, and pin that `gte` binds `min` and `lte` binds `max`.
  it('between binds min to gte and max to lte, in that order', async () => {
    const { ops, render } = setup((value) => ({ p: value }))

    const q = render(await ops.between(users.age, -128, 127))

    expect(q.sql).toBe(
      '(eql_v3.gte("users"."age", $1::eql_v3.query_integer_ord) AND eql_v3.lte("users"."age", $2::eql_v3.query_integer_ord))',
    )
    expect(q.params).toEqual(['{"p":-128}', '{"p":127}'])
  })

  it('notBetween binds min to gte and max to lte, in that order', async () => {
    const { ops, render } = setup((value) => ({ p: value }))

    const q = render(await ops.notBetween(users.age, -128, 127))

    expect(q.params).toEqual(['{"p":-128}', '{"p":127}'])
  })

  it('not(between(...)) negates the whole range, not just its lower bound', async () => {
    const { ops, render } = setup()

    const q = render(ops.not(await ops.between(users.age, 25, 40)))

    // `not eql_v3.gte(..) AND eql_v3.lte(..)` would parse as `(NOT gte) AND
    // lte` in Postgres — every row under the lower bound, none of the intended
    // complement. The range must arrive pre-parenthesised.
    expect(q.sql).toBe(
      'not (eql_v3.gte("users"."age", $1::eql_v3.query_integer_ord) AND eql_v3.lte("users"."age", $2::eql_v3.query_integer_ord))',
    )
  })

  it('between stays parenthesised when combined with other predicates', async () => {
    const { ops, render } = setup()

    const q = render(
      await ops.or(
        ops.between(users.age, 25, 40),
        ops.eq(users.nickname, 'ada'),
      ),
    )

    expect(q.sql).toContain(
      '(eql_v3.gte("users"."age", $1::eql_v3.query_integer_ord) AND eql_v3.lte("users"."age", $2::eql_v3.query_integer_ord))',
    )
  })

  it.each(
    orderDomains,
  )('%s asc / desc extract the ord term', (eqlType, spec) => {
    const { ops, render } = setup()
    // eql-3.0.0 splits the extractor by ordering flavour: `ord_term` for the
    // OPE-backed `_ord` domains, `ord_term_ore` for the block-ORE `_ord_ore`.
    const fn = spec.indexes.ore ? 'ord_term_ore' : 'ord_term'
    const ascq = render(ops.asc(matrixColumn(eqlType)))
    expect(ascq.sql).toContain(
      `eql_v3.${fn}("matrix_users"."${slug(eqlType)}")`,
    )
    expect(ascq.sql.toLowerCase()).toContain('asc')

    const descq = render(ops.desc(matrixColumn(eqlType)))
    expect(descq.sql).toContain(
      `eql_v3.${fn}("matrix_users"."${slug(eqlType)}")`,
    )
    expect(descq.sql.toLowerCase()).toContain('desc')
  })
})

describe('createEncryptionOperatorsV3 - free-text match', () => {
  it.each(
    matchDomains,
  )('%s contains emits latest eql_v3.contains with a query-term operand', async (eqlType, spec) => {
    const { ops, encryptQuery, render } = setup()
    const q = render(await ops.contains(matrixColumn(eqlType), needleFor(spec)))

    expect(q.sql).toContain(
      `eql_v3.contains("matrix_users"."${slug(eqlType)}", $1::${qcast(eqlType)})`,
    )
    expect(q.params).toEqual([TERM_JSON])
    expect(encryptQuery.mock.calls[0]?.[1]?.column.getName()).toBe(
      slug(eqlType),
    )
    expect(encryptQuery.mock.calls[0]?.[1]?.queryType).toBe('freeTextSearch')
  })

  // A needle shorter than the tokenizer's `token_length` produces an empty
  // bloom filter, and `stored_bf @> '{}'` is true for every row — so this must
  // throw rather than silently return the whole table.
  it.each(
    matchDomains,
  )('%s contains rejects a needle shorter than token_length before encrypting', async (eqlType) => {
    const { ops, encryptQuery } = setup()
    await expect(ops.contains(matrixColumn(eqlType), 'ad')).rejects.toThrow(
      /at least 3 characters/,
    )
    await expect(ops.contains(matrixColumn(eqlType), '')).rejects.toThrow(
      EncryptionOperatorError,
    )
    expect(encryptQuery).not.toHaveBeenCalled()
  })

  it('contains accepts a needle exactly at token_length', async () => {
    const { ops, render } = setup()
    const q = render(await ops.contains(users.email, 'ada'))
    expect(q.sql).toContain(
      'eql_v3.contains("users"."email", $1::eql_v3.query_text_search)',
    )
  })

  it('negation is expressed through the passthrough Drizzle not operator', async () => {
    const { ops, render } = setup()
    const q = render(ops.not(await ops.contains(users.email, 'example.com')))
    expect(q.sql).toMatch(/^not /i)
    expect(q.sql).toContain(
      'eql_v3.contains("users"."email", $1::eql_v3.query_text_search)',
    )
  })

  it('does not expose obsolete like/ilike helpers', () => {
    const { ops } = setup()
    expect('like' in ops).toBe(false)
    expect('ilike' in ops).toBe(false)
    expect('notIlike' in ops).toBe(false)
  })
})

describe('createEncryptionOperatorsV3 - JSON containment', () => {
  const JSON_TYPE = 'public.eql_v3_json'

  // json has no `eql_v3.contains` overload: containment is the `@>` operator,
  // and the needle is a narrowed `query_jsonb` term from `encryptQuery` (no
  // ciphertext), cast to `eql_v3.query_jsonb`.
  it('contains emits the @> operator with a query_jsonb needle', async () => {
    const { ops, encryptQuery, render } = setup()
    const q = render(
      await ops.contains(matrixColumn(JSON_TYPE), { roles: ['eng'] }),
    )

    expect(q.sql.toLowerCase()).toContain(
      `"matrix_users"."${slug(JSON_TYPE)}" operator(public.@>) $1::eql_v3.query_jsonb`,
    )
    expect(q.sql).not.toContain('eql_v3.contains')
    // The needle is the encryptQuery result, not a full storage envelope.
    expect(q.params).toEqual([TERM_JSON])
    expect(encryptQuery).toHaveBeenCalledTimes(1)
    expect(encryptQuery.mock.calls[0]?.[0]).toEqual({ roles: ['eng'] })
    expect(encryptQuery.mock.calls[0]?.[1]).toMatchObject({
      queryType: 'searchableJson',
    })
  })

  it('JSON containment carries the default lock context and audit config', async () => {
    const { ops, encryptQuery } = setup()
    await ops.contains(matrixColumn(JSON_TYPE), { roles: ['eng'] })
    const op = encryptQuery.mock.results[0]?.value
    expect(op.withLockContext).toHaveBeenCalledWith(lockContext)
    expect(op.audit).toHaveBeenCalledWith(audit)
  })

  it('contains surfaces an encryptQuery failure as an EncryptionOperatorError', async () => {
    const { ops, encryptQuery } = setup()
    encryptQuery.mockReturnValueOnce(
      chainable(Promise.resolve({ failure: { message: 'boom' } })),
    )
    await expect(
      ops.contains(matrixColumn(JSON_TYPE), { roles: ['eng'] }),
    ).rejects.toBeInstanceOf(EncryptionOperatorError)
  })

  it('contains rejects a null operand before calling encryptQuery', async () => {
    const { ops, encryptQuery } = setup()
    await expect(
      ops.contains(matrixColumn(JSON_TYPE), null),
    ).rejects.toBeInstanceOf(EncryptionOperatorError)
    expect(encryptQuery).not.toHaveBeenCalled()
  })

  // `doc @> '{}'` holds for every row (jsonb `{} ⊆ anything`); an empty-object
  // needle would silently return the whole table, so it is refused before
  // encrypting — the same whole-table guard the bloom path applies.
  it('contains rejects an empty-object needle before calling encryptQuery', async () => {
    const { ops, encryptQuery } = setup()
    await expect(ops.contains(matrixColumn(JSON_TYPE), {})).rejects.toThrow(
      /matches every row/,
    )
    expect(encryptQuery).not.toHaveBeenCalled()
  })
})

describe('createEncryptionOperatorsV3 - domains with no scalar query', () => {
  it.each(nonScalarQueryDomains)('%s eq throws', async (eqlType, spec) => {
    const { ops } = setup()
    await expect(
      ops.eq(matrixColumn(eqlType), sampleFor(spec)),
    ).rejects.toBeInstanceOf(EncryptionOperatorError)
  })

  it.each(noContainmentDomains)('%s contains throws', async (eqlType, spec) => {
    const { ops } = setup()
    await expect(
      ops.contains(matrixColumn(eqlType), sampleFor(spec)),
    ).rejects.toBeInstanceOf(EncryptionOperatorError)
  })

  it.each(nonScalarQueryDomains)('%s asc throws synchronously', (eqlType) => {
    const { ops } = setup()
    expect(() => ops.asc(matrixColumn(eqlType))).toThrow(
      EncryptionOperatorError,
    )
  })
})

describe('createEncryptionOperatorsV3 - array, ordering, combinators', () => {
  it('inArray ORs one eq term per value; empty array throws', async () => {
    const { ops, render } = setup()
    const q = render(await ops.inArray(users.nickname, ['ada', 'grace']))
    expect(q.sql).toContain(' or ')
    expect((q.sql.match(/eql_v3\.eq/g) ?? []).length).toBe(2)
    await expect(ops.inArray(users.nickname, [])).rejects.toThrow(/non-empty/)
  })

  it('inArray encrypts every value in one batch crossing, ORing one eq term each', async () => {
    const { ops, encryptQuery, render } = setup()
    const values = [
      'ada',
      'grace',
      'alan',
      'katherine',
      'dorothy',
      'mary',
      'joan',
    ]

    const q = render(await ops.inArray(users.nickname, values))

    expect((q.sql.match(/eql_v3\.eq/g) ?? []).length).toBe(values.length)
    expect(q.params).toEqual(values.map(() => TERM_JSON))
    // No fan-out anymore: the whole list crosses in a single batch call.
    expect(encryptQuery).toHaveBeenCalledTimes(1)
    const terms = encryptQuery.mock.calls[0]?.[0] as Array<{
      value: unknown
      column: { getName(): string }
    }>
    expect(terms.map((c) => c.value)).toEqual(values)
    expect(terms.every((c) => c.column.getName() === 'nickname')).toBe(true)
  })

  it('inArray on an ORE column uses ORE equality for each term', async () => {
    const { ops, render } = setup()
    const q = render(await ops.inArray(users.age, [30, 42]))
    expect(q.sql).toContain(' or ')
    expect((q.sql.match(/eql_v3\.eq/g) ?? []).length).toBe(2)
  })

  it('notInArray ANDs one ne term per value; empty array throws', async () => {
    const { ops, render } = setup()
    const q = render(await ops.notInArray(users.nickname, ['ada', 'grace']))
    expect(q.sql).toContain(' and ')
    await expect(ops.notInArray(users.nickname, [])).rejects.toThrow(
      /non-empty/,
    )
  })

  it('notInArray on an ORE column uses ORE inequality for each term', async () => {
    const { ops, render } = setup()
    const q = render(await ops.notInArray(users.age, [30, 42]))
    expect(q.sql).toContain(' and ')
    expect((q.sql.match(/eql_v3\.neq/g) ?? []).length).toBe(2)
  })

  it('inArray encrypts the whole list in a single encryptQuery batch crossing', async () => {
    const { ops, encryptQuery, render } = setup()
    const values = ['ada', 'grace', 'alan', 'katherine', 'dorothy']

    const q = render(await ops.inArray(users.nickname, values))

    expect(encryptQuery).toHaveBeenCalledTimes(1)
    const terms = encryptQuery.mock.calls[0]?.[0] as Array<{
      value: unknown
      column: { getName(): string }
    }>
    expect(terms.map((c) => c.value)).toEqual(values)
    expect(terms.every((c) => c.column.getName() === 'nickname')).toBe(true)
    expect((q.sql.match(/eql_v3\.eq/g) ?? []).length).toBe(values.length)
    expect(q.params).toEqual(values.map(() => TERM_JSON))
  })

  it('notInArray batch-encrypts once and ANDs one ne term per value', async () => {
    const { ops, encryptQuery, render } = setup()

    const q = render(await ops.notInArray(users.nickname, ['ada', 'grace']))

    expect(encryptQuery).toHaveBeenCalledTimes(1)
    expect((q.sql.match(/eql_v3\.neq/g) ?? []).length).toBe(2)
    expect(q.sql).toContain(' and ')
  })

  it('batch operand encryption carries the lock context and audit config', async () => {
    const { ops, encryptQuery } = setup()

    await ops.inArray(users.nickname, ['ada', 'grace'])

    const op = encryptQuery.mock.results[0]?.value
    expect(op.withLockContext).toHaveBeenCalledWith(lockContext)
    expect(op.audit).toHaveBeenCalledWith(audit)
  })

  it('batch terms keep their positions so each eq term matches its value', async () => {
    // Echo each value through the batch so a re-ordering inside `encryptOperands`
    // would surface as a mismatched param, not be masked by a constant term.
    const { ops, render } = setup((value) => ({ c: value }))

    const q = render(await ops.inArray(users.nickname, ['ada', 'grace']))

    expect(q.params).toEqual([
      JSON.stringify({ c: 'ada' }),
      JSON.stringify({ c: 'grace' }),
    ])
  })

  it('a batch encryption failure is wrapped with operator context', async () => {
    const { ops, encryptQuery } = setup()
    encryptQuery.mockReturnValueOnce(
      chainable(Promise.resolve({ failure: { message: 'bad query term' } })),
    )

    await expect(
      ops.inArray(users.nickname, ['ada', 'grace']),
    ).rejects.toMatchObject({
      name: 'EncryptionOperatorError',
      context: { columnName: 'nickname', operator: 'inArray' },
    })
  })

  it('a null value in the list throws before any encryption crossing', async () => {
    const { ops, encryptQuery } = setup()

    await expect(ops.inArray(users.nickname, ['ada', null])).rejects.toThrow(
      /isNull/,
    )
    expect(encryptQuery).not.toHaveBeenCalled()
  })

  it('a batch response of the wrong length is rejected rather than silently truncated', async () => {
    const { ops, encryptQuery } = setup()
    // One term for two values — the batch contract is violated.
    encryptQuery.mockReturnValue(chainable(Promise.resolve({ data: [TERM] })))

    // Pin the counts: an off-by-one guard, or a rejection thrown for some
    // unrelated reason, must not pass as "handled".
    await expect(ops.inArray(users.nickname, ['ada', 'grace'])).rejects.toThrow(
      /batch query encryption returned 1 terms for 2 values/,
    )
    await expect(
      ops.inArray(users.nickname, ['ada', 'grace']),
    ).rejects.toBeInstanceOf(EncryptionOperatorError)
  })

  it('inArray gates on the column capability before encrypting anything', async () => {
    const { ops, encryptQuery } = setup()

    await expect(ops.inArray(users.flag, [true])).rejects.toBeInstanceOf(
      EncryptionOperatorError,
    )
    expect(encryptQuery).not.toHaveBeenCalled()
  })

  it('and ignores undefined conditions and keeps the encrypted predicates', async () => {
    const { ops, render } = setup()
    const q = render(
      await ops.and(
        undefined,
        ops.eq(users.nickname, 'ada'),
        undefined,
        ops.gte(users.age, 30),
      ),
    )
    expect(q.sql).toContain('eql_v3.eq("users"."nickname"')
    expect(q.sql).toContain('eql_v3.gte("users"."age"')
    expect(q.sql).toContain(' and ')
  })

  it('empty and/or resolve to their neutral predicates', async () => {
    const { ops, render } = setup()
    expect(render(await ops.and()).sql).toBe('true')
    expect(render(await ops.or()).sql).toBe('false')
  })

  it('or combines encrypted and plain predicates', async () => {
    const { ops, render } = setup()
    const q = render(
      await ops.or(ops.eq(users.nickname, 'ada'), drizzleEq(users.id, 1)),
    )
    expect(q.sql).toContain(' or ')
    expect(q.sql).toContain('eql_v3.eq("users"."nickname"')
    expect(q.sql).toContain('"users"."id" = $2')
  })

  it('exports the passthrough Drizzle operators unchanged', () => {
    const { ops } = setup()
    expect(ops.isNull).toBe(isNull)
    expect(ops.isNotNull).toBe(isNotNull)
    expect(ops.not).toBe(not)
    expect(ops.exists).toBe(exists)
    expect(ops.notExists).toBe(notExists)
  })
})

describe('createEncryptionOperatorsV3 - gating errors', () => {
  it('wraps encryption failures with operator context', async () => {
    const { ops, encryptQuery } = setup()
    encryptQuery.mockReturnValueOnce(
      chainable(Promise.resolve({ failure: { message: 'bad query term' } })),
    )

    await expect(ops.eq(users.nickname, 'ada')).rejects.toMatchObject({
      name: 'EncryptionOperatorError',
    })
  })

  it('gt on an equality-only column throws', async () => {
    const { ops } = setup()
    await expect(ops.gt(users.nickname, 'ada')).rejects.toBeInstanceOf(
      EncryptionOperatorError,
    )
  })

  it('contains on a column without match throws', async () => {
    const { ops } = setup()
    await expect(ops.contains(users.nickname, 'ada')).rejects.toBeInstanceOf(
      EncryptionOperatorError,
    )
  })

  it('null operands throw and point callers to null checks', async () => {
    const { ops } = setup()
    await expect(ops.eq(users.nickname, null)).rejects.toThrow(/isNull/)
    await expect(ops.contains(users.email, undefined)).rejects.toThrow(/isNull/)
  })

  it('eq on a storage-only column throws', async () => {
    const { ops } = setup()
    await expect(ops.eq(users.flag, true)).rejects.toBeInstanceOf(
      EncryptionOperatorError,
    )
  })

  it('the equality gate reports the offending domain, as every other gate does', async () => {
    const { ops } = setup()

    // Same diagnostic shape as the ore/match gates: operator, capability,
    // column, and the domain that cannot answer it.
    await expect(ops.eq(users.flag, true)).rejects.toThrow(
      'Operator "eq" requires equality on column "flag" (domain public.eql_v3_boolean does not support it).',
    )
    await expect(ops.gt(users.nickname, 'ada')).rejects.toThrow(
      'Operator "gt" requires order/range on column "nickname" (domain public.eql_v3_text_eq does not support it).',
    )
  })

  it('asc on a non-ore column throws synchronously', () => {
    const { ops } = setup()
    expect(() => ops.asc(users.nickname)).toThrow(EncryptionOperatorError)
  })

  it('a non-v3 column throws', async () => {
    const { ops } = setup()
    await expect(ops.eq(users.id, 1)).rejects.toBeInstanceOf(
      EncryptionOperatorError,
    )
  })

  it('does not treat SQLWrapper objects with column-shaped fields as Drizzle columns', async () => {
    const { ops } = setup()
    const spoof = {
      name: 'nickname',
      table: users,
      getSQL: () => sql`"users"."nickname"`,
    } as unknown as SQLWrapper

    await expect(ops.eq(spoof, 'ada')).rejects.toMatchObject({
      name: 'EncryptionOperatorError',
      context: { columnName: 'unknown', operator: 'eq' },
    })
  })
})
