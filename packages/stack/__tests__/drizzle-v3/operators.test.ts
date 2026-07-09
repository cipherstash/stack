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
import { makeEqlV3Column } from '@/eql/v3/drizzle/column'
import {
  createEncryptionOperatorsV3,
  EncryptionOperatorError,
} from '@/eql/v3/drizzle/operators'
import { extractEncryptionSchemaV3 } from '@/eql/v3/drizzle/schema-extraction'
import { types } from '@/eql/v3/drizzle/types'
import {
  eqlTypeSlug as slug,
  typedEntries,
  V3_MATRIX,
} from '../v3-matrix/catalog'

const TERM = { c: 'ct', v: 1 }
const TERM_JSON = JSON.stringify(TERM)
const lockContext = { identityClaim: 'user-123' }
const audit = { metadata: { actor: 'test' } }

type EncryptResult = Promise<
  { data: typeof TERM } | { failure: { message: string } }
>

function chainable(result: EncryptResult) {
  const op = result as EncryptResult & {
    withLockContext: ReturnType<typeof vi.fn>
    audit: ReturnType<typeof vi.fn>
  }
  op.withLockContext = vi.fn(() => op)
  op.audit = vi.fn(() => op)
  return op
}

function setup(
  encryptImpl: (...args: unknown[]) => EncryptResult = async () => ({
    data: TERM,
  }),
) {
  const encrypt = vi.fn((...args: unknown[]) => chainable(encryptImpl(...args)))
  // The factory's `client` parameter is the structural `{ encrypt }` surface,
  // so this hand-rolled double satisfies it with no cast (M1).
  const client = { encrypt }
  const ops = createEncryptionOperatorsV3(client, { lockContext, audit })
  const dialect = new PgDialect()
  const render = (s: unknown) => dialect.sqlToQuery(s as SQL)
  return { ops, encrypt, render }
}

type BulkPayload = Array<{ id?: string; plaintext: unknown }>
type BulkResult = Promise<
  { data: Array<{ data: typeof TERM }> } | { failure: { message: string } }
>

/**
 * A double for the fuller client surface — one that also exposes `bulkEncrypt`,
 * as the real `TypedEncryptionClient` does. `inArray`/`notInArray` should
 * prefer it over N single `encrypt` crossings.
 */
function setupBulk(
  bulkImpl: (payloads: BulkPayload) => BulkResult = async (payloads) => ({
    data: payloads.map(() => ({ data: TERM })),
  }),
) {
  const encrypt = vi.fn(() => chainable(Promise.resolve({ data: TERM })))
  const bulkEncrypt = vi.fn((payloads: BulkPayload, ..._rest: unknown[]) =>
    chainable(bulkImpl(payloads) as never),
  )
  const client = { encrypt, bulkEncrypt }
  const ops = createEncryptionOperatorsV3(client, { lockContext, audit })
  const dialect = new PgDialect()
  const render = (s: unknown) => dialect.sqlToQuery(s as SQL)
  return { ops, encrypt, bulkEncrypt, render }
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

// `contains` needles must reach the match tokenizer's `token_length` (3), so
// they cannot come from `sampleFor` — `TEXT_S[0]` is the empty string, which
// tokenizes to nothing and is rejected as unanswerable.
const needleFor = (
  spec: (typeof V3_MATRIX)[keyof typeof V3_MATRIX],
): string => {
  const needle = spec.samples.find(
    (sample) => typeof sample === 'string' && sample.length >= 3,
  )
  if (typeof needle !== 'string') {
    throw new Error('no searchable sample for a match domain')
  }
  return needle
}

const equalityDomains = matrixEntries.filter(
  ([, spec]) => spec.indexes.unique || spec.indexes.ore,
)
const orderDomains = matrixEntries.filter(([, spec]) => spec.indexes.ore)
const matchDomains = matrixEntries.filter(([, spec]) => spec.indexes.match)
const storageDomains = matrixEntries.filter(
  ([, spec]) =>
    !spec.indexes.unique && !spec.indexes.ore && !spec.indexes.match,
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
  )('%s eq emits the latest two-arg eql_v3.eq with a full-envelope operand', async (eqlType, spec) => {
    const { ops, encrypt, render } = setup()
    const q = render(await ops.eq(matrixColumn(eqlType), sampleFor(spec)))

    expect(q.sql).toContain(
      `eql_v3.eq("matrix_users"."${slug(eqlType)}", $1::jsonb)`,
    )
    expect(q.params).toEqual([TERM_JSON])
    expect(encrypt.mock.calls[0]?.[1]?.column.getName()).toBe(slug(eqlType))
  })

  it.each(equalityDomains)('%s ne emits eql_v3.neq', async (eqlType, spec) => {
    const { ops, encrypt, render } = setup()
    const q = render(await ops.ne(matrixColumn(eqlType), sampleFor(spec)))

    expect(q.sql).toContain(
      `eql_v3.neq("matrix_users"."${slug(eqlType)}", $1::jsonb)`,
    )
    expect(q.params).toEqual([TERM_JSON])
    expect(encrypt.mock.calls[0]?.[1]?.column.getName()).toBe(slug(eqlType))
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

    expect(q.sql).toContain('eql_v3.eq("accounts"."email", $1::jsonb)')
  })

  it('does not reuse a cached extracted schema across distinct pgTable objects with the same SQL name', async () => {
    const first = pgTable('shared', {
      email: types.TextEq('email'),
    })
    const second = pgTable('shared', {
      age: types.IntegerOrd('age'),
    })
    const { ops, encrypt } = setup()

    await ops.eq(first.email, 'ada@example.com')
    await ops.eq(second.age, 37)

    expect(encrypt.mock.calls[1]?.[1]?.table.build()).toEqual(
      extractEncryptionSchemaV3(second).build(),
    )
  })

  it('passes default lock context and audit to operand encryption', async () => {
    const { ops, encrypt } = setup()
    await ops.eq(users.nickname, 'ada')
    const op = encrypt.mock.results[0]?.value
    expect(op.withLockContext).toHaveBeenCalledWith(lockContext)
    expect(op.audit).toHaveBeenCalledWith(audit)
  })

  it('per-call lock context and audit override constructor defaults', async () => {
    const { ops, encrypt } = setup()
    const callLockContext = { identityClaim: 'user-456' }
    const callAudit = { metadata: { actor: 'override' } }

    await ops.eq(users.nickname, 'ada', {
      lockContext: callLockContext,
      audit: callAudit,
    })

    const op = encrypt.mock.results[0]?.value
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
      const { ops, encrypt, render } = setup()
      const q = render(await ops[op](matrixColumn(eqlType), sampleFor(spec)))

      expect(q.sql).toContain(
        `${fn}("matrix_users"."${slug(eqlType)}", $1::jsonb)`,
      )
      expect(q.params).toEqual([TERM_JSON])
      expect(encrypt.mock.calls[0]?.[1]?.column.getName()).toBe(slug(eqlType))
    }
  })

  it.each(
    orderDomains,
  )('%s between emits a bounded range with two full-envelope operands', async (eqlType, spec) => {
    const { ops, render } = setup()
    const value = sampleFor(spec)
    const q = render(await ops.between(matrixColumn(eqlType), value, value))

    expect(q.sql).toContain(
      `eql_v3.gte("matrix_users"."${slug(eqlType)}", $1::jsonb)`,
    )
    expect(q.sql).toContain(
      `eql_v3.lte("matrix_users"."${slug(eqlType)}", $2::jsonb)`,
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
      `eql_v3.gte("matrix_users"."${slug(eqlType)}", $1::jsonb)`,
    )
    expect(q.sql).toContain(
      `eql_v3.lte("matrix_users"."${slug(eqlType)}", $2::jsonb)`,
    )
    expect(q.params).toEqual([TERM_JSON, TERM_JSON])
  })

  // Every other `between` case passes identical bounds against a constant
  // encrypt stub, so the operand never reaches an assertion and a min/max
  // transposition inside `range` is invisible. Echo the plaintext through the
  // stub instead, and pin that `gte` binds `min` and `lte` binds `max`.
  it('between binds min to gte and max to lte, in that order', async () => {
    const { ops, render } = setup(async (value) => ({
      data: { p: value } as never,
    }))

    const q = render(await ops.between(users.age, -128, 127))

    expect(q.sql).toBe(
      '(eql_v3.gte("users"."age", $1::jsonb) AND eql_v3.lte("users"."age", $2::jsonb))',
    )
    expect(q.params).toEqual(['{"p":-128}', '{"p":127}'])
  })

  it('notBetween binds min to gte and max to lte, in that order', async () => {
    const { ops, render } = setup(async (value) => ({
      data: { p: value } as never,
    }))

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
      'not (eql_v3.gte("users"."age", $1::jsonb) AND eql_v3.lte("users"."age", $2::jsonb))',
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
      '(eql_v3.gte("users"."age", $1::jsonb) AND eql_v3.lte("users"."age", $2::jsonb))',
    )
  })

  it.each(orderDomains)('%s asc / desc extract the ord term', (eqlType) => {
    const { ops, render } = setup()
    const ascq = render(ops.asc(matrixColumn(eqlType)))
    expect(ascq.sql).toContain(
      `eql_v3.ord_term("matrix_users"."${slug(eqlType)}")`,
    )
    expect(ascq.sql.toLowerCase()).toContain('asc')

    const descq = render(ops.desc(matrixColumn(eqlType)))
    expect(descq.sql).toContain(
      `eql_v3.ord_term("matrix_users"."${slug(eqlType)}")`,
    )
    expect(descq.sql.toLowerCase()).toContain('desc')
  })
})

describe('createEncryptionOperatorsV3 - free-text match', () => {
  it.each(
    matchDomains,
  )('%s contains emits latest eql_v3.contains with a full-envelope operand', async (eqlType, spec) => {
    const { ops, encrypt, render } = setup()
    const q = render(await ops.contains(matrixColumn(eqlType), needleFor(spec)))

    expect(q.sql).toContain(
      `eql_v3.contains("matrix_users"."${slug(eqlType)}", $1::jsonb)`,
    )
    expect(q.params).toEqual([TERM_JSON])
    expect(encrypt.mock.calls[0]?.[1]?.column.getName()).toBe(slug(eqlType))
  })

  // A needle shorter than the tokenizer's `token_length` produces an empty
  // bloom filter, and `stored_bf @> '{}'` is true for every row — so this must
  // throw rather than silently return the whole table.
  it.each(
    matchDomains,
  )('%s contains rejects a needle shorter than token_length before encrypting', async (eqlType) => {
    const { ops, encrypt } = setup()
    await expect(ops.contains(matrixColumn(eqlType), 'ad')).rejects.toThrow(
      /at least 3 characters/,
    )
    await expect(ops.contains(matrixColumn(eqlType), '')).rejects.toThrow(
      EncryptionOperatorError,
    )
    expect(encrypt).not.toHaveBeenCalled()
  })

  it('contains accepts a needle exactly at token_length', async () => {
    const { ops, render } = setup()
    const q = render(await ops.contains(users.email, 'ada'))
    expect(q.sql).toContain('eql_v3.contains("users"."email", $1::jsonb)')
  })

  it('negation is expressed through the passthrough Drizzle not operator', async () => {
    const { ops, render } = setup()
    const q = render(ops.not(await ops.contains(users.email, 'example.com')))
    expect(q.sql).toMatch(/^not /i)
    expect(q.sql).toContain('eql_v3.contains("users"."email", $1::jsonb)')
  })

  it('does not expose obsolete like/ilike helpers', () => {
    const { ops } = setup()
    expect('like' in ops).toBe(false)
    expect('ilike' in ops).toBe(false)
    expect('notIlike' in ops).toBe(false)
  })
})

describe('createEncryptionOperatorsV3 - storage-only domains', () => {
  it.each(storageDomains)('%s eq throws', async (eqlType, spec) => {
    const { ops } = setup()
    await expect(
      ops.eq(matrixColumn(eqlType), sampleFor(spec)),
    ).rejects.toBeInstanceOf(EncryptionOperatorError)
  })

  it.each(storageDomains)('%s contains throws', async (eqlType, spec) => {
    const { ops } = setup()
    await expect(
      ops.contains(matrixColumn(eqlType), sampleFor(spec)),
    ).rejects.toBeInstanceOf(EncryptionOperatorError)
  })

  it.each(storageDomains)('%s asc throws synchronously', (eqlType) => {
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

  it('inArray fans out more than MAX_IN_ARRAY_CONCURRENCY values exactly once', async () => {
    const { ops, encrypt, render } = setup()
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
    expect(encrypt).toHaveBeenCalledTimes(values.length)
    expect(encrypt.mock.calls.map(([value]) => value).sort()).toEqual(
      [...values].sort(),
    )
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

  it('inArray encrypts the whole list in a single bulkEncrypt crossing', async () => {
    const { ops, encrypt, bulkEncrypt, render } = setupBulk()
    const values = ['ada', 'grace', 'alan', 'katherine', 'dorothy']

    const q = render(await ops.inArray(users.nickname, values))

    expect(bulkEncrypt).toHaveBeenCalledTimes(1)
    expect(encrypt).not.toHaveBeenCalled()
    expect(bulkEncrypt.mock.calls[0]?.[0]).toEqual(
      values.map((plaintext) => ({ plaintext })),
    )
    const opts = bulkEncrypt.mock.calls[0]?.[1] as {
      column: { getName(): string }
    }
    expect(opts.column.getName()).toBe('nickname')
    expect((q.sql.match(/eql_v3\.eq/g) ?? []).length).toBe(values.length)
    expect(q.params).toEqual(values.map(() => TERM_JSON))
  })

  it('notInArray bulk-encrypts once and ANDs one ne term per value', async () => {
    const { ops, bulkEncrypt, render } = setupBulk()

    const q = render(await ops.notInArray(users.nickname, ['ada', 'grace']))

    expect(bulkEncrypt).toHaveBeenCalledTimes(1)
    expect((q.sql.match(/eql_v3\.neq/g) ?? []).length).toBe(2)
    expect(q.sql).toContain(' and ')
  })

  it('bulk operand encryption carries the lock context and audit config', async () => {
    const { ops, bulkEncrypt } = setupBulk()

    await ops.inArray(users.nickname, ['ada', 'grace'])

    const op = bulkEncrypt.mock.results[0]?.value
    expect(op.withLockContext).toHaveBeenCalledWith(lockContext)
    expect(op.audit).toHaveBeenCalledWith(audit)
  })

  it('bulk terms keep their positions so each eq term matches its value', async () => {
    const terms = [{ c: 'ada' }, { c: 'grace' }] as unknown as Array<{
      data: typeof TERM
    }>
    const { ops, render } = setupBulk(async () => ({
      data: [{ data: terms[0] as never }, { data: terms[1] as never }],
    }))

    const q = render(await ops.inArray(users.nickname, ['ada', 'grace']))

    expect(q.params).toEqual([
      JSON.stringify(terms[0]),
      JSON.stringify(terms[1]),
    ])
  })

  it('a bulk encryption failure is wrapped with operator context', async () => {
    const { ops } = setupBulk(async () => ({
      failure: { message: 'bad query term' },
    }))

    await expect(
      ops.inArray(users.nickname, ['ada', 'grace']),
    ).rejects.toMatchObject({
      name: 'EncryptionOperatorError',
      context: { columnName: 'nickname', operator: 'inArray' },
    })
  })

  it('a null value in the list throws before any encryption crossing', async () => {
    const { ops, bulkEncrypt } = setupBulk()

    await expect(ops.inArray(users.nickname, ['ada', null])).rejects.toThrow(
      /isNull/,
    )
    expect(bulkEncrypt).not.toHaveBeenCalled()
  })

  it('a bulk response of the wrong length is rejected rather than silently truncated', async () => {
    const { ops } = setupBulk(async () => ({ data: [{ data: TERM }] }))

    // Pin the counts: an off-by-one guard, or a rejection thrown for some
    // unrelated reason, must not pass as "handled".
    await expect(ops.inArray(users.nickname, ['ada', 'grace'])).rejects.toThrow(
      /bulk encryption returned 1 terms for 2 values/,
    )
    await expect(
      ops.inArray(users.nickname, ['ada', 'grace']),
    ).rejects.toBeInstanceOf(EncryptionOperatorError)
  })

  it('inArray gates on the column capability before encrypting anything', async () => {
    const { ops, bulkEncrypt } = setupBulk()

    await expect(ops.inArray(users.flag, [true])).rejects.toBeInstanceOf(
      EncryptionOperatorError,
    )
    expect(bulkEncrypt).not.toHaveBeenCalled()
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
    const { ops } = setup(async () => ({
      failure: { message: 'bad query term' },
    }))

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
      'Operator "eq" requires equality on column "flag" (domain public.boolean does not support it).',
    )
    await expect(ops.gt(users.nickname, 'ada')).rejects.toThrow(
      'Operator "gt" requires order/range on column "nickname" (domain public.text_eq does not support it).',
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
