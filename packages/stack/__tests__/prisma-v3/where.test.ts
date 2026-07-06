import { describe, expect, it } from 'vitest'
import { encryptedTable, types } from '@/eql/v3'
import {
  EncryptionOperatorError,
  PrismaEncryptionError,
} from '@/eql/v3/prisma/errors'
import { buildModelMap } from '@/eql/v3/prisma/model-map'
import { createEncryptedWhere } from '@/eql/v3/prisma/where'
import {
  type CapturedSql,
  createFailingEncryptionClient,
  createMockEncryptionClient,
  fakeEnvelope,
  fakePrismaNamespace,
  renderSql,
} from './mocks'

const users = encryptedTable('users', {
  email: types.TextEq('email'), // equality only
  name: types.TextSearch('name'), // equality + order + match
  age: types.IntegerOrd('age'), // order/range only (equality via ORE)
  bio: types.TextMatch('bio'), // match only
  note: types.Text('note'), // storage-only
  createdOn: types.TimestampOrd('created_on'), // db name differs from property
})

const unregistered = encryptedTable('other', {
  field: types.TextEq('field'),
})

function setup(encryption = createMockEncryptionClient()) {
  const { byColumn } = buildModelMap({ User: users })
  const where = createEncryptedWhere({
    encryptionClient: encryption.client,
    prisma: fakePrismaNamespace,
    byColumn,
  })
  return { where, calls: encryption.calls }
}

const envelopeJson = (value: unknown, column: string) =>
  JSON.stringify(fakeEnvelope(value, column))

describe('equality operators', () => {
  it('eq lowers to the two-arg eql_v3.eq with a full-envelope jsonb operand', async () => {
    const { where } = setup()
    const frag = (await where.eq(users.email, 'a@b.com')) as CapturedSql
    expect(renderSql(frag)).toBe('eql_v3.eq("email", $1::jsonb)')
    expect(frag.values).toEqual([envelopeJson('a@b.com', 'email')])
  })

  it('ne lowers to eql_v3.neq', async () => {
    const { where } = setup()
    const frag = (await where.ne(users.email, 'a@b.com')) as CapturedSql
    expect(renderSql(frag)).toBe('eql_v3.neq("email", $1::jsonb)')
  })

  it('eq on an order-only column is allowed (equality via ORE)', async () => {
    const { where } = setup()
    const frag = (await where.eq(users.age, 42)) as CapturedSql
    expect(renderSql(frag)).toBe('eql_v3.eq("age", $1::jsonb)')
  })

  it('eq on a match-only column throws with context', async () => {
    const { where } = setup()
    await expect(where.eq(users.bio, 'x')).rejects.toThrow(
      EncryptionOperatorError,
    )
    await expect(where.eq(users.bio, 'x')).rejects.toThrow(/bio/)
  })

  it('eq on a storage-only column throws', async () => {
    const { where } = setup()
    await expect(where.eq(users.note, 'x')).rejects.toThrow(
      EncryptionOperatorError,
    )
  })

  it('a column from an unregistered table throws', async () => {
    const { where } = setup()
    await expect(where.eq(unregistered.field, 'x')).rejects.toThrow(
      /not registered/i,
    )
  })

  it('a null operand throws and points at isNull', async () => {
    const { where } = setup()
    await expect(
      where.eq(users.email, null as unknown as string),
    ).rejects.toThrow(/isNull/)
  })
})

describe('comparison operators', () => {
  it.each([
    ['gt', 'eql_v3.gt'],
    ['gte', 'eql_v3.gte'],
    ['lt', 'eql_v3.lt'],
    ['lte', 'eql_v3.lte'],
  ] as const)('%s lowers to %s', async (op, fn) => {
    const { where } = setup()
    const frag = (await where[op](users.age, 30)) as CapturedSql
    expect(renderSql(frag)).toBe(`${fn}("age", $1::jsonb)`)
    expect(frag.values).toEqual([envelopeJson(30, 'age')])
  })

  it('comparison on a column without an ore index throws', async () => {
    const { where } = setup()
    await expect(where.gt(users.email, 'x')).rejects.toThrow(
      EncryptionOperatorError,
    )
  })

  it('between composes gte AND lte with two operands', async () => {
    const { where } = setup()
    const frag = (await where.between(users.age, 10, 90)) as CapturedSql
    expect(renderSql(frag)).toBe(
      '(eql_v3.gte("age", $1::jsonb) AND eql_v3.lte("age", $2::jsonb))',
    )
    expect(frag.values).toEqual([
      envelopeJson(10, 'age'),
      envelopeJson(90, 'age'),
    ])
  })

  it('notBetween wraps the range in NOT', async () => {
    const { where } = setup()
    const frag = (await where.notBetween(users.age, 10, 90)) as CapturedSql
    expect(renderSql(frag)).toBe(
      'NOT (eql_v3.gte("age", $1::jsonb) AND eql_v3.lte("age", $2::jsonb))',
    )
  })
})

describe('free-text match', () => {
  it('contains lowers to eql_v3.contains', async () => {
    const { where } = setup()
    const frag = (await where.contains(users.name, 'ada')) as CapturedSql
    expect(renderSql(frag)).toBe('eql_v3.contains("name", $1::jsonb)')
  })

  it('contains on a column without a match index throws', async () => {
    const { where } = setup()
    await expect(where.contains(users.email, 'x')).rejects.toThrow(
      EncryptionOperatorError,
    )
  })
})

describe('list operators', () => {
  it('in joins equality fragments with OR', async () => {
    const { where } = setup()
    const frag = (await where.in(users.email, ['a', 'b'])) as CapturedSql
    expect(renderSql(frag)).toBe(
      '(eql_v3.eq("email", $1::jsonb) OR eql_v3.eq("email", $2::jsonb))',
    )
    expect(frag.values).toEqual([
      envelopeJson('a', 'email'),
      envelopeJson('b', 'email'),
    ])
  })

  it('notIn joins inequality fragments with AND', async () => {
    const { where } = setup()
    const frag = (await where.notIn(users.email, ['a', 'b'])) as CapturedSql
    expect(renderSql(frag)).toBe(
      '(eql_v3.neq("email", $1::jsonb) AND eql_v3.neq("email", $2::jsonb))',
    )
  })

  it('preserves operand order for long lists (bounded concurrency)', async () => {
    const { where } = setup()
    const values = Array.from({ length: 10 }, (_, i) => `v${i}`)
    const frag = (await where.in(users.email, values)) as CapturedSql
    expect(frag.values).toEqual(values.map((v) => envelopeJson(v, 'email')))
  })

  it('an empty list throws', async () => {
    const { where } = setup()
    await expect(where.in(users.email, [])).rejects.toThrow(/empty/i)
  })
})

describe('ordering and null checks', () => {
  it('orderBy emits ord_term with the default ASC direction', () => {
    const { where } = setup()
    const frag = where.orderBy(users.age) as CapturedSql
    expect(renderSql(frag)).toBe('eql_v3.ord_term("age") ASC')
    expect(frag.values).toEqual([])
  })

  it('orderBy desc', () => {
    const { where } = setup()
    const frag = where.orderBy(users.age, 'desc') as CapturedSql
    expect(renderSql(frag)).toBe('eql_v3.ord_term("age") DESC')
  })

  it('orderBy on a column without an ore index throws', () => {
    const { where } = setup()
    expect(() => where.orderBy(users.email)).toThrow(EncryptionOperatorError)
  })

  it('isNull / isNotNull work on any column, including storage-only', () => {
    const { where } = setup()
    expect(renderSql(where.isNull(users.note) as CapturedSql)).toBe(
      '"note" IS NULL',
    )
    expect(renderSql(where.isNotNull(users.email) as CapturedSql)).toBe(
      '"email" IS NOT NULL',
    )
  })
})

describe('identifiers and mapping', () => {
  it('uses the db column name, not the JS property name', async () => {
    const { where } = setup()
    const frag = where.orderBy(users.createdOn) as CapturedSql
    expect(renderSql(frag)).toBe('eql_v3.ord_term("created_on") ASC')
  })

  it('escapes double quotes in column identifiers', async () => {
    const weird = encryptedTable('weird', {
      col: types.TextEq('we"ird'),
    })
    const { byColumn } = buildModelMap({ Weird: weird })
    const where = createEncryptedWhere({
      encryptionClient: createMockEncryptionClient().client,
      prisma: fakePrismaNamespace,
      byColumn,
    })
    const frag = (await where.eq(weird.col, 'x')) as CapturedSql
    expect(renderSql(frag)).toBe('eql_v3.eq("we""ird", $1::jsonb)')
  })
})

describe('operation plumbing', () => {
  it('passes lockContext and audit through to the encrypt operation', async () => {
    const encryption = createMockEncryptionClient()
    const { where, calls } = setup(encryption)
    const lockContext = { kind: 'lc' }
    const audit = { metadata: { actor: 'test' } }
    await where.eq(users.email, 'a@b.com', { lockContext, audit })
    expect(calls.lockContexts).toEqual([lockContext])
    expect(calls.audits).toEqual([audit])
  })

  it('wraps encryption failures in PrismaEncryptionError', async () => {
    const { byColumn } = buildModelMap({ User: users })
    const where = createEncryptedWhere({
      encryptionClient: createFailingEncryptionClient('nope'),
      prisma: fakePrismaNamespace,
      byColumn,
    })
    await expect(where.eq(users.email, 'x')).rejects.toThrow(
      PrismaEncryptionError,
    )
  })
})
