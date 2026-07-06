import { describe, expect, it } from 'vitest'
import { encryptedTable, types } from '@/eql/v3'
import {
  PrismaEncryptedColumnError,
  PrismaEncryptionError,
} from '@/eql/v3/prisma/errors'
import { createEncryptedExtension } from '@/eql/v3/prisma/extension'
import { buildModelMap } from '@/eql/v3/prisma/model-map'
import {
  createFailingEncryptionClient,
  createFakePrismaClient,
  createMockEncryptionClient,
  fakeEnvelope,
  fakePrismaNamespace,
  isFakeEnvelope,
  PrismaDbNull,
} from './mocks'

const users = encryptedTable('users', {
  email: types.TextEq('email'),
  age: types.IntegerOrd('age'),
  createdOn: types.TimestampOrd('created_on'),
})

type ExtendedHarness = {
  run(
    model: string,
    operation: string,
    args: Record<string, unknown>,
  ): Promise<unknown>
}

function setup(options?: {
  encryption?: ReturnType<typeof createMockEncryptionClient>
  baseQuery?: (call: {
    model: string
    operation: string
    args: Record<string, unknown>
  }) => unknown
  config?: { lockContext?: unknown; audit?: unknown }
}) {
  const encryption = options?.encryption ?? createMockEncryptionClient()
  const seen: Array<{
    model: string
    operation: string
    args: Record<string, unknown>
  }> = []
  const { client } = createFakePrismaClient((call) => {
    seen.push(call)
    return options?.baseQuery ? options.baseQuery(call) : null
  })
  const { byModel } = buildModelMap({ User: users })
  const extension = createEncryptedExtension({
    encryptionClient: encryption.client,
    prisma: fakePrismaNamespace,
    byModel,
    lockContext: options?.config?.lockContext as never,
    audit: options?.config?.audit as never,
  })
  const extended = client.$extends(
    extension as Parameters<typeof client.$extends>[0],
  ) as unknown as ExtendedHarness
  return { extended, seen, calls: encryption.calls }
}

describe('write path', () => {
  it('encrypts registered fields on create and passes others through', async () => {
    const { extended, seen } = setup()
    await extended.run('User', 'create', {
      data: { email: 'a@b.com', age: 30, plan: 'pro' },
    })
    const sent = seen[0].args.data as Record<string, unknown>
    expect(isFakeEnvelope(sent.email)).toBe(true)
    expect(isFakeEnvelope(sent.age)).toBe(true)
    expect(sent.plan).toBe('pro')
  })

  it('normalizes null encrypted fields to Prisma.DbNull', async () => {
    const { extended, seen } = setup()
    await extended.run('User', 'create', {
      data: { email: null, plan: 'free' },
    })
    const sent = seen[0].args.data as Record<string, unknown>
    expect(sent.email).toBe(PrismaDbNull)
    expect(sent.plan).toBe('free')
  })

  it('leaves absent and undefined fields untouched (Prisma "not provided")', async () => {
    const { extended, seen } = setup()
    await extended.run('User', 'update', {
      where: { id: 1 },
      data: { email: 'x@y.z', age: undefined },
    })
    const sent = seen[0].args.data as Record<string, unknown>
    expect(isFakeEnvelope(sent.email)).toBe(true)
    expect(sent.age).toBeUndefined()
    expect(sent.age !== PrismaDbNull).toBe(true)
  })

  it('bulk-encrypts createMany array data', async () => {
    const { extended, seen } = setup()
    await extended.run('User', 'createMany', {
      data: [{ email: 'a@a.com' }, { email: null }],
    })
    const sent = seen[0].args.data as Record<string, unknown>[]
    expect(isFakeEnvelope(sent[0].email)).toBe(true)
    expect(sent[1].email).toBe(PrismaDbNull)
  })

  it('handles createMany with a single object', async () => {
    const { extended, seen } = setup()
    await extended.run('User', 'createMany', {
      data: { email: 'a@a.com' },
    })
    const sent = seen[0].args.data as Record<string, unknown>
    expect(isFakeEnvelope(sent.email)).toBe(true)
  })

  it('encrypts both branches of upsert', async () => {
    const { extended, seen } = setup()
    await extended.run('User', 'upsert', {
      where: { id: 1 },
      create: { email: 'a@a.com' },
      update: { email: 'b@b.com' },
    })
    const args = seen[0].args as Record<string, Record<string, unknown>>
    expect(isFakeEnvelope(args.create.email)).toBe(true)
    expect(isFakeEnvelope(args.update.email)).toBe(true)
  })

  it('wraps encryption failures in PrismaEncryptionError', async () => {
    const { client } = createFakePrismaClient(() => null)
    const { byModel } = buildModelMap({ User: users })
    const extension = createEncryptedExtension({
      encryptionClient: createFailingEncryptionClient(),
      prisma: fakePrismaNamespace,
      byModel,
    })
    const extended = client.$extends(
      extension as Parameters<typeof client.$extends>[0],
    ) as unknown as ExtendedHarness
    await expect(
      extended.run('User', 'create', { data: { email: 'a@a.com' } }),
    ).rejects.toThrow(PrismaEncryptionError)
  })
})

describe('typed-query guard', () => {
  it.each([
    ['where', { where: { email: { equals: 'x' } } }],
    ['where', { where: { email: 'x' } }],
    ['nested AND', { where: { AND: [{ email: 'x' }] } }],
    ['nested OR of NOT', { where: { OR: [{ NOT: { email: 'x' } }] } }],
    ['orderBy object', { orderBy: { email: 'asc' } }],
    ['orderBy array', { orderBy: [{ email: 'asc' }] }],
    ['distinct', { distinct: ['email'] }],
    ['cursor', { cursor: { email: 'x' } }],
  ])('throws when an encrypted field appears in %s', async (_label, args) => {
    const { extended } = setup()
    await expect(extended.run('User', 'findMany', args)).rejects.toThrow(
      PrismaEncryptedColumnError,
    )
  })

  it('allows plaintext fields in where/orderBy/distinct', async () => {
    const { extended, seen } = setup()
    await extended.run('User', 'findMany', {
      where: { plan: 'pro', AND: [{ id: { gt: 3 } }] },
      orderBy: { id: 'desc' },
      distinct: ['plan'],
    })
    expect(seen).toHaveLength(1)
  })

  it('does not recurse into relation filter objects', async () => {
    // `posts` is a relation whose OWN model may have a field named `email` —
    // that is a different column and must not trip this table's guard.
    const { extended, seen } = setup()
    await extended.run('User', 'findMany', {
      where: { posts: { some: { email: 'x' } } },
    })
    expect(seen).toHaveLength(1)
  })

  it('guards where on count/aggregate but passes their result through', async () => {
    const { extended } = setup({ baseQuery: () => ({ _count: 3 }) })
    await expect(
      extended.run('User', 'count', { where: { email: 'x' } }),
    ).rejects.toThrow(PrismaEncryptedColumnError)
    const result = await extended.run('User', 'count', {
      where: { plan: 'pro' },
    })
    expect(result).toEqual({ _count: 3 })
  })
})

describe('read path', () => {
  const dbRow = () => ({
    id: 1,
    email: fakeEnvelope('a@b.com', 'email'),
    createdOn: fakeEnvelope(new Date('2026-01-02T03:04:05.000Z'), 'created_on'),
    plan: 'pro',
  })

  it('decrypts array results and reconstructs dates', async () => {
    const { extended } = setup({ baseQuery: () => [dbRow()] })
    const rows = (await extended.run('User', 'findMany', {})) as Record<
      string,
      unknown
    >[]
    expect(rows[0].email).toBe('a@b.com')
    expect(rows[0].createdOn).toBeInstanceOf(Date)
    expect((rows[0].createdOn as Date).toISOString()).toBe(
      '2026-01-02T03:04:05.000Z',
    )
    expect(rows[0].plan).toBe('pro')
  })

  it('decrypts single-object results (create/findUnique)', async () => {
    const { extended } = setup({ baseQuery: () => dbRow() })
    const row = (await extended.run('User', 'create', {
      data: { plan: 'pro' },
    })) as Record<string, unknown>
    expect(row.email).toBe('a@b.com')
  })

  it('passes null results through (findFirst miss)', async () => {
    const { extended } = setup({ baseQuery: () => null })
    expect(await extended.run('User', 'findFirst', {})).toBeNull()
  })

  it('passes batch payloads through untouched (createMany)', async () => {
    const { extended } = setup({ baseQuery: () => ({ count: 2 }) })
    const result = await extended.run('User', 'createMany', {
      data: [{ email: 'a@a.com' }],
    })
    expect(result).toEqual({ count: 2 })
  })
})

describe('model routing and plumbing', () => {
  it('passes unregistered models through untouched', async () => {
    const { extended, seen } = setup()
    const args = {
      data: { email: 'plain@text.com' },
      where: { email: 'plain@text.com' },
    }
    await extended.run('Post', 'create', args)
    expect(seen[0].args).toBe(args)
    expect((seen[0].args as { data: Record<string, unknown> }).data.email).toBe(
      'plain@text.com',
    )
  })

  it('applies config lockContext and audit to encrypt/decrypt operations', async () => {
    const lockContext = { kind: 'lc' }
    const audit = { metadata: { actor: 'ext' } }
    const encryption = createMockEncryptionClient()
    const { extended, calls } = setup({
      encryption,
      baseQuery: () => ({ id: 1, email: fakeEnvelope('a@b.com', 'email') }),
      config: { lockContext, audit },
    })
    await extended.run('User', 'create', { data: { email: 'a@b.com' } })
    // one encryptModel + one decryptModel, each with both applied
    expect(calls.lockContexts).toEqual([lockContext, lockContext])
    expect(calls.audits).toEqual([audit, audit])
  })
})
