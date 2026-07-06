import { describe, expect, it } from 'vitest'
import { encryptedTable, types } from '@/eql/v3'
import { encryptedPrisma } from '@/eql/v3/prisma'
import {
  type CapturedSql,
  createFakePrismaClient,
  createMockEncryptionClient,
  fakeEnvelope,
  fakePrismaNamespace,
  isFakeEnvelope,
  renderSql,
} from './mocks'

const users = encryptedTable('users', {
  email: types.TextEq('email'),
  createdOn: types.TimestampOrd('created_on'),
})

const audits = encryptedTable('audits', {
  actor: types.TextEq('actor'),
})

function setup(baseQuery: Parameters<typeof createFakePrismaClient>[0]) {
  const encryption = createMockEncryptionClient()
  const fake = createFakePrismaClient(baseQuery)
  const instance = encryptedPrisma({
    encryptionClient: encryption.client,
    prismaClient: fake.client,
    prisma: fakePrismaNamespace,
    tables: { User: users },
  })
  return { instance, fake, calls: encryption.calls }
}

describe('encryptedPrisma factory', () => {
  it('returns the extended client, where builders, and $queryRawEncrypted', () => {
    const { instance } = setup(() => null)
    expect(instance.client).toMatchObject({ __extended: true })
    expect(typeof instance.where.eq).toBe('function')
    expect(typeof instance.$queryRawEncrypted).toBe('function')
  })

  it('the extension and where builders share the registration', async () => {
    const { instance } = setup(() => null)
    const frag = (await instance.where.eq(
      users.email,
      'a@b.com',
    )) as CapturedSql
    expect(renderSql(frag)).toBe('eql_v3.eq("email", $1::jsonb)')
  })
})

describe('$queryRawEncrypted', () => {
  const dbRows = () => [
    {
      id: 1,
      email: fakeEnvelope('a@b.com', 'email'),
      created_on: fakeEnvelope(
        new Date('2026-01-02T03:04:05.000Z'),
        'created_on',
      ),
      plan: 'pro',
    },
  ]

  it('passes the fragment to $queryRaw and decrypts db-name-keyed rows', async () => {
    const { instance, fake } = setup(() => dbRows())
    const query = fakePrismaNamespace.sql(['SELECT * FROM users'])
    const rows = await instance.$queryRawEncrypted(users, query)
    expect(fake.captured.rawQueries).toEqual([query])
    expect(rows[0].email).toBe('a@b.com')
    expect(rows[0].plan).toBe('pro')
  })

  it('reconstructs dates under the db column name', async () => {
    const { instance } = setup(() => dbRows())
    const rows = await instance.$queryRawEncrypted(
      users,
      fakePrismaNamespace.sql(['SELECT * FROM users']),
    )
    expect(rows[0].created_on).toBeInstanceOf(Date)
    expect((rows[0].created_on as Date).toISOString()).toBe(
      '2026-01-02T03:04:05.000Z',
    )
  })

  it('decrypts against an unregistered table schema too', async () => {
    const { instance } = setup(() => [{ actor: fakeEnvelope('root', 'actor') }])
    const rows = await instance.$queryRawEncrypted(
      audits,
      fakePrismaNamespace.sql(['SELECT * FROM audits']),
    )
    expect(rows[0].actor).toBe('root')
  })

  it('passes per-call lockContext and audit to the decrypt operation', async () => {
    const { instance, calls } = setup(() => dbRows())
    const lockContext = { kind: 'lc' }
    const audit = { metadata: { actor: 'raw' } }
    await instance.$queryRawEncrypted(
      users,
      fakePrismaNamespace.sql(['SELECT * FROM users']),
      { lockContext: lockContext as never, audit },
    )
    expect(calls.lockContexts).toEqual([lockContext])
    expect(calls.audits).toEqual([audit])
  })

  it('returns non-row results untouched', async () => {
    const { instance } = setup(() => [])
    const rows = await instance.$queryRawEncrypted(
      users,
      fakePrismaNamespace.sql(['SELECT * FROM users WHERE 1=0']),
    )
    expect(rows).toEqual([])
  })
})

describe('end-to-end write through the extended client', () => {
  it('routes model operations through the extension', async () => {
    const seen: Array<{ args: Record<string, unknown> }> = []
    const { instance } = setup((call) => {
      seen.push(call)
      return null
    })
    const harness = instance.client as unknown as {
      run(
        model: string,
        operation: string,
        args: Record<string, unknown>,
      ): Promise<unknown>
    }
    await harness.run('User', 'create', { data: { email: 'a@b.com' } })
    const sent = seen[0].args.data as Record<string, unknown>
    expect(isFakeEnvelope(sent.email)).toBe(true)
  })
})
