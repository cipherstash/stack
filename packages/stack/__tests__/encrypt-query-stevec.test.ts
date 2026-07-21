import 'dotenv/config'
import { beforeAll, describe, expect, it } from 'vitest'
import { encryptedTable, types } from '@/eql/v3'
import { Encryption } from '@/index'
import { expectFailure, unwrapResult } from './fixtures'

type EncryptionClient = Awaited<ReturnType<typeof Encryption>>

const documents = encryptedTable('documents', {
  metadata: types.Json('metadata'),
})
const plain = encryptedTable('plain', { raw: types.Text('raw') })

function expectSelector(value: unknown): asserts value is string {
  expect(typeof value).toBe('string')
  expect((value as string).length).toBeGreaterThan(0)
}

function expectQueryJson(value: unknown): void {
  expect(value).toMatchObject({ sv: expect.any(Array) })
  expect(JSON.stringify(value)).not.toContain('"c"')
}

function expectOrderingTerm(value: unknown): void {
  expect(value).toMatchObject({ v: 3, op: expect.any(String) })
  expect(value).not.toHaveProperty('c')
}

describe('encryptQuery with protect-ffi 0.30 SteVec operations', () => {
  let client: EncryptionClient

  beforeAll(async () => {
    client = await Encryption({ schemas: [documents, plain] })
  })

  it('returns a bare selector hash for a JSONPath', async () => {
    const result = await client.encryptQuery('$.user.email', {
      column: documents.metadata,
      table: documents,
      queryType: 'steVecSelector',
    })
    expectSelector(unwrapResult(result))
  }, 30000)

  it('returns an exact value-selector containment needle', async () => {
    const result = await client.encryptQuery(
      { path: '$.user.age', value: 42 },
      {
        column: documents.metadata,
        table: documents,
        queryType: 'steVecValueSelector',
      },
    )
    expectQueryJson(unwrapResult(result))
  }, 30000)

  it.each([
    'zoe',
    42,
  ])('returns a ciphertext-free selector ordering term for %j', async (value) => {
    const result = await client.encryptQuery(value, {
      column: documents.metadata,
      table: documents,
      queryType: 'steVecTerm',
    })
    expectOrderingTerm(unwrapResult(result))
  }, 30000)

  it.each([
    { role: 'admin' },
    ['admin', 'user'],
  ])('uses default structural containment for %j', async (value) => {
    const result = await client.encryptQuery(value, {
      column: documents.metadata,
      table: documents,
      queryType: 'searchableJson',
    })
    expectQueryJson(unwrapResult(result))
  }, 30000)

  it('infers selector versus containment when queryType is omitted', async () => {
    const selector = await client.encryptQuery('$.user.email', {
      column: documents.metadata,
      table: documents,
    })
    const containment = await client.encryptQuery(
      { role: 'admin' },
      {
        column: documents.metadata,
        table: documents,
      },
    )
    expectSelector(unwrapResult(selector))
    expectQueryJson(unwrapResult(containment))
  }, 30000)

  it('supports every SteVec query shape in one batch', async () => {
    const result = await client.encryptQuery([
      {
        value: '$.user.email',
        column: documents.metadata,
        table: documents,
        queryType: 'steVecSelector',
      },
      {
        value: { path: '$.user.age', value: 42 },
        column: documents.metadata,
        table: documents,
        queryType: 'steVecValueSelector',
      },
      {
        value: 42,
        column: documents.metadata,
        table: documents,
        queryType: 'steVecTerm',
      },
      {
        value: { role: 'admin' },
        column: documents.metadata,
        table: documents,
        queryType: 'searchableJson',
      },
    ])
    const data = unwrapResult(result)
    expectSelector(data[0])
    expectQueryJson(data[1])
    expectOrderingTerm(data[2])
    expectQueryJson(data[3])
  }, 30000)

  it('rejects SteVec query operations on a non-SteVec column', async () => {
    const result = await client.encryptQuery('$.user.email', {
      column: plain.raw,
      table: plain,
      queryType: 'steVecSelector',
    })
    expectFailure(result, /not configured/)
  }, 30000)
})
