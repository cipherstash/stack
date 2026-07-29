import 'dotenv/config'
import { beforeAll, describe, expect, it } from 'vitest'
import type { EncryptionClient } from '@/encryption'
import { encryptedTable, types } from '@/eql/v3'
import { Encryption } from '@/index'
import { createMockLockContext, expectFailure, unwrapResult } from './fixtures'

const documents = encryptedTable('documents', {
  metadata: types.Json('metadata'),
})

function expectSelector(value: unknown): asserts value is string {
  expect(typeof value).toBe('string')
  expect((value as string).length).toBeGreaterThan(0)
}

function expectContainment(value: unknown): void {
  expect(value).toMatchObject({ sv: expect.any(Array) })
  expect(JSON.stringify(value)).not.toContain('"c"')
}

describe('encryptQuery with searchableJson', () => {
  // NOTE: this suite holds the client through the NOMINAL surface on purpose.
  // The typed client derives `encryptQuery`'s plaintext from the column's domain,
  // so every query type on a `types.Json()` column is typed `JsonDocument` — but
  // the searchable-JSON query types take a JSONPath string, a `{ path, value }`
  // pair, or a bare scalar. This file exercises exactly those, so typing it
  // against the typed client would mean casting away the argument type at every
  // call and hiding the gap. Cast once, here, where it is visible and explained.
  let client: EncryptionClient

  beforeAll(async () => {
    client = (await Encryption({
      schemas: [documents],
    })) as unknown as EncryptionClient
  })

  it('infers a selector hash for string plaintext', async () => {
    const result = await client.encryptQuery('$.user.email', {
      column: documents.metadata,
      table: documents,
      queryType: 'searchableJson',
    })
    expectSelector(unwrapResult(result))
  }, 30000)

  it.each([
    { role: 'admin' },
    { user: { profile: { role: 'admin' } } },
    ['admin', 'user'],
  ])('uses default structural containment for %j', async (value) => {
    const result = await client.encryptQuery(value, {
      column: documents.metadata,
      table: documents,
      queryType: 'searchableJson',
    })
    expectContainment(unwrapResult(result))
  }, 30000)

  it.each([
    42,
    true,
  ])('rejects a top-level JSON scalar containment needle (%j)', async (value) => {
    const result = await client.encryptQuery(value, {
      column: documents.metadata,
      table: documents,
      queryType: 'searchableJson',
    })
    expectFailure(result)
  }, 30000)

  it('infers the same operation when queryType is omitted', async () => {
    const explicit = await client.encryptQuery(
      { role: 'admin' },
      {
        column: documents.metadata,
        table: documents,
        queryType: 'searchableJson',
      },
    )
    const implicit = await client.encryptQuery(
      { role: 'admin' },
      {
        column: documents.metadata,
        table: documents,
      },
    )
    expect(unwrapResult(explicit)).toEqual(unwrapResult(implicit))
  }, 30000)

  it('preserves mixed selector and containment results in a batch', async () => {
    const result = await client.encryptQuery([
      {
        value: '$.user.email',
        column: documents.metadata,
        table: documents,
        queryType: 'searchableJson',
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
    expectContainment(data[1])
  }, 30000)

  it.each([
    'composite-literal',
    'escaped-composite-literal',
  ] as const)('supports %s formatting for containment needles', async (returnType) => {
    const result = await client.encryptQuery(
      { role: 'admin' },
      {
        column: documents.metadata,
        table: documents,
        queryType: 'searchableJson',
        returnType,
      },
    )
    expect(typeof unwrapResult(result)).toBe('string')
  }, 30000)

  it('supports lock-context chaining for JSON query terms', async () => {
    const operation = client.encryptQuery(
      { role: 'admin' },
      {
        column: documents.metadata,
        table: documents,
        queryType: 'searchableJson',
      },
    )
    const withContext = operation.withLockContext(createMockLockContext())
    expect(withContext).toHaveProperty('execute')
    expect(typeof withContext.execute).toBe('function')
  }, 30000)
})
