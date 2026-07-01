import { describe, expect, it } from 'vitest'
import type { EncryptionClient } from '@/encryption'
import {
  encryptedInt8Column,
  encryptedTable,
  encryptedTextColumn,
  encryptedTimestamptzColumn,
  typedClient,
} from '@/encryption/v3'

const table = encryptedTable('t', {
  when: encryptedTimestamptzColumn('when'),
  big: encryptedInt8Column('big'),
  note: encryptedTextColumn('note'),
})

/**
 * A minimal client stub whose model-decrypt methods resolve to a fixed
 * `Result` payload. `typedClient` only `await`s these, so a plain Promise is a
 * sufficient thenable.
 */
function fakeClient(data: Record<string, unknown>): EncryptionClient {
  return {
    decryptModel: () => Promise.resolve({ data }),
    bulkDecryptModels: () => Promise.resolve({ data: [data] }),
  } as unknown as EncryptionClient
}

describe('typedClient — decrypt reconstruction', () => {
  it('reconstructs Date and bigint columns from cast_as', async () => {
    const client = typedClient(
      fakeClient({
        when: '2020-01-02T03:04:05.000Z',
        big: '42',
        note: 'hi',
      }),
      table,
    )

    const result = await client.decryptModel({}, table)
    expect(result.failure).toBeFalsy()
    if (result.failure) return

    const data = result.data as Record<string, unknown>
    expect(data.when).toBeInstanceOf(Date)
    expect((data.when as Date).toISOString()).toBe('2020-01-02T03:04:05.000Z')
    expect(data.big).toBe(42n)
    expect(data.note).toBe('hi') // string column untouched
  })

  it('leaves null column values untouched', async () => {
    const client = typedClient(
      fakeClient({ when: null, big: null, note: null }),
      table,
    )

    const result = await client.decryptModel({}, table)
    if (result.failure) return

    const data = result.data as Record<string, unknown>
    expect(data.when).toBeNull()
    expect(data.big).toBeNull()
    expect(data.note).toBeNull()
  })

  it('reconstructs each row for bulkDecryptModels', async () => {
    const client = typedClient(
      fakeClient({ when: '2021-06-01T00:00:00.000Z', big: '7', note: 'x' }),
      table,
    )

    const result = await client.bulkDecryptModels([{}], table)
    if (result.failure) return

    const rows = result.data as Array<Record<string, unknown>>
    expect(rows).toHaveLength(1)
    expect(rows[0].when).toBeInstanceOf(Date)
    expect(rows[0].big).toBe(7n)
  })

  it('propagates a failure result unchanged', async () => {
    const failing = {
      decryptModel: () =>
        Promise.resolve({
          failure: { type: 'DecryptionError', message: 'boom' },
        }),
    } as unknown as EncryptionClient

    const client = typedClient(failing, table)
    const result = await client.decryptModel({}, table)
    expect(result.failure).toBeTruthy()
  })
})
