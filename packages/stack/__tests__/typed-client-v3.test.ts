import { describe, expect, it } from 'vitest'
import type { EncryptionClient } from '@/encryption'
import { encryptedTable, typedClient, types } from '@/encryption/v3'

const table = encryptedTable('t', {
  when: types.Timestamp('when'),
  note: types.Text('note'),
  // camelCase JS property → snake_case DB name: reconstruction must key by the
  // JS property (how the decrypted row is keyed), not the DB column name.
  createdOn: types.Date('created_on'),
})

/**
 * A minimal operation stub resolving to a fixed `Result`. `typedClient` now
 * wraps the underlying decrypt op in a `MappedDecryptOperation` and calls
 * `.execute()` on it (rather than awaiting a bare promise), so the stub must be
 * operation-like: `.execute()` plus the chainable `.audit()` / `.withLockContext()`
 * the wrapper may delegate to.
 */
function fakeOp<R>(result: R) {
  return {
    execute: () => Promise.resolve(result),
    audit() {
      return this
    },
    withLockContext() {
      return this
    },
  }
}

/**
 * A minimal client stub whose model-decrypt methods return an operation
 * resolving to a fixed `Result` payload.
 */
function fakeClient(data: Record<string, unknown>): EncryptionClient {
  return {
    decryptModel: () => fakeOp({ data }),
    bulkDecryptModels: () => fakeOp({ data: [data] }),
  } as unknown as EncryptionClient
}

describe('typedClient — decrypt reconstruction', () => {
  it('reconstructs Date columns from cast_as', async () => {
    const client = typedClient(
      fakeClient({
        when: '2020-01-02T03:04:05.000Z',
        note: 'hi',
        createdOn: '2026-07-01T00:00:00.000Z',
      }),
      table,
    )

    const result = await client.decryptModel({}, table)
    expect(result.failure).toBeFalsy()
    if (result.failure) return

    const data = result.data as Record<string, unknown>
    expect(data.when).toBeInstanceOf(Date)
    expect((data.when as Date).toISOString()).toBe('2020-01-02T03:04:05.000Z')
    // Reconstructed by JS property (`createdOn`), though the DB column is
    // `created_on` — a regression here would leave it an unparsed string.
    expect(data.createdOn).toBeInstanceOf(Date)
    expect((data.createdOn as Date).toISOString()).toBe(
      '2026-07-01T00:00:00.000Z',
    )
    expect(data.note).toBe('hi') // string column untouched
  })

  it('leaves null column values untouched', async () => {
    const client = typedClient(fakeClient({ when: null, note: null }), table)

    const result = await client.decryptModel({}, table)
    if (result.failure) return

    const data = result.data as Record<string, unknown>
    expect(data.when).toBeNull()
    expect(data.note).toBeNull()
  })

  it('reconstructs each row for bulkDecryptModels', async () => {
    const client = typedClient(
      fakeClient({ when: '2021-06-01T00:00:00.000Z', note: 'x' }),
      table,
    )

    const result = await client.bulkDecryptModels([{}], table)
    if (result.failure) return

    const rows = result.data as Array<Record<string, unknown>>
    expect(rows).toHaveLength(1)
    expect(rows[0].when).toBeInstanceOf(Date)
  })

  it('propagates a failure result unchanged', async () => {
    const failing = {
      decryptModel: () =>
        fakeOp({
          failure: { type: 'DecryptionError', message: 'boom' },
        }),
    } as unknown as EncryptionClient

    const client = typedClient(failing, table)
    const result = await client.decryptModel({}, table)
    expect(result.failure).toBeTruthy()
  })

  it('fails with a DecryptionError when given a table it was not initialized with', async () => {
    const other = encryptedTable('other', { x: types.Text('x') })
    const client = typedClient(fakeClient({ when: null }), table)

    const single = await client.decryptModel({}, other as never)
    expect(single.failure?.type).toBe('DecryptionError')
    expect(single.failure?.message).toMatch(/not initialized with/i)

    const bulk = await client.bulkDecryptModels([{}], other as never)
    expect(bulk.failure?.type).toBe('DecryptionError')
  })

  // Reconstructors are keyed by `tableName`, not object identity: a table
  // re-imported from another module (or rebuilt across an HMR reload) is a
  // distinct object that still satisfies `Table extends S[number]`.
  it('decrypts when handed a structurally identical, separately constructed table', async () => {
    const sameTableRebuilt = encryptedTable('t', {
      when: types.Timestamp('when'),
      note: types.Text('note'),
      createdOn: types.Date('created_on'),
    })
    expect(sameTableRebuilt).not.toBe(table)

    const client = typedClient(
      fakeClient({ when: '2020-01-02T03:04:05.000Z', note: 'hi' }),
      table,
    )

    const result = await client.decryptModel({}, sameTableRebuilt)
    expect(result.failure).toBeFalsy()
    if (result.failure) return

    const data = result.data as Record<string, unknown>
    expect(data.when).toBeInstanceOf(Date)
  })

  // `Encryption` now returns THIS typed client for a v3 schema set, so a consumer
  // typed against the nominal overload (e.g. stack-supabase's query builder,
  // which casts to it and calls the one-arg `decryptModel(row)` /
  // `bulkDecryptModels(rows)`) reaches the typed methods with NO table argument.
  // They must decrypt without throwing — degrading to nominal behaviour (no date
  // reconstruction) — not dereference `undefined.tableName`.
  it('tolerates a one-arg (nominal-style) decryptModel call with no table', async () => {
    const client = typedClient(
      fakeClient({ when: '2020-01-02T03:04:05.000Z', note: 'hi' }),
      table,
    )
    // The typed signature forbids the one-arg form; a nominal-typed caller does
    // it at runtime. Exercise that runtime path.
    // biome-ignore lint/suspicious/noExplicitAny: exercising the nominal-arity runtime path
    const decryptOneArg = client.decryptModel as any

    const result = await decryptOneArg({
      when: '2020-01-02T03:04:05.000Z',
      note: 'hi',
    })
    expect(result.failure).toBeFalsy()
    if (result.failure) return

    const data = result.data as Record<string, unknown>
    // No table → no reconstruction: `when` stays the raw string, exactly as the
    // nominal client would return it.
    expect(data.when).toBe('2020-01-02T03:04:05.000Z')
    expect(data.note).toBe('hi')
  })

  it('tolerates a one-arg (nominal-style) bulkDecryptModels call with no table', async () => {
    const client = typedClient(
      fakeClient({ when: '2021-06-01T00:00:00.000Z', note: 'x' }),
      table,
    )
    // biome-ignore lint/suspicious/noExplicitAny: exercising the nominal-arity runtime path
    const bulkOneArg = client.bulkDecryptModels as any

    const result = await bulkOneArg([{ when: '2021-06-01T00:00:00.000Z' }])
    expect(result.failure).toBeFalsy()
    if (result.failure) return

    const rows = result.data as Array<Record<string, unknown>>
    expect(rows).toHaveLength(1)
    // No table → no reconstruction: raw string, not a Date.
    expect(rows[0].when).toBe('2021-06-01T00:00:00.000Z')
  })
})
