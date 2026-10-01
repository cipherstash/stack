/**
 * Which TABLE a legacy DynamoDB read forwards, and to which client shape.
 *
 * This file is the SURFACE axis of the legacy read path, and it deliberately
 * uses one `types.TextEq` column throughout — the forward is table-level, so a
 * second domain would not make these cases stronger. The TYPE axis (what
 * happens to a `date`, a `bigint`, a nested column on the way back out) lives in
 * `v2-type-coverage.test.ts`, which drives the whole domain catalog through the
 * real client wrapper.
 *
 * The one exception is the last case here, because on the wasm-shaped client the
 * two axes meet: that entry reconstructs dates ITSELF from the forwarded table,
 * so the forward is what decides whether a legacy date read is a `Date` at all.
 */
import { describe, expect, it } from 'vitest'
import { encryptedDynamoDB } from '@/dynamodb'
import { type AnyV3Table, encryptedTable, types } from '@/eql/v3'
import { DATE_LIKE_CASTS } from '@/eql/v3/columns'
import { reconstructDatePaths } from '@/eql/v3/date-reconstruction'

const users = encryptedTable('users', {
  email: types.TextEq('email'),
})

/**
 * @param requiresTableForDecrypt models the WASM client, whose `decryptModel` /
 *   `bulkDecryptModels` resolve date fields from a per-table map and THROW
 *   without a table (`WasmEncryptionClient.requireTable`). The stub throws for
 *   the same input, which is what makes the wasm-shaped cases below able to
 *   fail: a plain recorder would pass whether or not the adapter forwarded the
 *   table, so asserting against one proves nothing the cases above don't.
 */
function recordingClient(options: { requiresTableForDecrypt?: boolean } = {}) {
  const calls: { method: string; args: unknown[] }[] = []
  const record =
    (method: string) =>
    (...args: unknown[]) => {
      if (options.requiresTableForDecrypt && method.endsWith('DecryptModels')) {
        if (args[1] === undefined) {
          throw new Error(
            `[wasm stub]: ${method} requires the table — this client resolves date fields from a per-table map`,
          )
        }
      }
      if (
        options.requiresTableForDecrypt &&
        method === 'decryptModel' &&
        args[1] === undefined
      ) {
        throw new Error(
          '[wasm stub]: decryptModel requires the table — this client resolves date fields from a per-table map',
        )
      }
      calls.push({ method, args })
      return Promise.resolve({ data: method.startsWith('bulk') ? [{}] : {} })
    }

  return {
    calls,
    client: {
      requiresTableForDecrypt: options.requiresTableForDecrypt,
      getEncryptConfig: () => ({ tables: { users: {} } }),
      encryptModel: record('encryptModel'),
      bulkEncryptModels: record('bulkEncryptModels'),
      decryptModel: record('decryptModel'),
      bulkDecryptModels: record('bulkDecryptModels'),
    },
  }
}

describe('legacy DynamoDB read forwarding', () => {
  it('forwards the registered v3 table while reconstructing EQL v2 storage', async () => {
    const { calls, client } = recordingClient()
    const dynamo = encryptedDynamoDB({ encryptionClient: client as never })

    await dynamo.decryptModel({ email__source: 'ciphertext' }, users, {
      storedEqlVersion: 2,
    })

    expect(calls).toHaveLength(1)
    expect(calls[0]?.method).toBe('decryptModel')
    expect(calls[0]?.args).toHaveLength(2)
    expect(calls[0]?.args[1]).toBe(users)
    expect(calls[0]?.args[0]).toEqual({
      email: {
        i: { c: 'email', t: 'users' },
        v: 2,
        k: 'ct',
        c: 'ciphertext',
      },
    })
  })

  it('forwards the registered v3 table on bulk legacy reads', async () => {
    const { calls, client } = recordingClient()
    const dynamo = encryptedDynamoDB({ encryptionClient: client as never })

    await dynamo.bulkDecryptModels([{ email__source: 'ciphertext' }], users, {
      storedEqlVersion: 2,
    })

    expect(calls[0]?.method).toBe('bulkDecryptModels')
    expect(calls[0]?.args).toHaveLength(2)
    expect(calls[0]?.args[1]).toBe(users)
  })

  it('continues to forward the table for stored EQL v3 items', async () => {
    const { calls, client } = recordingClient()
    const dynamo = encryptedDynamoDB({ encryptionClient: client as never })

    await dynamo.decryptModel({ email__source: 'ciphertext' }, users)

    expect(calls[0]?.args[1]).toBe(users)
  })

  // The two cases below are the ones that would have caught the refusal this
  // adapter used to carry: a wasm-shaped client was rejected outright on the
  // legacy path, on the false premise that the v2 read omits the table. Their
  // stub throws when called table-less, so if the adapter ever stops forwarding
  // it, these fail rather than quietly recording the wrong call.
  it('forwards the registered v3 table for clients that require table-aware decrypt', async () => {
    const { calls, client } = recordingClient({
      requiresTableForDecrypt: true,
    })
    const dynamo = encryptedDynamoDB({ encryptionClient: client as never })

    await dynamo.decryptModel({ email__source: 'ciphertext' }, users, {
      storedEqlVersion: 2,
    })

    expect(calls).toHaveLength(1)
    expect(calls[0]?.args[1]).toBe(users)
    expect(calls[0]?.args[0]).toEqual({
      email: {
        i: { c: 'email', t: 'users' },
        v: 2,
        k: 'ct',
        c: 'ciphertext',
      },
    })
  })

  it('forwards the registered v3 table on bulk legacy reads for table-aware clients', async () => {
    const { calls, client } = recordingClient({
      requiresTableForDecrypt: true,
    })
    const dynamo = encryptedDynamoDB({ encryptionClient: client as never })

    await dynamo.bulkDecryptModels([{ email__source: 'ciphertext' }], users, {
      storedEqlVersion: 2,
    })

    expect(calls).toHaveLength(1)
    expect(calls[0]?.args[1]).toBe(users)
  })

  it('rejects an invalid stored version from JavaScript callers', () => {
    const { client } = recordingClient()
    const dynamo = encryptedDynamoDB({ encryptionClient: client as never })

    expect(() =>
      dynamo.decryptModel({ email__source: 'ciphertext' }, users, {
        storedEqlVersion: 4,
      } as never),
    ).toThrow(/unsupported storedEqlVersion 4/)
    expect(() =>
      dynamo.bulkDecryptModels([{ email__source: 'ciphertext' }], users, {
        storedEqlVersion: 4,
      } as never),
    ).toThrow(/unsupported storedEqlVersion 4/)
  })
})

/**
 * The point of forwarding the table, on the entry where it is load-bearing.
 *
 * The native client reconstructs `Date` columns in the wrapper
 * (`rowReconstructor`, `client-v3.ts`). `WasmEncryptionClient` does it INSIDE
 * its own `decryptModel`, from `dateFieldsByTable` — a per-table map keyed by
 * the table it is handed. The cases above prove the adapter forwards the table
 * on a legacy read; this proves what that forward buys: a `date` column stored
 * as EQL v2 still comes back as a `Date`, reconstructed off the CURRENT v3
 * descriptor's `cast_as`.
 *
 * The stub resolves its date paths the way that client does — from the
 * forwarded table — so dropping the forward makes it throw rather than silently
 * hand back the FFI's string.
 */
describe('a client that reconstructs dates from the forwarded table', () => {
  const people = encryptedTable('people', {
    email: types.TextEq('email'),
    bornOn: types.Date('born_on'),
  })

  /** The date-cast JS property paths of a table — what the wasm entry precomputes. */
  function datePathsOf(table: AnyV3Table): string[] {
    const { columns } = table.build()
    return Object.entries(table.buildColumnKeyMap())
      .filter(([, dbName]) =>
        (DATE_LIKE_CASTS as readonly string[]).includes(
          String(columns[dbName]?.cast_as),
        ),
      )
      .map(([property]) => property)
  }

  it('returns a Date for a date column stored as EQL v2', async () => {
    const client = {
      decryptModel: (item: Record<string, unknown>, table?: AnyV3Table) => {
        if (!table) {
          throw new Error(
            '[wasm stub]: decryptModel requires the table — this client resolves date fields from a per-table map',
          )
        }
        // Stand in for the FFI: every rebuilt envelope decrypts to the string
        // form protect-ffi hands back. The `Date` can then only come from the
        // reconstruction the forwarded table drives.
        const decrypted = Object.fromEntries(
          Object.entries(item).map(([key, value]) => [
            key,
            value !== null && typeof value === 'object' && 'c' in value
              ? String((value as { c: unknown }).c)
              : value,
          ]),
        )
        return Promise.resolve({
          data: reconstructDatePaths(decrypted, datePathsOf(table)),
        })
      },
    }

    const dynamo = encryptedDynamoDB({ encryptionClient: client as never })

    const result = await dynamo.decryptModel(
      { pk: 'p#1', bornOn__source: '1990-04-05T00:00:00.000Z' },
      people,
      { storedEqlVersion: 2 },
    )

    expect(result.failure).toBeUndefined()
    if (result.failure) return

    const data = result.data as Record<string, unknown>
    expect(data.bornOn).toBeInstanceOf(Date)
    expect((data.bornOn as Date).toISOString()).toBe('1990-04-05T00:00:00.000Z')
    expect(data.pk).toBe('p#1')
  })
})
