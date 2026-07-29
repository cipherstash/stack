import { describe, expect, it } from 'vitest'
import { encryptedDynamoDB } from '@/dynamodb'
import { encryptedTable, types } from '@/eql/v3'

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
  })
})
