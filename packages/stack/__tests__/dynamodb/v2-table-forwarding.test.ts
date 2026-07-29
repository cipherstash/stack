import { describe, expect, it } from 'vitest'
import { encryptedDynamoDB } from '@/dynamodb'
import { encryptedTable, types } from '@/eql/v3'

const users = encryptedTable('users', {
  email: types.TextEq('email'),
})

function recordingClient(options: { requiresTableForDecrypt?: boolean } = {}) {
  const calls: { method: string; args: unknown[] }[] = []
  const record =
    (method: string) =>
    (...args: unknown[]) => {
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

  it('rejects legacy reads for clients that require table-aware decrypt', () => {
    const { calls, client } = recordingClient({
      requiresTableForDecrypt: true,
    })
    const dynamo = encryptedDynamoDB({ encryptionClient: client as never })

    expect(() =>
      dynamo.decryptModel({ email__source: 'ciphertext' }, users, {
        storedEqlVersion: 2,
      }),
    ).toThrow(/wasm-inline client cannot read.*stored from EQL v2/)
    expect(calls).toHaveLength(0)
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
