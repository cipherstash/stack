/**
 * Which table (if any) the DynamoDB adapter forwards to the encryption client.
 *
 * `encryptedDynamoDB` promises that `decryptModel` / `bulkDecryptModels` keep
 * accepting an EQL **v2** table so previously stored v2 items stay readable
 * (see the contract note in `src/dynamodb/index.ts`). That promise breaks if the
 * adapter forwards the v2 table to a v3-configured client: the typed client
 * looks the table up in its own reconstructor map, does not find it, and fails
 * with "decryptModel received a table this client was not initialized with".
 *
 * The nominal client derives the table from the payloads and needs no second
 * argument, and the typed client now exposes a table-less overload for exactly
 * this case — so the correct forward is conditional on the table's generation,
 * not unconditional.
 *
 * Credential-free by construction: the adapter never touches the AWS SDK, and
 * these drive it with a recording stub client, so the assertion is on the call
 * the adapter makes rather than on a live decrypt. That matters because the only
 * other coverage of this path is an integration suite requiring live ZeroKMS.
 */
import { describe, expect, it } from 'vitest'
import { encryptedDynamoDB } from '@/dynamodb'
import { encryptedTable as encryptedTableV3, types } from '@/eql/v3'
import { encryptedColumn, encryptedTable as encryptedTableV2 } from '@/schema'

const usersV2 = encryptedTableV2('users_v2', {
  email: encryptedColumn('email').equality(),
})

const usersV3 = encryptedTableV3('users_v3', {
  email: types.TextEq('email'),
})

/**
 * A client that records how each decrypt method was called. `getEncryptConfig`
 * reports `knownTables` so the construction-time version guard sees a client
 * that knows the v3 table under test.
 */
function recordingClient(knownTables: string[]) {
  const calls: { method: string; argCount: number; table: unknown }[] = []

  const record =
    (method: string) =>
    (...args: unknown[]) => {
      calls.push({ method, argCount: args.length, table: args[1] })
      return Promise.resolve({ data: {} })
    }

  const client = {
    getEncryptConfig: () => ({
      v: 1,
      tables: Object.fromEntries(knownTables.map((t) => [t, {}])),
    }),
    encryptModel: record('encryptModel'),
    bulkEncryptModels: record('bulkEncryptModels'),
    decryptModel: record('decryptModel'),
    bulkDecryptModels: record('bulkDecryptModels'),
  }

  return { calls, client }
}

describe('decryptModel table forwarding', () => {
  it('does not forward an EQL v2 table to the client', async () => {
    const { calls, client } = recordingClient([])
    const dynamo = encryptedDynamoDB({ encryptionClient: client as never })

    await dynamo.decryptModel({ pk: 'a' }, usersV2)

    expect(calls).toHaveLength(1)
    expect(calls[0]?.method).toBe('decryptModel')
    // The v2 table must not reach the client — a typed client would reject it.
    expect(calls[0]?.table).toBeUndefined()
  })

  it('still forwards an EQL v3 table, which the typed client requires', async () => {
    const { calls, client } = recordingClient(['users_v3'])
    const dynamo = encryptedDynamoDB({ encryptionClient: client as never })

    await dynamo.decryptModel({ pk: 'a' }, usersV3)

    expect(calls).toHaveLength(1)
    expect(calls[0]?.table).toBe(usersV3)
  })
})

describe('bulkDecryptModels table forwarding', () => {
  it('does not forward an EQL v2 table to the client', async () => {
    const { calls, client } = recordingClient([])
    const dynamo = encryptedDynamoDB({ encryptionClient: client as never })

    await dynamo.bulkDecryptModels([{ pk: 'a' }], usersV2)

    expect(calls).toHaveLength(1)
    expect(calls[0]?.method).toBe('bulkDecryptModels')
    expect(calls[0]?.table).toBeUndefined()
  })

  it('still forwards an EQL v3 table, which the typed client requires', async () => {
    const { calls, client } = recordingClient(['users_v3'])
    const dynamo = encryptedDynamoDB({ encryptionClient: client as never })

    await dynamo.bulkDecryptModels([{ pk: 'a' }], usersV3)

    expect(calls).toHaveLength(1)
    expect(calls[0]?.table).toBe(usersV3)
  })
})

/**
 * #772 review, finding 10.
 *
 * The table-less v2 decrypt above is correct for the native clients, which
 * derive the table from the payloads. `WasmEncryptionClient` cannot: its
 * decrypt requires the table and resolves date fields from a per-table map, so
 * the omitted argument reached `requireTable(undefined)` and threw a TypeError
 * about reading `tableName` — a message pointing nowhere near the cause, on the
 * documented entry for Deno / Workers / Supabase Edge Functions, which
 * satisfies `DynamoDBEncryptionClient` structurally and so is accepted with no
 * cast.
 */
describe('a client whose decrypt requires the table', () => {
  /** The shape `WasmEncryptionClient` presents: declared capability, no `.audit()`. */
  function wasmShapedClient(knownTables: string[]) {
    const calls: { method: string; argCount: number }[] = []
    const record =
      (method: string) =>
      (...args: unknown[]) => {
        calls.push({ method, argCount: args.length })
        // Mirrors requireTable: throws rather than returning a Result.
        if (args[1] === undefined) {
          throw new TypeError(
            "Cannot read properties of undefined (reading 'tableName')",
          )
        }
        return Promise.resolve({ data: {} })
      }
    const client = {
      requiresTableForDecrypt: true,
      getEncryptConfig: () => ({
        v: 1,
        tables: Object.fromEntries(knownTables.map((t) => [t, {}])),
      }),
      encryptModel: record('encryptModel'),
      bulkEncryptModels: record('bulkEncryptModels'),
      decryptModel: record('decryptModel'),
      bulkDecryptModels: record('bulkDecryptModels'),
    }
    return { calls, client }
  }

  it('is refused for an EQL v2 table, naming the entry to use instead', () => {
    const { calls, client } = wasmShapedClient([])
    const dynamo = encryptedDynamoDB({ encryptionClient: client as never })

    // Synchronous: the guard runs when the operation is built, so the failure
    // lands at the call site rather than as a rejected promise later.
    expect(() => dynamo.decryptModel({ pk: 'a' }, usersV2)).toThrow(
      /wasm-inline client cannot read legacy EQL v2 items/,
    )
    // Refused before the client is touched, so the user never sees the
    // TypeError about `tableName`.
    expect(calls).toHaveLength(0)
  })

  it('is refused on the bulk v2 path too', () => {
    const { client } = wasmShapedClient([])
    const dynamo = encryptedDynamoDB({ encryptionClient: client as never })

    expect(() => dynamo.bulkDecryptModels([{ pk: 'a' }], usersV2)).toThrow(
      /wasm-inline client cannot read legacy EQL v2 items/,
    )
  })

  // v3 tables ARE forwarded the table, so this client works there — the guard
  // must not turn into a blanket rejection of the wasm entry.
  it('is accepted for an EQL v3 table, which is always given the table', async () => {
    const { calls, client } = wasmShapedClient(['users_v3'])
    const dynamo = encryptedDynamoDB({ encryptionClient: client as never })

    await dynamo.decryptModel({ pk: 'a' }, usersV3)

    expect(calls).toHaveLength(1)
    expect(calls[0]?.argCount).toBe(2)
  })
})
