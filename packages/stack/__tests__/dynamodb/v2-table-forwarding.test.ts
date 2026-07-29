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
import { afterEach, describe, expect, it, vi } from 'vitest'
import { encryptedDynamoDB } from '@/dynamodb'
import { encryptedTable as encryptedTableV3, types } from '@/eql/v3'
import { encryptedColumn, encryptedTable as encryptedTableV2 } from '@/schema'
import { logger } from '@/utils/logger'

// The audit-drop tests spy on the shared `logger` singleton, which other suites
// in this directory also patch. Each restores its own spy in a `finally`; this
// is the safety net so a patched method can never survive a test boundary.
afterEach(() => {
  vi.restoreAllMocks()
})

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
        // A bare promise — NOT a thenable operation with `.audit()`. That is
        // the whole point of this stub: it is the shape `WasmEncryptionClient`
        // returns from `wasmResult`. The bulk methods resolve to an array,
        // index-aligned with their input, as the real client does.
        return Promise.resolve(
          method.startsWith('bulk') ? { data: [{}] } : { data: {} },
        )
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
      /wasm-inline client cannot be paired with the legacy EQL v2 table/,
    )
    // Refused before the client is touched, so the user never sees the
    // TypeError about `tableName`.
    expect(calls).toHaveLength(0)
  })

  it('is refused on the bulk v2 path too', () => {
    const { client } = wasmShapedClient([])
    const dynamo = encryptedDynamoDB({ encryptionClient: client as never })

    expect(() => dynamo.bulkDecryptModels([{ pk: 'a' }], usersV2)).toThrow(
      /wasm-inline client cannot be paired with the legacy EQL v2 table/,
    )
  })

  /**
   * #788 review, minor finding.
   *
   * The guard runs on all four operations, not just the two read ones, so a
   * plain-JS caller reaching the write path with a v2 table hits the SAME
   * message. It must therefore not be phrased for reads only — "would fail at
   * the first read" names an operation that never ran.
   *
   * Typed callers cannot get here (the write overloads are `AnyV3Table`-only,
   * pinned by `client-compat.test-d.ts`), so this is about the message a JS
   * caller or a cast lands on, not about reachable behaviour changing.
   */
  it('is refused on the v2 WRITE path, with a message that does not claim a read', () => {
    const { calls, client } = wasmShapedClient([])
    const dynamo = encryptedDynamoDB({ encryptionClient: client as never })

    for (const call of [
      () => dynamo.encryptModel({ pk: 'a' } as never, usersV2 as never),
      () => dynamo.bulkEncryptModels([{ pk: 'a' }] as never, usersV2 as never),
    ]) {
      expect(call).toThrow(
        /wasm-inline client cannot be paired with the legacy EQL v2 table/,
      )
      // The read-path phrasing must not survive on a write.
      expect(call).not.toThrow(/would fail at the first read/)
      expect(call).not.toThrow(/cannot read legacy EQL v2 items/)
    }

    expect(calls).toHaveLength(0)
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

  /**
   * #788 review follow-up: the same "v3 tables are unaffected" promise, on the
   * WRITE path.
   *
   * The encrypt operations chained `.audit()` onto the client's result
   * unconditionally. The native clients return a thenable operation carrying
   * it; `WasmEncryptionClient.encryptModel` returns a plain
   * `Promise<WasmResult>` from `wasmResult` (it has no `.audit()` anywhere),
   * so every v3 encrypt through this adapter died with
   * `client.encryptModel(...).audit is not a function` — surfaced as a
   * `DYNAMODB_ENCRYPTION_ERROR` failure, not a crash, so it read as a genuine
   * encryption fault. The decrypt path already tolerates the bare promise via
   * `resolveDecryptResult`; the write path must match.
   */
  it('encrypts an EQL v3 table even though its encrypt returns a bare promise', async () => {
    const { calls, client } = wasmShapedClient(['users_v3'])
    const dynamo = encryptedDynamoDB({ encryptionClient: client as never })

    const single = await dynamo.encryptModel({ pk: 'a' } as never, usersV3)
    expect(single.failure).toBeUndefined()

    const bulk = await dynamo.bulkEncryptModels([{ pk: 'a' }] as never, usersV3)
    expect(bulk.failure).toBeUndefined()

    expect(calls.map((c) => c.method)).toEqual([
      'encryptModel',
      'bulkEncryptModels',
    ])
  })

  /**
   * Audit metadata has nowhere to go on this client shape, so it is dropped —
   * but the encrypt must still succeed rather than failing the whole write, and
   * the drop must be OBSERVABLE rather than silent. Asserting only that the
   * result succeeded would pass even with the debug log deleted, and that log is
   * the half that makes a missing audit record diagnosable.
   */
  it('drops audit metadata observably, without failing the encrypt', async () => {
    const spy = vi.spyOn(logger, 'debug').mockImplementation(() => {})

    try {
      const { client } = wasmShapedClient(['users_v3'])
      const dynamo = encryptedDynamoDB({ encryptionClient: client as never })

      const result = await dynamo
        .encryptModel({ pk: 'a' } as never, usersV3)
        .audit({ metadata: { requestId: 'r-1' } })

      expect(result.failure).toBeUndefined()
      expect(spy).toHaveBeenCalledWith(
        expect.stringContaining('encryptModel audit metadata ignored'),
      )
      // It must name the entry to switch to, not merely report a loss.
      expect(spy.mock.calls.at(-1)?.[0]).toMatch(/@cipherstash\/stack/)
    } finally {
      spy.mockRestore()
    }
  })

  /**
   * The mirror: a client that DOES carry `.audit()` must not trip the drop path.
   * Without this, a "fix" that logged unconditionally — or that stopped chaining
   * `.audit()` at all — would leave every test green while silently discarding
   * the native clients' audit trail.
   */
  it('does not report a drop when the client can carry the metadata', async () => {
    const spy = vi.spyOn(logger, 'debug').mockImplementation(() => {})

    try {
      let seen: unknown
      const chainable = {
        audit(config: { metadata?: Record<string, unknown> }) {
          seen = config.metadata
          return Promise.resolve({ data: {} })
        },
      }
      const client = {
        getEncryptConfig: () => ({ v: 1, tables: { users_v3: {} } }),
        encryptModel: () => chainable,
        bulkEncryptModels: () => chainable,
        decryptModel: () => Promise.resolve({ data: {} }),
        bulkDecryptModels: () => Promise.resolve({ data: {} }),
      }
      const dynamo = encryptedDynamoDB({ encryptionClient: client as never })

      const result = await dynamo
        .encryptModel({ pk: 'a' } as never, usersV3)
        .audit({ metadata: { requestId: 'r-1' } })

      expect(result.failure).toBeUndefined()
      expect(seen).toEqual({ requestId: 'r-1' })
      expect(spy).not.toHaveBeenCalledWith(
        expect.stringContaining('audit metadata ignored'),
      )
    } finally {
      spy.mockRestore()
    }
  })

  /**
   * The tolerance must not swallow a malformed result into a fake success —
   * the same guard `resolveDecryptResult` applies on read.
   */
  it('rejects a bare encrypt result that is not { data } or { failure }', async () => {
    const client = {
      requiresTableForDecrypt: true,
      getEncryptConfig: () => ({ v: 1, tables: { users_v3: {} } }),
      encryptModel: () => Promise.resolve('not-a-result'),
      bulkEncryptModels: () => Promise.resolve('not-a-result'),
      decryptModel: () => Promise.resolve({ data: {} }),
      bulkDecryptModels: () => Promise.resolve({ data: {} }),
    }
    const dynamo = encryptedDynamoDB({ encryptionClient: client as never })

    const result = await dynamo.encryptModel({ pk: 'a' } as never, usersV3)

    expect(result.failure?.message).toMatch(/malformed result/)
  })
})
