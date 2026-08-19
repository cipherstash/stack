import { encryptedTable, types } from '@cipherstash/stack/eql/v3'
import { describe, expect, it, vi } from 'vitest'
import { adaptWasmEncryption } from '../src/wasm-client-adapter'
import { createMockSupabase, fakeEnvelope } from './helpers/supabase-mock'

/**
 * The adapter that lets the edge entry's WASM engine drive this package's
 * query pipeline (#708 review, P1).
 *
 * The two engines differ in ways that are **silent at construction** — the
 * edge entry built and returned a client happily while every query through it
 * would have failed. That is what these tests exist to stop, so they model the
 * WASM contract rather than the native one: `decryptModel` REQUIRES a table
 * and throws without it, operations are plain Results with no `.withLockContext()`
 * or `.audit()`, and `bulkEncrypt` takes a different shape.
 */

const users = encryptedTable('users', {
  email: types.TextSearch('email'),
})

/**
 * A stand-in with the WASM client's contract, not the native one. Every
 * difference the adapter exists to reconcile is enforced here, so a test that
 * passes against this double could not pass against a native-shaped fake.
 */
function fakeWasmClient() {
  const seen = {
    decryptModelTable: undefined as unknown,
    bulkDecryptModelsTable: undefined as unknown,
  }
  const client = {
    encrypt: vi.fn(async (value: unknown, _opts: unknown) => ({
      data: fakeEnvelope(value, 'email'),
    })),
    encryptModel: vi.fn(async (model: unknown, table: unknown) => {
      if (!table) throw new Error('WASM encryptModel requires a table')
      return { data: model }
    }),
    bulkEncryptModels: vi.fn(async (models: unknown, table: unknown) => {
      if (!table) throw new Error('WASM bulkEncryptModels requires a table')
      return { data: models }
    }),
    decryptModel: vi.fn(async (model: unknown, table: unknown) => {
      // The contract that broke the un-adapted entry.
      if (!table) throw new Error('WASM decryptModel requires a table')
      seen.decryptModelTable = table
      return { data: model }
    }),
    bulkDecryptModels: vi.fn(async (models: unknown, table: unknown) => {
      if (!table) throw new Error('WASM bulkDecryptModels requires a table')
      seen.bulkDecryptModelsTable = table
      return { data: models }
    }),
    // Present, and deliberately NOT forwarded — its signature differs.
    bulkEncrypt: vi.fn(async () => ({ data: [] })),
  }
  return { client, seen }
}

async function adapted() {
  const { client, seen } = fakeWasmClient()
  const factory = adaptWasmEncryption(async () => client as never)
  const instance = (await factory({
    schemas: [],
    config: {},
  })) as unknown as Record<string, (...args: unknown[]) => Promise<unknown>>
  return { instance, client, seen }
}

describe('adaptWasmEncryption', () => {
  it('forwards the table the WASM client requires on both decrypt paths', async () => {
    const { instance, seen } = await adapted()
    await instance.decryptModel({ email: 'x' }, users)
    await instance.bulkDecryptModels([{ email: 'x' }], users)
    expect(seen.decryptModelTable).toBe(users)
    expect(seen.bulkDecryptModelsTable).toBe(users)
  })

  /**
   * `query-encrypt.ts` reaches for `bulkEncrypt` with optional chaining and
   * falls back to per-term `encrypt` when it is absent. Forwarding the WASM
   * one would put a mismatched signature on that path; omitting it selects the
   * supported fallback. The omission is load-bearing, so pin it.
   */
  it('does not forward bulkEncrypt, so the per-term fallback is selected', async () => {
    const { instance, client } = await adapted()
    expect(instance.bulkEncrypt).toBeUndefined()
    expect(client.bulkEncrypt).not.toHaveBeenCalled()
  })

  it('forwards the methods the pipeline does call', async () => {
    const { instance, client } = await adapted()
    await instance.encrypt('a', { column: users.email, table: users })
    await instance.encryptModel({ email: 'a' }, users)
    await instance.bulkEncryptModels([{ email: 'a' }], users)
    expect(client.encrypt).toHaveBeenCalledTimes(1)
    expect(client.encryptModel).toHaveBeenCalledTimes(1)
    expect(client.bulkEncryptModels).toHaveBeenCalledTimes(1)
  })

  /**
   * Lock context is a real capability gap on the WASM engine, not an adapter
   * shortcut. Silently dropping the claim would write values any keyset holder
   * can decrypt — the opposite of what the caller asked for — so it must fail,
   * and it must fail with a sentence rather than
   * `op.withLockContext is not a function`.
   */
  it('fails loudly, and by name, when a lock context is requested', async () => {
    const { instance } = await adapted()
    const op = instance.encrypt('a', {
      column: users.email,
      table: users,
    }) as unknown as { withLockContext: () => never; audit: () => never }
    expect(() => op.withLockContext()).toThrow(/withLockContext/)
    expect(() => op.withLockContext()).toThrow(/edge entry/)
    expect(() => op.audit()).toThrow(/audit/)
  })

  it('still resolves as a normal promise when nothing decorates it', async () => {
    const { instance } = await adapted()
    await expect(
      instance.encrypt('a', { column: users.email, table: users }),
    ).resolves.toHaveProperty('data')
  })
})

/**
 * The end-to-end shape: a client built from the adapter, driven through the
 * real query builder against the recording Supabase double. This is the Node
 * stand-in for the Deno test's query assertion — it cannot prove WASM runs,
 * but it proves the pipeline never calls the WASM client in a way its contract
 * rejects, which is the half that used to be broken.
 */
describe('a declared-mode client built on the adapter', () => {
  it('runs a filtered select end to end without violating the WASM contract', async () => {
    const { client: wasmClient } = fakeWasmClient()
    const { makeEncryptedSupabase } = await import('../src/create')
    const supabaseMock = createMockSupabase([
      { email: fakeEnvelope('alice@example.com', 'email') },
    ])

    const encryptedSupabase = makeEncryptedSupabase(
      adaptWasmEncryption(async () => wasmClient as never),
      null,
    )
    const db = await encryptedSupabase(supabaseMock.client as never, {
      schemas: { users },
    })

    const result = await (
      db as unknown as {
        from: (t: string) => {
          select: (c: string) => {
            eq: (c: string, v: string) => PromiseLike<{ data: unknown }>
          }
        }
      }
    )
      .from('users')
      .select('email')
      .eq('email', 'alice@example.com')

    // The operand was encrypted rather than passed through.
    const eqCall = supabaseMock.callsFor('eq')[0]
    expect(eqCall).toBeDefined()
    expect(String(eqCall.args[1])).not.toBe('alice@example.com')

    // The decrypt path ran, and it handed the WASM client the table it
    // requires. Asserting the CALL, not just that a result came back: the
    // builder turns a thrown decrypt into an `{ error }` result, so
    // `toHaveProperty('data')` passes whether or not the table was supplied —
    // which made an earlier version of this test unable to fail.
    expect(wasmClient.bulkDecryptModels).toHaveBeenCalledTimes(1)
    // Not `toBe(users)`: declared mode rebuilds the table through
    // `mergeDeclaredTables`, so the pipeline holds an equivalent instance
    // rather than the declared object. What matters is that a table arrived at
    // all — passing `undefined` is what the WASM client rejects.
    const tableArg = wasmClient.bulkDecryptModels.mock.calls[0][1] as {
      tableName?: string
    }
    expect(tableArg).toBeDefined()
    expect(tableArg?.tableName).toBe('users')
    expect((result as unknown as { error: unknown }).error).toBeNull()
  })
})
