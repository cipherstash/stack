/**
 * Behaviour pins for `createCipherstashV3Sdk`.
 *
 * Uses a hand-built fake v3 client (no live ZeroKMS) — every call
 * returns a deterministic, inspectable result so the adapter's routing,
 * query-term dispatch, and error-mapping logic can be observed at the
 * boundary.
 *
 * The load-bearing pin is the QUERY-TERM seam (Task 6 → Task 7):
 * envelopes marked via `markV3QueryTerm` must be encrypted through the
 * client's `encryptQuery` — batch form for scalar flavours (one
 * crossing per flavour, mirroring stack-drizzle's v3 `inArray`), single
 * form for `searchableJson` (mirroring stack-drizzle's JSON containment
 * path) — while unmarked values take the storage `bulkEncrypt` path.
 */

import { encryptedTable, types } from '@cipherstash/stack/eql/v3'
import { describe, expect, it, vi } from 'vitest'
import { EncryptedJson } from '../../src/execution/envelope-json'
import { EncryptedString } from '../../src/execution/envelope-string'
import { EncryptedNumber } from '../../src/v3/envelope-number'
import { markV3QueryTerm } from '../../src/v3/query-term'
import {
  type CipherstashV3Client,
  createCipherstashV3Sdk,
} from '../../src/v3/sdk-adapter-v3'

function makeUsersTable() {
  return encryptedTable('users', {
    email: types.TextSearch('email'),
    score: types.IntegerOrd('score'),
    payload: types.Json('payload'),
  })
}

interface FakeCalls {
  bulkEncrypt: Array<{
    plaintexts: unknown[]
    table: unknown
    column: unknown
  }>
  encryptQuerySingle: Array<{ plaintext: unknown; opts: unknown }>
  encryptQueryBatch: Array<unknown[]>
  decrypt: unknown[]
  bulkDecrypt: unknown[][]
}

function makeFakeClient(): { client: CipherstashV3Client; calls: FakeCalls } {
  const calls: FakeCalls = {
    bulkEncrypt: [],
    encryptQuerySingle: [],
    encryptQueryBatch: [],
    decrypt: [],
    bulkDecrypt: [],
  }
  const client: CipherstashV3Client = {
    bulkEncrypt: vi.fn(
      async (
        payload: ReadonlyArray<{ plaintext: unknown }>,
        opts: { table: unknown; column: unknown },
      ) => {
        calls.bulkEncrypt.push({
          plaintexts: payload.map((p) => p.plaintext),
          table: opts.table,
          column: opts.column,
        })
        return {
          data: payload.map((p) => ({
            data: { c: `enc:${String(p.plaintext)}` },
          })),
        }
      },
    ),
    decrypt: vi.fn(async (encrypted: unknown) => {
      calls.decrypt.push(encrypted)
      return { data: 'pt-single' }
    }),
    bulkDecrypt: vi.fn(async (payload: ReadonlyArray<{ data: unknown }>) => {
      calls.bulkDecrypt.push(payload.map((p) => p.data))
      return { data: payload.map((_, i) => ({ data: `pt-${i}` })) }
    }),
    // The implementation signature is broad; the interface's `never`
    // params exist only so the REAL generic client satisfies it.
    encryptQuery: vi.fn(async (first: unknown, opts?: unknown) => {
      if (opts === undefined) {
        const terms = first as unknown[]
        calls.encryptQueryBatch.push(terms)
        return {
          data: terms.map((t, i) => ({
            qt: `term-${i}`,
            value: (t as { value: unknown }).value,
          })),
        }
      }
      calls.encryptQuerySingle.push({ plaintext: first, opts })
      return { data: { qt: 'json-term', value: first } }
      // Cast rationale: the fake implements both overloads through one
      // broad body; the interface's `never` params make a direct
      // assignment impossible without widening here.
    }) as unknown as CipherstashV3Client['encryptQuery'],
  }
  return { client, calls }
}

describe('createCipherstashV3Sdk — routing-key lookup', () => {
  it('resolves a (table, column) routing key to the typed v3 schema objects', async () => {
    const users = makeUsersTable()
    const { client, calls } = makeFakeClient()
    const sdk = createCipherstashV3Sdk(client, [users])

    const out = await sdk.bulkEncrypt({
      routingKey: { table: 'users', column: 'email' },
      values: ['alice'],
    })

    expect(calls.bulkEncrypt).toHaveLength(1)
    expect(calls.bulkEncrypt[0]?.table).toBe(users)
    expect(calls.bulkEncrypt[0]?.column).toBe(users.columnBuilders.email)
    expect(calls.bulkEncrypt[0]?.plaintexts).toEqual(['alice'])
    expect(out).toEqual([{ c: 'enc:alice' }])
  })

  it('throws a clear error for an unknown routing-key table', async () => {
    const { client } = makeFakeClient()
    const sdk = createCipherstashV3Sdk(client, [makeUsersTable()])
    await expect(
      sdk.bulkEncrypt({
        routingKey: { table: 'audit_log', column: 'message' },
        values: ['x'],
      }),
    ).rejects.toThrow(/routing-key table "audit_log"/)
  })

  it('throws a clear error for an unknown column on a known table', async () => {
    const { client } = makeFakeClient()
    const sdk = createCipherstashV3Sdk(client, [makeUsersTable()])
    await expect(
      sdk.bulkEncrypt({
        routingKey: { table: 'users', column: 'nope' },
        values: ['x'],
      }),
    ).rejects.toThrow(/routing-key column "nope"/)
  })
})

describe('createCipherstashV3Sdk — query-term routing (Task 6 seam)', () => {
  it('routes scalar marked envelopes through ONE encryptQuery batch per flavour', async () => {
    const users = makeUsersTable()
    const { client, calls } = makeFakeClient()
    const sdk = createCipherstashV3Sdk(client, [users])

    const a = EncryptedNumber.from(1)
    const b = EncryptedNumber.from(2)
    markV3QueryTerm(a, 'equality')
    markV3QueryTerm(b, 'equality')

    const out = await sdk.bulkEncrypt({
      routingKey: { table: 'users', column: 'score' },
      values: [a, b],
    })

    // No storage crossing, exactly one batch crossing.
    expect(calls.bulkEncrypt).toHaveLength(0)
    expect(calls.encryptQuerySingle).toHaveLength(0)
    expect(calls.encryptQueryBatch).toHaveLength(1)
    expect(calls.encryptQueryBatch[0]).toEqual([
      {
        value: 1,
        table: users,
        column: users.columnBuilders.score,
        queryType: 'equality',
      },
      {
        value: 2,
        table: users,
        column: users.columnBuilders.score,
        queryType: 'equality',
      },
    ])
    expect(out).toEqual([
      { qt: 'term-0', value: 1 },
      { qt: 'term-1', value: 2 },
    ])
  })

  it('routes searchableJson marked envelopes through the single-call encryptQuery path', async () => {
    const users = makeUsersTable()
    const { client, calls } = makeFakeClient()
    const sdk = createCipherstashV3Sdk(client, [users])

    const needle = EncryptedJson.from({ role: 'admin' })
    markV3QueryTerm(needle, 'searchableJson')

    const out = await sdk.bulkEncrypt({
      routingKey: { table: 'users', column: 'payload' },
      values: [needle],
    })

    expect(calls.encryptQueryBatch).toHaveLength(0)
    expect(calls.encryptQuerySingle).toHaveLength(1)
    expect(calls.encryptQuerySingle[0]?.plaintext).toEqual({ role: 'admin' })
    expect(calls.encryptQuerySingle[0]?.opts).toEqual({
      table: users,
      column: users.columnBuilders.payload,
      queryType: 'searchableJson',
    })
    expect(out).toEqual([{ qt: 'json-term', value: { role: 'admin' } }])
  })

  it('keeps mixed storage values and query terms position-stable', async () => {
    const users = makeUsersTable()
    const { client, calls } = makeFakeClient()
    const sdk = createCipherstashV3Sdk(client, [users])

    const term = EncryptedString.from('needle')
    markV3QueryTerm(term, 'freeTextSearch')

    const out = await sdk.bulkEncrypt({
      routingKey: { table: 'users', column: 'email' },
      values: ['stored-a', term, 'stored-b'],
    })

    expect(calls.bulkEncrypt[0]?.plaintexts).toEqual(['stored-a', 'stored-b'])
    expect(calls.encryptQueryBatch[0]).toEqual([
      {
        value: 'needle',
        table: users,
        column: users.columnBuilders.email,
        queryType: 'freeTextSearch',
      },
    ])
    expect(out).toEqual([
      { c: 'enc:stored-a' },
      { qt: 'term-0', value: 'needle' },
      { c: 'enc:stored-b' },
    ])
  })

  it('treats an UNMARKED envelope instance as an ordinary storage value', async () => {
    const users = makeUsersTable()
    const { client, calls } = makeFakeClient()
    const sdk = createCipherstashV3Sdk(client, [users])

    const unmarked = EncryptedString.from('plain')
    await sdk.bulkEncrypt({
      routingKey: { table: 'users', column: 'email' },
      values: [unmarked],
    })
    expect(calls.bulkEncrypt).toHaveLength(1)
    expect(calls.bulkEncrypt[0]?.plaintexts).toEqual([unmarked])
    expect(calls.encryptQueryBatch).toHaveLength(0)
  })

  it('throws when a marked envelope carries no plaintext', async () => {
    const users = makeUsersTable()
    const { client } = makeFakeClient()
    const sdk = createCipherstashV3Sdk(client, [users])

    const envelope = EncryptedString.fromInternal({
      ciphertext: { c: 'pre-existing' },
      table: 'users',
      column: 'email',
      sdk,
    })
    markV3QueryTerm(envelope, 'equality')

    await expect(
      sdk.bulkEncrypt({
        routingKey: { table: 'users', column: 'email' },
        values: [envelope],
      }),
    ).rejects.toThrow(/no plaintext/)
  })

  it('throws when the batch returns the wrong number of terms', async () => {
    const users = makeUsersTable()
    const { client } = makeFakeClient()
    // Cast rationale: overriding the vi.fn mock's broad implementation
    // signature; the interface's `never` params block direct assignment.
    client.encryptQuery = (async () => ({
      data: [],
    })) as unknown as CipherstashV3Client['encryptQuery']
    const sdk = createCipherstashV3Sdk(client, [users])
    const term = EncryptedNumber.from(1)
    markV3QueryTerm(term, 'equality')

    await expect(
      sdk.bulkEncrypt({
        routingKey: { table: 'users', column: 'score' },
        values: [term],
      }),
    ).rejects.toThrow(/returned 0 terms for 1/)
  })

  it('surfaces an encryptQuery failure as a thrown error', async () => {
    const users = makeUsersTable()
    const { client } = makeFakeClient()
    // Cast rationale: see above.
    client.encryptQuery = (async () => ({
      failure: { message: 'nope' },
    })) as unknown as CipherstashV3Client['encryptQuery']
    const sdk = createCipherstashV3Sdk(client, [users])
    const term = EncryptedNumber.from(1)
    markV3QueryTerm(term, 'equality')

    await expect(
      sdk.bulkEncrypt({
        routingKey: { table: 'users', column: 'score' },
        values: [term],
      }),
    ).rejects.toThrow(/encryptQuery.*failed: nope/)
  })
})

describe('createCipherstashV3Sdk — bulkEncrypt error mapping', () => {
  it('surfaces a bulkEncrypt failure as a thrown error', async () => {
    const users = makeUsersTable()
    const { client } = makeFakeClient()
    client.bulkEncrypt = async () => ({ failure: { message: 'kaput' } })
    const sdk = createCipherstashV3Sdk(client, [users])
    await expect(
      sdk.bulkEncrypt({
        routingKey: { table: 'users', column: 'email' },
        values: ['x'],
      }),
    ).rejects.toThrow(/bulkEncrypt failed: kaput/)
  })

  it('throws when the client returns the wrong number of ciphertexts', async () => {
    const users = makeUsersTable()
    const { client } = makeFakeClient()
    client.bulkEncrypt = async () => ({ data: [] })
    const sdk = createCipherstashV3Sdk(client, [users])
    await expect(
      sdk.bulkEncrypt({
        routingKey: { table: 'users', column: 'email' },
        values: ['x'],
      }),
    ).rejects.toThrow(/returned 0 ciphertexts for 1/)
  })
})

describe('createCipherstashV3Sdk — decrypt paths', () => {
  it('decrypt forwards the v3 EQL payload and unwraps the Result', async () => {
    const users = makeUsersTable()
    const { client, calls } = makeFakeClient()
    const sdk = createCipherstashV3Sdk(client, [users])
    const payload = { c: 'ct', i: { t: 'users', c: 'email' } }

    await expect(
      sdk.decrypt({ ciphertext: payload, table: 'users', column: 'email' }),
    ).resolves.toBe('pt-single')
    expect(calls.decrypt).toEqual([payload])
  })

  it('decrypt rejects a non-object ciphertext with a v3 diagnostic', async () => {
    const users = makeUsersTable()
    const { client } = makeFakeClient()
    const sdk = createCipherstashV3Sdk(client, [users])
    await expect(
      sdk.decrypt({ ciphertext: 'raw-text', table: 'users', column: 'email' }),
    ).rejects.toThrow(/not a valid EQL v3 payload/)
  })

  it('bulkDecrypt maps payloads through and unwraps per-entry data', async () => {
    const users = makeUsersTable()
    const { client, calls } = makeFakeClient()
    const sdk = createCipherstashV3Sdk(client, [users])

    const out = await sdk.bulkDecrypt({
      routingKey: { table: 'users', column: 'email' },
      ciphertexts: [{ c: 'a' }, { c: 'b' }],
    })
    expect(out).toEqual(['pt-0', 'pt-1'])
    expect(calls.bulkDecrypt).toEqual([[{ c: 'a' }, { c: 'b' }]])
  })

  it('bulkDecrypt throws on a per-entry error', async () => {
    const users = makeUsersTable()
    const { client } = makeFakeClient()
    client.bulkDecrypt = async () => ({
      data: [{ error: 'entry-broke' }],
    })
    const sdk = createCipherstashV3Sdk(client, [users])
    await expect(
      sdk.bulkDecrypt({
        routingKey: { table: 'users', column: 'email' },
        ciphertexts: [{ c: 'a' }],
      }),
    ).rejects.toThrow(/entry failed: entry-broke/)
  })

  it('bulkDecrypt surfaces a whole-call failure', async () => {
    const users = makeUsersTable()
    const { client } = makeFakeClient()
    client.bulkDecrypt = async () => ({ failure: { message: 'downstream' } })
    const sdk = createCipherstashV3Sdk(client, [users])
    await expect(
      sdk.bulkDecrypt({
        routingKey: { table: 'users', column: 'email' },
        ciphertexts: [{ c: 'a' }],
      }),
    ).rejects.toThrow(/bulkDecrypt failed: downstream/)
  })
})
