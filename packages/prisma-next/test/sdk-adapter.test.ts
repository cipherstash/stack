/**
 * Behaviour pins for `createCipherstashSdk`.
 *
 * Uses a hand-built fake `EncryptionClient` (no live ZeroKMS) — every
 * call returns a deterministic, inspectable result so the adapter's
 * routing, coercion, and error-mapping logic can be observed at the
 * boundary.
 */

import type { EncryptionClient } from '@cipherstash/stack/client'
import { encryptedColumn, encryptedTable } from '@cipherstash/stack/schema'
import { describe, expect, it, vi } from 'vitest'

import { createCipherstashSdk } from '../src/stack/sdk-adapter'

interface FakeBulkEncryptCall {
  readonly plaintexts: ReadonlyArray<unknown>
  readonly column: unknown
  readonly table: unknown
}

interface FakeClientHandle {
  readonly client: EncryptionClient
  readonly bulkEncryptCalls: FakeBulkEncryptCall[]
  readonly bulkDecryptCalls: ReadonlyArray<unknown>[]
  readonly decryptCalls: unknown[]
}

function makeFakeClient(): FakeClientHandle {
  const bulkEncryptCalls: FakeBulkEncryptCall[] = []
  const bulkDecryptCalls: ReadonlyArray<unknown>[] = []
  const decryptCalls: unknown[] = []

  const client = {
    bulkEncrypt: vi.fn(
      async (
        plaintexts: ReadonlyArray<{ plaintext: unknown }>,
        opts: { column: unknown; table: unknown },
      ) => {
        bulkEncryptCalls.push({
          plaintexts: plaintexts.map((p) => p.plaintext),
          column: opts.column,
          table: opts.table,
        })
        return {
          failure: null,
          data: plaintexts.map((_, i) => ({ data: `ct-${i}` as unknown })),
        } as { failure: null; data: ReadonlyArray<{ data: unknown }> }
      },
    ),
    bulkDecrypt: vi.fn(async (payload: ReadonlyArray<{ data: unknown }>) => {
      bulkDecryptCalls.push(payload.map((p) => p.data))
      return {
        failure: null,
        data: payload.map((p, i) => ({ id: i, data: `pt-${i}` as unknown })),
      } as {
        failure: null
        data: ReadonlyArray<{ id?: number; data?: unknown; error?: unknown }>
      }
    }),
    decrypt: vi.fn(async (ciphertext: unknown) => {
      decryptCalls.push(ciphertext)
      return { failure: null, data: 'pt-single' as unknown }
    }),
  }

  return {
    client: client as unknown as EncryptionClient,
    bulkEncryptCalls,
    bulkDecryptCalls,
    decryptCalls,
  }
}

const validEnvelope = {
  v: 2,
  i: { t: 'users', c: 'email' },
  c: 'ct-blob',
}

describe('createCipherstashSdk — routing-key lookup', () => {
  it('resolves a (table, column) routing key to the typed schema objects', async () => {
    const users = encryptedTable('users', {
      email: encryptedColumn('email').equality(),
    })
    const fake = makeFakeClient()
    const sdk = createCipherstashSdk(fake.client, [users])

    await sdk.bulkEncrypt({
      routingKey: { table: 'users', column: 'email' },
      values: ['alice'],
    })

    expect(fake.bulkEncryptCalls).toHaveLength(1)
    expect(fake.bulkEncryptCalls[0]?.table).toBe(users)
    expect(fake.bulkEncryptCalls[0]?.column).toBe(users.email)
    expect(fake.bulkEncryptCalls[0]?.plaintexts).toEqual(['alice'])
  })

  it('throws a clear error when the routing-key table is unknown', async () => {
    const users = encryptedTable('users', {
      email: encryptedColumn('email').equality(),
    })
    const fake = makeFakeClient()
    const sdk = createCipherstashSdk(fake.client, [users])

    await expect(
      sdk.bulkEncrypt({
        routingKey: { table: 'audit_log', column: 'message' },
        values: ['x'],
      }),
    ).rejects.toThrow(/routing-key table "audit_log"/)
  })

  it('throws a clear error when the routing-key column is unknown on a known table', async () => {
    const users = encryptedTable('users', {
      email: encryptedColumn('email').equality(),
    })
    const fake = makeFakeClient()
    const sdk = createCipherstashSdk(fake.client, [users])

    await expect(
      sdk.bulkEncrypt({
        routingKey: { table: 'users', column: 'phone' },
        values: ['x'],
      }),
    ).rejects.toThrow(/column "phone" is not on stack table "users"/)
  })
})

describe('createCipherstashSdk — plaintext coercion at the boundary', () => {
  it('coerces bigint to Number when in the safe-integer range', async () => {
    const accounts = encryptedTable('accounts', {
      id: encryptedColumn('id').dataType('bigint').equality(),
    })
    const fake = makeFakeClient()
    const sdk = createCipherstashSdk(fake.client, [accounts])

    await sdk.bulkEncrypt({
      routingKey: { table: 'accounts', column: 'id' },
      values: [123_456n, 0n, -9_007_199_254_740_991n],
    })

    expect(fake.bulkEncryptCalls[0]?.plaintexts).toEqual([
      123_456, 0, -9_007_199_254_740_991,
    ])
  })

  it('throws on bigint overflow rather than truncating silently', async () => {
    const accounts = encryptedTable('accounts', {
      id: encryptedColumn('id').dataType('bigint').equality(),
    })
    const fake = makeFakeClient()
    const sdk = createCipherstashSdk(fake.client, [accounts])

    await expect(
      sdk.bulkEncrypt({
        routingKey: { table: 'accounts', column: 'id' },
        // 2^54 — one past Number.MAX_SAFE_INTEGER
        values: [BigInt(2) ** BigInt(54)],
      }),
    ).rejects.toThrow(/exceeds Number\.MAX_SAFE_INTEGER/)
  })

  it('coerces Date to an ISO 8601 string', async () => {
    const events = encryptedTable('events', {
      at: encryptedColumn('at').dataType('date').equality(),
    })
    const fake = makeFakeClient()
    const sdk = createCipherstashSdk(fake.client, [events])

    await sdk.bulkEncrypt({
      routingKey: { table: 'events', column: 'at' },
      values: [new Date('2026-05-13T08:00:00.000Z')],
    })

    expect(fake.bulkEncryptCalls[0]?.plaintexts).toEqual([
      '2026-05-13T08:00:00.000Z',
    ])
  })

  it('passes string / number / boolean / object plaintexts through unchanged', async () => {
    const t = encryptedTable('t', {
      c: encryptedColumn('c').equality(),
    })
    const fake = makeFakeClient()
    const sdk = createCipherstashSdk(fake.client, [t])

    await sdk.bulkEncrypt({
      routingKey: { table: 't', column: 'c' },
      values: ['s', 1, true, { k: 'v' }],
    })

    expect(fake.bulkEncryptCalls[0]?.plaintexts).toEqual([
      's',
      1,
      true,
      { k: 'v' },
    ])
  })
})

describe('createCipherstashSdk — bulkDecrypt envelope validation', () => {
  it('rejects ciphertext values that are not EQL v2 envelopes with a clear error', async () => {
    const t = encryptedTable('t', { c: encryptedColumn('c').equality() })
    const fake = makeFakeClient()
    const sdk = createCipherstashSdk(fake.client, [t])

    await expect(
      sdk.bulkDecrypt({
        routingKey: { table: 't', column: 'c' },
        ciphertexts: [validEnvelope, { not: 'an envelope' }],
      }),
    ).rejects.toThrow(/at index 1.*not a valid EQL v2 envelope/)
  })

  it('forwards valid envelopes to the underlying client.bulkDecrypt', async () => {
    const t = encryptedTable('t', { c: encryptedColumn('c').equality() })
    const fake = makeFakeClient()
    const sdk = createCipherstashSdk(fake.client, [t])

    const result = await sdk.bulkDecrypt({
      routingKey: { table: 't', column: 'c' },
      ciphertexts: [validEnvelope, validEnvelope],
    })

    expect(fake.bulkDecryptCalls).toHaveLength(1)
    expect(fake.bulkDecryptCalls[0]).toEqual([validEnvelope, validEnvelope])
    expect(result).toEqual(['pt-0', 'pt-1'])
  })
})

describe('createCipherstashSdk — error mapping', () => {
  it('propagates underlying client failures as Error with the failure message', async () => {
    const t = encryptedTable('t', { c: encryptedColumn('c').equality() })
    const failingClient = {
      bulkEncrypt: async () => ({
        failure: { message: 'workspace credentials missing' },
      }),
      bulkDecrypt: async () => ({ failure: null, data: [] }),
      decrypt: async () => ({ failure: null, data: '' }),
    } as unknown as EncryptionClient
    const sdk = createCipherstashSdk(failingClient, [t])

    await expect(
      sdk.bulkEncrypt({
        routingKey: { table: 't', column: 'c' },
        values: ['x'],
      }),
    ).rejects.toThrow(/workspace credentials missing/)
  })
})
