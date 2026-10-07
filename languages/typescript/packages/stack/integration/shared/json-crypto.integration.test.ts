/**
 * Live round-trip for the v3 `types.Json()` column — an encrypted JSONB document
 * (`public.eql_v3_json_search`). Proves the new json column model encrypts and decrypts
 * a real document through protect-ffi (no DB query here; containment is exercised
 * by the Drizzle json suite). The stored payload is protect-ffi's
 * `SteVecDocument`, carrying an `sv` array rather than a scalar `c` ciphertext.
 */
import { unwrapResult } from '@cipherstash/test-kit'
import { beforeAll, describe, expect, it } from 'vitest'
import type { EncryptionClient } from '@/encryption/v3'
import { Encryption, encryptedTable, types } from '@/encryption/v3'
import type { JsonDocument } from '@/eql/v3/columns'

const docs = encryptedTable('v3_json_docs', {
  profile: types.Json('profile'),
})

describe('v3 typed client — encrypted JSONB round-trip', () => {
  let client: EncryptionClient<readonly [typeof docs]>

  beforeAll(async () => {
    client = await Encryption({ schemas: [docs] })
  }, 30000)

  it('round-trips a JSON document through encrypt/decrypt', async () => {
    const value = {
      user: 'ada@example.com',
      roles: ['admin', 'eng'],
      active: true,
      meta: { since: 2020 },
    }

    const encrypted = unwrapResult(
      await client.encrypt(value, { table: docs, column: docs.profile }),
    )
    // An encrypted JSONB document carries an `sv` array, not a scalar `c`
    // ciphertext (the stored shape is protect-ffi's `SteVecDocument`).
    expect(Array.isArray((encrypted as { sv?: unknown }).sv)).toBe(true)

    const decrypted = unwrapResult(await client.decrypt(encrypted))
    expect(decrypted).toEqual(value)
  }, 30000)

  it('round-trips a JSON document through the model path', async () => {
    const model = { profile: { user: 'grace@example.com', roles: ['eng'] } }
    const encrypted = unwrapResult(await client.encryptModel(model, docs))
    const decrypted = unwrapResult(await client.decryptModel(encrypted, docs))
    expect(decrypted).toEqual(model)
  }, 30000)

  // A JSON document is not only an object: `types.Json` (and the `JsonDocument`
  // plaintext type) also admit a top-level array and `null`. Pin both so a
  // regression in encrypted-JSONB encoding of non-object roots turns a test red.
  it.each([
    ['array root', [1, 'two', { three: 3 }]],
    ['null root', null],
  ] as const)(
    'round-trips a %s',
    async (_label, value) => {
      const encrypted = unwrapResult(
        await client.encrypt(value, { table: docs, column: docs.profile }),
      )
      const decrypted = unwrapResult(await client.decrypt(encrypted))
      expect(decrypted).toEqual(value)
    },
    30000,
  )

  // `toJsPlaintext` (src/encryption/helpers/js-plaintext.ts) casts a JSON
  // document to protect-ffi's `JsPlaintext`, whose array type omits `null`, on
  // the claim that the FFI accepts `null` array ELEMENTS anyway. A top-level
  // `null` never reaches the FFI (encrypt short-circuits it), so the null-root
  // case above does not prove that claim — these do, on both the single and the
  // bulk encrypt paths.
  it.each<[string, JsonDocument]>([
    [
      'object with null array elements',
      { tags: ['a', null], grid: [[null, 1]] },
    ],
    ['array root with a null element', [null, 1]],
  ])(
    'round-trips an %s through encrypt',
    async (_label, value) => {
      const encrypted = unwrapResult(
        await client.encrypt(value, { table: docs, column: docs.profile }),
      )
      expect(encrypted).not.toBeNull()
      expect(Array.isArray((encrypted as { sv?: unknown }).sv)).toBe(true)

      const decrypted = unwrapResult(await client.decrypt(encrypted))
      expect(decrypted).toEqual(value)
    },
    30000,
  )

  it('round-trips a document with null array elements through bulkEncrypt', async () => {
    const value = { tags: ['a', null], grid: [[null, 1]] }

    const encrypted = unwrapResult(
      await client.bulkEncrypt([{ id: 'nulls', plaintext: value }], {
        table: docs,
        column: docs.profile,
      }),
    )
    expect(encrypted).toHaveLength(1)
    expect(encrypted[0].data).not.toBeNull()
    expect(Array.isArray((encrypted[0].data as { sv?: unknown }).sv)).toBe(true)

    const decrypted = unwrapResult(
      await client.bulkDecrypt([{ id: 'nulls', data: encrypted[0].data }]),
    )
    expect(decrypted).toHaveLength(1)
    expect(decrypted[0].data).toEqual(value)
  }, 30000)

  // The boundary the `JsonDocument` type encodes: a top-level SCALAR is not a
  // JSON document. protect-ffi rejects it ("Cannot convert … to Json") — a bare
  // scalar belongs in a scalar domain (`types.TextEq`, `types.IntegerEq`, …).
  // `as never` bypasses the compile-time block to prove the runtime enforces it.
  it.each([
    ['string', 'hello'],
    ['number', 42],
    ['boolean', true],
  ] as const)(
    'rejects a top-level %s scalar at encrypt',
    async (_label, scalar) => {
      const result = await client.encrypt(scalar as never, {
        table: docs,
        column: docs.profile,
      })
      expect(result.failure).toBeDefined()
      expect(result.failure?.message).toMatch(/convert .* to Json/i)
    },
    30000,
  )
})
