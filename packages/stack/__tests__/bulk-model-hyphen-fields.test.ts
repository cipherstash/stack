/**
 * Regression tests for bulk model reconstruction with hyphenated field names.
 *
 * The bulk model helpers key per-field operation results by a
 * `${modelIndex}-${fieldKey}` id. Reconstruction previously split that id
 * with a naive `split('-')`, truncating any field key containing a hyphen
 * (`some-field` → `some`) — the encrypted/decrypted value then landed under
 * the truncated key and the real field silently vanished from the model.
 * The split now happens at the FIRST hyphen only (`fieldsForModelIndex` in
 * src/encryption/helpers/model-helpers.ts).
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { EncryptionClient } from '@/encryption'
import { Encryption } from '@/index'
import { encryptedColumn, encryptedTable } from '@/schema'

// A protect-ffi-shaped encrypted payload carrying its plaintext in `c` so
// the fake decrypt can undo it (and `isEncryptedPayload` detects it).
const enc = (plaintext: unknown) => ({
  v: 2,
  i: { t: 'users', c: 'col' },
  c: `ct:${String(plaintext)}`,
})

vi.mock('@cipherstash/protect-ffi', () => ({
  newClient: vi.fn(async () => ({ __mock: 'client' })),
  encrypt: vi.fn(async () => enc('x')),
  decrypt: vi.fn(async () => 'decrypted'),
  encryptBulk: vi.fn(
    async (_c: unknown, opts: { plaintexts: Array<{ plaintext: unknown }> }) =>
      opts.plaintexts.map((p) => enc(p.plaintext)),
  ),
  decryptBulk: vi.fn(
    async (
      _c: unknown,
      opts: { ciphertexts: Array<{ ciphertext: { c: string } }> },
    ) => opts.ciphertexts.map((e) => e.ciphertext.c.replace(/^ct:/, '')),
  ),
  decryptBulkFallible: vi.fn(
    async (
      _c: unknown,
      opts: { ciphertexts: Array<{ ciphertext: { c: string } }> },
    ) =>
      opts.ciphertexts.map((e) => ({
        data: e.ciphertext.c.replace(/^ct:/, ''),
      })),
  ),
  encryptQuery: vi.fn(async () => enc('x')),
  encryptQueryBulk: vi.fn(async (_c: unknown, opts: { queries: unknown[] }) =>
    opts.queries.map(() => enc('x')),
  ),
}))

// DB column names deliberately contain hyphens — legal in (quoted) Postgres
// identifiers and previously corrupted by the naive id split.
const users = encryptedTable('users', {
  'some-field': encryptedColumn('some-field').equality(),
  'multi-part-name': encryptedColumn('multi-part-name').equality(),
  plainName: encryptedColumn('plainName').equality(),
})

let client: EncryptionClient

beforeEach(async () => {
  vi.clearAllMocks()
  client = await Encryption({ schemas: [users] })
})

// biome-ignore lint/suspicious/noExplicitAny: test helper unwraps Result
function unwrap(result: any) {
  if (result.failure) {
    throw new Error(`operation failed: ${result.failure.message}`)
  }
  return result.data
}

describe('bulk model helpers with hyphenated field names', () => {
  it('bulkEncryptModels keeps hyphenated field names intact', async () => {
    const models = [
      { 'some-field': 'a', 'multi-part-name': 'b', plainName: 'c', other: 1 },
      { 'some-field': 'd', plainName: 'e', other: 2 },
    ]

    const encrypted = unwrap(await client.bulkEncryptModels(models, users))

    expect(encrypted).toHaveLength(2)
    // The full hyphenated keys survive — no truncated `some` / `multi` keys.
    expect(encrypted[0]['some-field']).toMatchObject({ c: 'ct:a' })
    expect(encrypted[0]['multi-part-name']).toMatchObject({ c: 'ct:b' })
    expect(encrypted[0].plainName).toMatchObject({ c: 'ct:c' })
    expect(encrypted[0]).not.toHaveProperty('some')
    expect(encrypted[0]).not.toHaveProperty('multi')
    expect(encrypted[0].other).toBe(1)
    expect(encrypted[1]['some-field']).toMatchObject({ c: 'ct:d' })
  })

  it('bulkDecryptModels keeps hyphenated field names intact', async () => {
    const models = [
      {
        'some-field': enc('a'),
        'multi-part-name': enc('b'),
        other: 1,
      },
      { 'some-field': enc('c'), other: 2 },
    ]

    const decrypted = unwrap(await client.bulkDecryptModels(models))

    expect(decrypted).toHaveLength(2)
    expect(decrypted[0]['some-field']).toBe('a')
    expect(decrypted[0]['multi-part-name']).toBe('b')
    expect(decrypted[0]).not.toHaveProperty('some')
    expect(decrypted[0]).not.toHaveProperty('multi')
    expect(decrypted[0].other).toBe(1)
    expect(decrypted[1]['some-field']).toBe('c')
  })
})
