/**
 * v3 read-path pin. v3 reuses the EncryptedString envelope and the v2 decrypt
 * path verbatim: a v3 STORED payload `{v, i:{t,c}, c}` is exactly the protect-ffi
 * Encrypted shape, so it passes `isEncryptedPayload` / `ensureEncryptedEnvelope`
 * unchanged, and `decryptAll` / `EncryptedString#decrypt()` are version-agnostic.
 * No decrypt code change was needed (Round-3 §B1) — this test pins it as a
 * regression.
 */
import { isEncryptedPayload } from '@cipherstash/stack'
import { describe, expect, it, vi } from 'vitest'
import { createCipherstashStringV3Codec } from '../../src/execution/codec-v3'
import { decryptAll } from '../../src/execution/decrypt-all'
import { EncryptedString } from '../../src/execution/envelope-string'
import { makeFakeSdk } from './helpers/fake-sdk'

const ctx = (table: string, name: string) => ({ column: { table, name } }) as never

describe('decryptAll over v3 envelopes', () => {
  it('groups v3 read-side envelopes by (table,column) and bulk-decrypts once per group', async () => {
    const bulkDecrypt = vi.fn(makeFakeSdk().bulkDecrypt)
    const sdk = makeFakeSdk({ bulkDecrypt })
    const codec = createCipherstashStringV3Codec(sdk)
    const env = await codec.decode('{"v":2,"i":{"t":"users","c":"email"},"c":"ct"}', ctx('users', 'email'))
    const rows = [{ email: env }]

    await decryptAll(rows)

    expect(bulkDecrypt).toHaveBeenCalledOnce()
    expect(await (rows[0]!.email as EncryptedString).decrypt()).toBe('plaintext')
  })

  it('a v3 stored payload satisfies isEncryptedPayload (the v2 read-path gate)', () => {
    // A v3 STORED value is a full payload; the stack helper that the v2 decrypt
    // path uses must accept it unchanged.
    expect(isEncryptedPayload({ v: 2, i: { t: 'users', c: 'email' }, c: 'ct' })).toBe(true)
    // A v3 SEARCH term (no ciphertext `c`) is NOT a stored value and must never be
    // routed into decrypt; it correctly fails the stored-payload gate.
    expect(isEncryptedPayload({ v: 2, i: { t: 'users', c: 'email' }, hm: 'h' })).toBe(false)
  })
})
