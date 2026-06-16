import { describe, expect, it } from 'vitest'
import { createCipherstashStringV3Codec } from '../../src/execution/codec-v3'
import { EncryptedString } from '../../src/execution/envelope-string'
import { makeFakeSdk } from './helpers/fake-sdk'

// The real SqlCodecCallContext routing key is `ctx.column = { table, name }`
// (see cell-codec-factory.ts decode body), so the test ctx mirrors that.
const ctx = (table: string, name: string) => ({ column: { table, name } }) as never

describe('createCipherstashStringV3Codec', () => {
  it('decode parses plain-jsonb wire, stamps (table,column), keeps ciphertext', async () => {
    const codec = createCipherstashStringV3Codec(makeFakeSdk())
    const env = await codec.decode('{"v":2,"i":{"t":"users","c":"email"},"c":"ct"}', ctx('users', 'email'))
    expect(env).toBeInstanceOf(EncryptedString)
    const h = (env as EncryptedString).expose()
    expect(h.table).toBe('users')
    expect(h.column).toBe('email')
    expect(h.ciphertext).toEqual({ v: 2, i: { t: 'users', c: 'email' }, c: 'ct' })
  })

  it('encode passes through an already-replaced wire string unchanged (0.8 primary path)', async () => {
    const codec = createCipherstashStringV3Codec(makeFakeSdk())
    const wire = '{"v":2,"i":{"t":"t","c":"c"},"c":"ct"}'
    expect(await codec.encode(wire as never, {} as never)).toBe(wire)
  })

  it('encode of an envelope WITH ciphertext returns plain-jsonb (JSON.stringify), not a v2 composite', async () => {
    const codec = createCipherstashStringV3Codec(makeFakeSdk())
    const env = EncryptedString.fromInternal({
      ciphertext: { v: 2, i: { t: 't', c: 'c' }, c: 'ct' },
      table: 't',
      column: 'c',
      sdk: makeFakeSdk(),
    })
    expect(await codec.encode(env as never, {} as never)).toBe('{"v":2,"i":{"t":"t","c":"c"},"c":"ct"}')
  })

  it('decode passes a null wire through to a null-bearing envelope (NULL round-trips)', async () => {
    const codec = createCipherstashStringV3Codec(makeFakeSdk())
    const env = await codec.decode(null as never, ctx('t', 'c'))
    expect((env as EncryptedString).expose().ciphertext ?? null).toBeNull()
  })
})
