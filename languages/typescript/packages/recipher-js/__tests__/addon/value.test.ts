import { inspect } from 'node:util'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { Cipher, Ciphertext, Keyset } from '../../src/index'
import { testCipher } from '../../src/testing'

async function cipher(seed?: Uint8Array): Promise<Cipher> {
  return (await testCipher(seed ? { seed } : {})).unwrap()
}

describe('one string, with no context', () => {
  it('encrypts and decrypts through the cipher and the keyset', async () => {
    const c = await cipher()
    expect(c).toBeInstanceOf(Cipher)
    const keyset = c.defaultKeyset()
    expect(keyset).toBeInstanceOf(Keyset)
    const sealed = (await keyset.encrypt('a secret message')).unwrap()
    expect(sealed).toBeInstanceOf(Ciphertext)

    expect((await c.decrypt(sealed)).unwrap()).toBe('a secret message')
    expect((await keyset.decrypt(sealed)).unwrap()).toBe('a secret message')
  })

  it('round-trips through stored bytes', async () => {
    const c = await cipher()
    const sealed = (await c.defaultKeyset().encrypt('stored')).unwrap()
    const bytes = sealed.toBytes()
    expect(bytes).toBeInstanceOf(Uint8Array)

    const read = Ciphertext.fromBytes(bytes).unwrap()
    expect((await c.decrypt(read)).unwrap()).toBe('stored')
    // A Buffer is a Uint8Array.
    const again = Ciphertext.fromBytes(Buffer.from(bytes)).unwrap()
    expect((await c.decrypt(again)).unwrap()).toBe('stored')
  })

  it('opens in another test cipher with the same seed', async () => {
    const seed = new Uint8Array(32).fill(9)
    const sealed = (
      await (await cipher(seed)).defaultKeyset().encrypt('kept')
    ).unwrap()
    expect((await (await cipher(seed)).decrypt(sealed)).unwrap()).toBe('kept')
  })

  it('gives each value its own ciphertext', async () => {
    const keyset = (await cipher()).defaultKeyset()
    const a = (await keyset.encrypt('same')).unwrap().toBytes()
    const b = (await keyset.encrypt('same')).unwrap().toBytes()
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false)
  })

  it('encrypts the empty string and text outside ASCII', async () => {
    const c = await cipher()
    for (const text of ['', 'héllo wörld', '日本語', '🔐']) {
      const sealed = (await c.defaultKeyset().encrypt(text)).unwrap()
      expect((await c.decrypt(sealed)).unwrap()).toBe(text)
    }
  })

  it('hides the bytes when printed or inspected', async () => {
    const sealed = (
      await (await cipher()).defaultKeyset().encrypt('printed')
    ).unwrap()
    expect(String(sealed)).toBe('Ciphertext(***)')
    const shown = inspect(sealed, { showHidden: true, depth: 5 })
    expect(shown).not.toContain('printed')
    expect(shown).not.toMatch(/\d+, \d+, \d+/)
  })

  it('copies the bytes it gives', async () => {
    const sealed = (
      await (await cipher()).defaultKeyset().encrypt('x')
    ).unwrap()
    const bytes = sealed.toBytes()
    bytes.fill(0)
    expect(sealed.toBytes()).not.toEqual(bytes)
  })
})

describe('failures are values', () => {
  it('refuses bytes that are not a ciphertext, without quoting them', () => {
    const result = Ciphertext.fromBytes(new TextEncoder().encode('plain text'))
    expect(result.err()?.code).toBe('stack_encrypt::leaf_version')
    expect(result.err()?.message).not.toContain('plain text')
  })

  it('refuses an altered ciphertext as one that did not open', async () => {
    const c = await cipher()
    const bytes = (await c.defaultKeyset().encrypt('intact')).unwrap().toBytes()
    const last = bytes.length - 1
    bytes[last] = (bytes[last] ?? 0) ^ 0x01
    const opened = await c.decrypt(Ciphertext.fromBytes(bytes).unwrap())
    const error = opened.err()
    expect(error?.code).toBe('stack_encrypt::aead')
    expect(error?.message).toBe(
      'AEAD operation failed (wrong key, AAD mismatch, or malformed ciphertext)',
    )
    // The engine's help is a property of its own, never part of the message.
    expect(error?.help).toMatch(/^Open the value under the context/)
    expect(error?.severity).toBe('error')
    expect(error?.fields).toEqual({})
    expect(error?.causes).toEqual([])
    expect(String(error)).not.toContain('intact')
  })

  it('refuses a value from another seed, which is another key', async () => {
    const sealed = (
      await (
        await cipher(new Uint8Array(32).fill(1))
      )
        .defaultKeyset()
        .encrypt('elsewhere')
    ).unwrap()
    const opened = await (await cipher(new Uint8Array(32).fill(2))).decrypt(
      sealed,
    )
    expect(opened.isErr()).toBe(true)
  })

  it('refuses a string with an unpaired surrogate, with a code of its own', async () => {
    const result = await (await cipher()).defaultKeyset().encrypt('\uD800')
    expect(result.err()?.code).toBe('recipher_js::unpaired_surrogate')
  })

  it('names the rule a refused value broke', async () => {
    const keyset = (await cipher()).defaultKeyset()
    const cases: [unknown, string][] = [
      [new Map(), 'recipher_js::not_plain'],
      [new Uint16Array(2), 'recipher_js::not_bytes'],
      [Symbol('s'), 'recipher_js::not_a_value'],
    ]
    for (const [value, code] of cases) {
      const result = await keyset.encrypt(value as string)
      expect(result.err()?.code).toBe(code)
    }
  })

  it('refuses a decrypt of something that is not a ciphertext', async () => {
    const c = await cipher()
    // @ts-expect-error: decrypt accepts a Ciphertext.
    const result = await c.decrypt(new Uint8Array(8))
    expect(result.err()?.code).toBe('recipher_js::not_a_ciphertext')
  })

  it('refuses a test cipher seed of the wrong length', async () => {
    const result = await testCipher({ seed: new Uint8Array(3) })
    expect(result.err()?.code).toBe('recipher_js::testing_seed')
  })
})

describe('a method called without its object throws a TypeError', () => {
  // The JavaScript engine checks a native method's object before any of
  // the addon's code runs, so this is the one case that throws rather than
  // returning an Err. A static method has no object, and works on its own.
  it('an instance method taken off its object throws, synchronously', async () => {
    const c = await cipher()
    const keyset = c.defaultKeyset()
    const sealed = (await keyset.encrypt('a')).unwrap()
    const { encrypt, decrypt } = keyset
    const { decrypt: cipherDecrypt, defaultKeyset } = c
    const { toBytes } = sealed
    expect(() => encrypt('a')).toThrow(TypeError)
    expect(() => decrypt(sealed)).toThrow(TypeError)
    expect(() => cipherDecrypt(sealed)).toThrow(TypeError)
    expect(() => defaultKeyset()).toThrow(TypeError)
    expect(() => toBytes()).toThrow(TypeError)
    expect(() => [sealed].map(c.decrypt)).toThrow(TypeError)
  })

  it('a method called on something that is not its class throws', () => {
    const decrypt = Cipher.prototype.decrypt as (value: unknown) => unknown
    expect(() => decrypt.call({}, 'x')).toThrow(TypeError)
    const fromKeyset = Keyset.prototype.decrypt as (value: unknown) => unknown
    expect(() => fromKeyset.call(Cipher, 'x')).toThrow(TypeError)
  })

  it('a method called on its object, or through a closure, works', async () => {
    const c = await cipher()
    const keyset = c.defaultKeyset()
    const sealed = (
      await Promise.all(['a', 'b'].map((text) => keyset.encrypt(text)))
    ).map((result) => result.unwrap())
    const opened = await Promise.all(
      sealed.map((ciphertext) => c.decrypt(ciphertext)),
    )
    expect(opened.map((result) => result.unwrap())).toEqual(['a', 'b'])
    const bound = keyset.decrypt.bind(keyset)
    expect((await bound(sealed[0] as Ciphertext)).unwrap()).toBe('a')
  })

  it('a static method taken off its class works', async () => {
    const sealed = (
      await (await cipher()).defaultKeyset().encrypt('a')
    ).unwrap()
    const { fromBytes } = Ciphertext
    expect(fromBytes(sealed.toBytes()).isOk()).toBe(true)
  })
})

describe('every other call returns or resolves to a Result', () => {
  it('a missing or extra argument is an Err, not a throw', async () => {
    const c = await cipher()
    const keyset = c.defaultKeyset()
    const loose = keyset as unknown as {
      encrypt(...args: unknown[]): ReturnType<Keyset['encrypt']>
      decrypt(...args: unknown[]): ReturnType<Keyset['decrypt']>
    }
    expect((await loose.encrypt()).err()?.code).toBe('recipher_js::undefined')
    expect((await loose.decrypt()).err()?.code).toBe(
      'recipher_js::not_a_ciphertext',
    )
    const sealed = (await loose.encrypt('a', 'extra')).unwrap()
    expect((await loose.decrypt(sealed, 'extra')).unwrap()).toBe('a')
    const fromBytes = Ciphertext.fromBytes as (...args: unknown[]) => unknown
    expect((fromBytes() as { isErr(): boolean }).isErr()).toBe(true)
  })

  it('arguments of every wrong type resolve to an Err', async () => {
    const c = await cipher()
    const keyset = c.defaultKeyset()
    const notValues: unknown[] = [
      undefined,
      {},
      Symbol('s'),
      () => 1,
      new Map(),
    ]
    for (const value of notValues) {
      expect((await keyset.encrypt(value as never)).isErr()).toBe(true)
    }
    const notCiphertexts: unknown[] = [...notValues, null, 0, 'text', [1]]
    for (const value of notCiphertexts) {
      const anyValue = value as never
      expect((await keyset.decrypt(anyValue)).isErr()).toBe(true)
      expect((await c.decrypt(anyValue)).isErr()).toBe(true)
      expect(Ciphertext.fromBytes(anyValue).isErr()).toBe(true)
      expect((await testCipher({ seed: anyValue })).isErr()).toBe(
        value !== undefined && value !== null,
      )
    }
    expect((await testCipher(null)).isOk()).toBe(true)
  })

  it('options that are not an object are an Err, not the default seed', async () => {
    for (const options of [42, true, 'seed', 0n, Symbol('s')]) {
      const result = await testCipher(options as never)
      expect(result.err()?.code, String(typeof options)).toBe(
        'recipher_js::testing_seed',
      )
    }
  })

  it('a getter that throws while the value is read is an Err without its message', async () => {
    const keyset = (await cipher()).defaultKeyset()
    const hostile = {
      get secret(): string {
        throw new Error('card 4111 is invalid')
      },
    }
    const result = await keyset.encrypt(hostile as never)
    expect(result.err()?.code).toBe('recipher_js::threw')
    expect(result.err()?.message).not.toContain('4111')
  })
})

describe('Cipher.create', () => {
  const saved: Record<string, string | undefined> = {}
  const VARS = [
    'CS_CLIENT_ID',
    'CS_CLIENT_KEY',
    'CS_CLIENT_ACCESS_KEY',
    'CS_WORKSPACE_CRN',
    'CS_CONFIG_PATH',
  ]

  beforeEach(async () => {
    const { mkdtempSync } = await import('node:fs')
    const { tmpdir } = await import('node:os')
    const { join } = await import('node:path')
    for (const name of VARS) {
      saved[name] = process.env[name]
      delete process.env[name]
    }
    // An empty profile directory, so no saved login is found and no
    // request is made.
    process.env.CS_CONFIG_PATH = mkdtempSync(join(tmpdir(), 'recipher-'))
  })

  afterEach(() => {
    for (const name of VARS) {
      if (saved[name] === undefined) {
        delete process.env[name]
      } else {
        process.env[name] = saved[name]
      }
    }
  })

  it('resolves to a configuration error, and does not throw, with no credentials', async () => {
    const result = await Cipher.create()
    expect(result.err()?.code).toBe('stack_encrypt::config')
  })
})
