import { inspect } from 'node:util'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { Cipher, Ciphertext, Keyset, type RecipherError } from '../../src/index'
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
  const kindOf = (error: RecipherError | undefined) => error?.kind

  it('refuses bytes that are not a ciphertext, without quoting them', () => {
    const result = Ciphertext.fromBytes(new TextEncoder().encode('plain text'))
    expect(kindOf(result.err())).toBe('open')
    expect(result.err()?.message).not.toContain('plain text')
  })

  it('refuses an altered ciphertext as one that did not open', async () => {
    const c = await cipher()
    const bytes = (await c.defaultKeyset().encrypt('intact')).unwrap().toBytes()
    const last = bytes.length - 1
    bytes[last] = (bytes[last] ?? 0) ^ 0x01
    const opened = await c.decrypt(Ciphertext.fromBytes(bytes).unwrap())
    expect(kindOf(opened.err())).toBe('open')
    expect(opened.err()?.message).not.toContain('intact')
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

  it('refuses a value that is not a string', async () => {
    const keyset = (await cipher()).defaultKeyset()
    // @ts-expect-error: this build encrypts a string.
    const result = await keyset.encrypt(5)
    expect(kindOf(result.err())).toBe('value')
    expect(result.err()?.code).toBe('recipher::not_a_string')
  })

  it('refuses a string with an unpaired surrogate, with a code of its own', async () => {
    const result = await (await cipher()).defaultKeyset().encrypt('\uD800')
    expect(result.err()?.kind).toBe('value')
    expect(result.err()?.code).toBe('recipher::unpaired_surrogate')
  })

  it('names the rule vitaminc refused a value by', async () => {
    const keyset = (await cipher()).defaultKeyset()
    const cases: [unknown, string][] = [
      [new Map(), 'recipher::not_plain'],
      [new Uint16Array(2), 'recipher::not_bytes'],
      [Symbol('s'), 'recipher::not_a_value'],
    ]
    for (const [value, code] of cases) {
      const result = await keyset.encrypt(value as string)
      expect(result.err()?.code).toBe(code)
    }
  })

  it('refuses a decrypt of something that is not a ciphertext', async () => {
    const c = await cipher()
    // @ts-expect-error: decrypt takes a Ciphertext.
    const result = await c.decrypt(new Uint8Array(8))
    expect(result.err()?.code).toBe('recipher::not_a_ciphertext')
  })

  it('refuses a test cipher seed of the wrong length', async () => {
    const result = await testCipher({ seed: new Uint8Array(3) })
    expect(result.err()?.code).toBe('recipher::testing_seed')
  })
})

describe('no call throws', () => {
  it('a method passed on its own keeps its cipher', async () => {
    const c = await cipher()
    const keyset = c.defaultKeyset()
    const sealed = (await Promise.all(['a', 'b'].map(keyset.encrypt))).map(
      (result) => result.unwrap(),
    )
    const opened = await Promise.all(sealed.map(c.decrypt))
    expect(opened.map((result) => result.unwrap())).toEqual(['a', 'b'])
    const { decrypt } = keyset
    expect((await decrypt(sealed[0] as Ciphertext)).unwrap()).toBe('a')
    const { fromBytes } = Ciphertext
    expect(fromBytes((sealed[0] as Ciphertext).toBytes()).isOk()).toBe(true)
  })

  it('a method called on something that is not its class is an Err', async () => {
    const decrypt = Object.getOwnPropertyDescriptor(Cipher.prototype, 'decrypt')
    const method = decrypt?.get?.call({}) as (value: unknown) => unknown
    const result = (await method('x')) as { err(): RecipherError | undefined }
    expect(result.err()?.kind).toBe('internal')
  })

  it('arguments of every wrong type resolve to an Err', async () => {
    const c = await cipher()
    const keyset = c.defaultKeyset()
    const wrong: unknown[] = [
      undefined,
      null,
      0,
      {},
      [],
      Symbol('s'),
      () => 1,
      new Map(),
    ]
    for (const value of wrong) {
      const anyValue = value as never
      expect((await keyset.encrypt(anyValue)).isErr()).toBe(true)
      expect((await keyset.decrypt(anyValue)).isErr()).toBe(true)
      expect((await c.decrypt(anyValue)).isErr()).toBe(true)
      expect(Ciphertext.fromBytes(anyValue).isErr()).toBe(true)
      expect((await testCipher({ seed: anyValue })).isErr()).toBe(
        value !== undefined && value !== null,
      )
    }
    expect((await testCipher(null)).isOk()).toBe(true)
  })

  it('a getter that throws while the value is read is an Err without its message', async () => {
    const keyset = (await cipher()).defaultKeyset()
    const hostile = {
      get secret(): string {
        throw new Error('card 4111 is invalid')
      },
    }
    const result = await keyset.encrypt(hostile as never)
    expect(result.err()?.kind).toBe('value')
    expect(result.err()?.code).toBe('recipher::threw')
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

  it('resolves to a credential error, and does not throw, with no credentials', async () => {
    const result = await Cipher.create()
    expect(result.err()?.kind).toBe('credential')
  })
})
