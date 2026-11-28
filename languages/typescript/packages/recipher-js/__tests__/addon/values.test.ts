import { inspect } from 'node:util'
import { describe, expect, it } from 'vitest'
import {
  type Cipher,
  Ciphertext,
  json,
  kinds,
  RcDate,
  RcDecimal,
  RcTimestamp,
  RcUuid,
} from '../../src/index'
import { testCipher } from '../../src/testing'
import { standInWrapper } from '../../src/values'

async function cipher(): Promise<Cipher> {
  return (await testCipher()).unwrap()
}

/** Encrypt one value, read it back from its stored bytes, and decrypt it. */
async function roundTrip(value: Parameters<typeof encryptOne>[1]) {
  const c = await cipher()
  const sealed = await encryptOne(c, value)
  const stored = Ciphertext.fromBytes(sealed.toBytes()).unwrap()
  return (await c.decrypt(stored)).unwrap()
}

async function encryptOne(
  c: Cipher,
  value:
    | string
    | boolean
    | number
    | bigint
    | Uint8Array
    | Date
    | RcDate
    | RcTimestamp
    | RcDecimal
    | null,
) {
  return (await c.defaultKeyset().encrypt(value)).unwrap()
}

describe('every value in the mapping round-trips', () => {
  it('text, booleans and numbers', async () => {
    expect(await roundTrip('text')).toBe('text')
    expect(await roundTrip(true)).toBe(true)
    expect(await roundTrip(false)).toBe(false)
    expect(await roundTrip(1.5)).toBe(1.5)
    expect(await roundTrip(-0.25)).toBe(-0.25)
    // A number is a float: 5 stays the number 5, never the integer 5n.
    expect(await roundTrip(5)).toBe(5)
  })

  it('integers, as bigints, at every width', async () => {
    for (const n of [
      0n,
      -1n,
      127n,
      -128n,
      2n ** 31n,
      2n ** 63n - 1n,
      -(2n ** 63n),
      2n ** 64n - 1n,
      2n ** 127n - 1n,
      -(2n ** 127n),
    ]) {
      expect(await roundTrip(n)).toBe(n)
    }
  })

  it('bytes, from a Uint8Array or a Buffer', async () => {
    const bytes = new Uint8Array([0, 1, 254, 255])
    expect(Buffer.from((await roundTrip(bytes)) as Uint8Array)).toEqual(
      Buffer.from(bytes),
    )
    const buffer = Buffer.from('a file')
    expect(Buffer.from((await roundTrip(buffer)) as Uint8Array)).toEqual(buffer)
  })

  it('a Date, to the millisecond', async () => {
    const date = new Date('2026-11-23T01:02:03.456Z')
    const opened = await roundTrip(date)
    expect(opened).toBeInstanceOf(Date)
    expect((opened as Date).getTime()).toBe(date.getTime())
  })

  it('the wrapper classes', async () => {
    const day = await roundTrip(new RcDate('2026-11-23'))
    expect(day).toBeInstanceOf(RcDate)
    expect((day as RcDate).value).toBe('2026-11-23')

    const fine = await roundTrip(
      new RcTimestamp('2026-11-23T01:02:03.000000001Z'),
    )
    expect(fine).toBeInstanceOf(RcTimestamp)
    expect((fine as RcTimestamp).value).toBe('2026-11-23T01:02:03.000000001Z')

    // A timestamp of whole milliseconds decrypts as a Date.
    const whole = await roundTrip(new RcTimestamp('2026-11-23T01:02:03.000Z'))
    expect(whole).toBeInstanceOf(Date)

    const price = await roundTrip(new RcDecimal('1.50'))
    expect(price).toBeInstanceOf(RcDecimal)
    expect((price as RcDecimal).value).toBe('1.50')
  })

  it('null', async () => {
    expect(await roundTrip(null)).toBeNull()
  })
})

describe('a wrapper class', () => {
  const classes = { RcDate, RcTimestamp, RcDecimal, RcUuid }
  const texts = {
    RcDate: '2026-11-23',
    RcTimestamp: '2026-11-23T01:02:03.000000001Z',
    RcDecimal: '1.50',
    RcUuid: '123e4567-e89b-12d3-a456-426614174000',
  }
  const names = ['RcDate', 'RcTimestamp', 'RcDecimal', 'RcUuid'] as const

  /** What a caller can observe of a class and one instance of it. */
  function observed(
    cls: new (text: string) => object,
    text: string,
  ): Record<string, unknown> {
    const instance = new cls(text)
    let thrown: unknown
    try {
      // @ts-expect-error: the constructor takes a string.
      new cls(20261123)
    } catch (error) {
      thrown = error
    }
    return {
      name: cls.name,
      value: Object.getOwnPropertyDescriptor(instance, 'value'),
      keys: Object.keys(instance),
      string: String(instance),
      json: JSON.stringify(instance),
      inspected: inspect(instance),
      frozen: [
        Object.isFrozen(instance),
        Object.isFrozen(cls),
        Object.isFrozen(cls.prototype),
      ],
      thrown: [
        thrown instanceof TypeError,
        thrown instanceof Error ? thrown.message : thrown,
      ],
    }
  }

  it('takes a string, and throws a TypeError for anything else', () => {
    for (const name of names) {
      // @ts-expect-error: the constructor takes a string.
      expect(() => new classes[name](20261123)).toThrow(TypeError)
      expect(new classes[name](texts[name]).value).toBe(texts[name])
    }
  })

  it('has a stand-in that constructs as it does', () => {
    for (const name of names) {
      expect(observed(standInWrapper(name), texts[name])).toEqual(
        observed(classes[name], texts[name]),
      )
    }
  })
})

describe('an array of values', () => {
  it('is an array of ciphertexts in, an array of values out, in order', async () => {
    const c = await cipher()
    const keyset = c.defaultKeyset()
    const sealed = (await keyset.encrypt(['first', 'second', 'third'])).unwrap()
    expect(sealed).toHaveLength(3)
    expect((await c.decrypt(sealed)).unwrap()).toEqual([
      'first',
      'second',
      'third',
    ])
    expect((await keyset.decrypt(sealed)).unwrap()).toEqual([
      'first',
      'second',
      'third',
    ])
  })

  it('opens each element on its own', async () => {
    const c = await cipher()
    const sealed = (await c.defaultKeyset().encrypt([1n, 2n, 3n])).unwrap()
    const second = sealed[1]
    expect(second).toBeDefined()
    if (second !== undefined) {
      expect((await c.decrypt(second)).unwrap()).toBe(2n)
    }
  })

  it('may mix types', async () => {
    const c = await cipher()
    const sealed = (
      await c.defaultKeyset().encrypt(['a', 1n, true, null] as const)
    ).unwrap()
    expect((await c.decrypt(sealed)).unwrap()).toEqual(['a', 1n, true, null])
  })

  it('is empty in, empty out', async () => {
    const c = await cipher()
    const sealed = (await c.defaultKeyset().encrypt([] as string[])).unwrap()
    expect(sealed).toEqual([])
    expect((await c.decrypt(sealed)).unwrap()).toEqual([])
  })

  it('is refused when it has a hole, to encrypt or to decrypt', async () => {
    const c = await cipher()
    const keyset = c.defaultKeyset()
    // biome-ignore lint/suspicious/noSparseArray: a hole is the case.
    const holed = await keyset.encrypt(['a', , 'b'] as string[])
    expect(holed.err()?.code).toBe('recipher_js::sparse_array')
    const empty = await keyset.encrypt(new Array<string>(3))
    expect(empty.err()?.code).toBe('recipher_js::sparse_array')

    const sealed = (await keyset.encrypt('a')).unwrap()
    // biome-ignore lint/suspicious/noSparseArray: a hole is the case.
    const opened = await c.decrypt([sealed, , sealed] as (typeof sealed)[])
    expect(opened.err()?.code).toBe('recipher_js::sparse_array')
  })

  it('never reads a hole through a polluted Array.prototype', async () => {
    const c = await cipher()
    const keyset = c.defaultKeyset()
    const other = (await keyset.encrypt('not passed')).unwrap()
    const sealed = (await keyset.encrypt('a')).unwrap()
    try {
      Object.defineProperty(Array.prototype, '1', {
        value: 'injected',
        configurable: true,
      })
      // biome-ignore lint/suspicious/noSparseArray: a hole is the case.
      const holed = await keyset.encrypt(['a', , 'b'] as string[])
      expect(holed.err()?.code).toBe('recipher_js::sparse_array')

      // A ciphertext the caller never passed is not decrypted.
      Object.defineProperty(Array.prototype, '1', {
        value: other,
        configurable: true,
      })
      // biome-ignore lint/suspicious/noSparseArray: a hole is the case.
      const opened = await c.decrypt([sealed, , sealed] as (typeof sealed)[])
      expect(opened.err()?.code).toBe('recipher_js::sparse_array')
    } finally {
      Reflect.deleteProperty(Array.prototype, '1')
    }
  })

  it('is refused whole when one element is refused', async () => {
    const keyset = (await cipher()).defaultKeyset()
    // @ts-expect-error: an array inside an array is not a value.
    const result = await keyset.encrypt(['fine', ['nested']])
    expect(result.err()?.code).toBe('recipher_js::not_a_scalar')
  })
})

describe('a JSON document', () => {
  it('round-trips as one ciphertext', async () => {
    const c = await cipher()
    const card = {
      number: '4111 1111 1111 1111',
      expiry: { month: 4, year: 2031 },
      tags: ['a', 'b'],
      active: true,
      note: null,
    }
    const sealed = (await c.defaultKeyset().encrypt(json(card))).unwrap()
    expect((await c.decrypt(sealed)).unwrap()).toEqual(card)
  })

  it('keeps an integer outside the safe range as a bigint', async () => {
    const c = await cipher()
    const document = { big: 18446744073709551615n, small: 5n }
    const sealed = (await c.defaultKeyset().encrypt(json(document))).unwrap()
    // The safe integer comes back as a number. The big one comes back as a
    // bigint.
    expect((await c.decrypt(sealed)).unwrap()).toEqual({
      big: 18446744073709551615n,
      small: 5,
    })
  })

  /** The JSON text a document is stored as: what another SDK reads. */
  async function storedText(document: Parameters<typeof json>[0]) {
    const c = await cipher()
    const sealed = (await c.defaultKeyset().encrypt(json(document))).unwrap()
    // With no kind named, the stored bytes decrypt as their text.
    const untyped = Ciphertext.fromBytes(sealed.toBytes()).unwrap()
    return (await c.decrypt(untyped)).unwrap()
  }

  /** The code and message of the `Err` that encrypting `document` gives. */
  async function refusal(document: unknown) {
    const keyset = (await cipher()).defaultKeyset()
    const result = await keyset.encrypt(json(document as never))
    expect(result.isErr()).toBe(true)
    return { code: result.err()?.code, message: result.err()?.message ?? '' }
  }

  it('stores a whole number as an integer, at every size', async () => {
    // For an integer field, a reader in Go or Rust accepts `5000000000`, and
    // refuses `5000000000.0`.
    expect(await storedText({ n: 5000000000 })).toBe('{"n":5000000000}')
    const now = Date.now()
    expect(await storedText({ t: now })).toBe(`{"t":${now}}`)
    expect(
      await storedText([
        5,
        -5,
        4294967296,
        -5000000000,
        Number.MAX_SAFE_INTEGER,
        Number.MIN_SAFE_INTEGER,
        -0,
      ]),
    ).toBe('[5,-5,4294967296,-5000000000,9007199254740991,-9007199254740991,0]')
  })

  it('stores any other number as a float', async () => {
    const text = await storedText([1.5, 2 ** 64, 1e20])
    expect(JSON.parse(text as string)).toEqual([1.5, 2 ** 64, 1e20])
    // Each has a fraction or an exponent, so no reader reads an integer.
    for (const number of (text as string).slice(1, -1).split(',')) {
      expect(number).toMatch(/[.e]/)
    }
  })

  it('stores a bigint as its digits, within 64 bits', async () => {
    expect(
      await storedText([
        5n,
        2n ** 53n,
        -(2n ** 63n),
        2n ** 63n,
        2n ** 64n - 1n,
      ]),
    ).toBe(
      '[5,9007199254740992,-9223372036854775808,9223372036854775808,18446744073709551615]',
    )
  })

  it('stores the members of an object sorted by key', async () => {
    expect(await storedText({ b: 1, a: 2, c: { z: 1, y: 2 } })).toBe(
      '{"a":2,"b":1,"c":{"y":2,"z":1}}',
    )
    const c = await cipher()
    const sealed = (
      await c.defaultKeyset().encrypt(json({ b: 1, a: 2 }))
    ).unwrap()
    const opened = (await c.decrypt(sealed)).unwrap()
    expect(Object.keys(opened as object)).toEqual(['a', 'b'])
  })

  it('opens an integer as a number in the safe range, and as a bigint outside it', async () => {
    const c = await cipher()
    const document = {
      safe: 9007199254740991n,
      negative: -9007199254740991n,
      edge: 2n ** 53n,
      least: -(2n ** 63n),
      most: 2n ** 64n - 1n,
      float: 1.5,
      whole: 5000000000,
      nested: [{ deep: 2n ** 60n, small: 7n }],
    }
    const sealed = (await c.defaultKeyset().encrypt(json(document))).unwrap()
    expect((await c.decrypt(sealed)).unwrap()).toStrictEqual({
      edge: 9007199254740992n,
      float: 1.5,
      least: -9223372036854775808n,
      most: 18446744073709551615n,
      negative: -9007199254740991,
      nested: [{ deep: 1152921504606846976n, small: 7 }],
      safe: 9007199254740991,
      whole: 5000000000,
    })
  })

  it('opens a document another SDK wrote, whatever its numbers', async () => {
    const c = await cipher()
    const keyset = c.defaultKeyset()
    // Encrypted as the engine encrypts a document: as its JSON text.
    const sealed = (
      await keyset.encrypt(
        '{"float":5.0,"big":1e20,"id":18446744073709551615,"n":-3}',
      )
    ).unwrap()
    const stored = Ciphertext.fromBytes(sealed.toBytes(), kinds.json).unwrap()
    expect((await c.decrypt(stored)).unwrap()).toStrictEqual({
      big: 1e20,
      float: 5,
      id: 18446744073709551615n,
      n: -3,
    })
  })

  it('refuses a whole number from 2^53 up to 2^64, and asks for a bigint', async () => {
    for (const unsafe of [2 ** 53, 2 ** 60, 2 ** 64 - 2048, -(2 ** 53)]) {
      const refused = await refusal({ n: unsafe })
      expect(refused.code).toBe('recipher_js::not_json')
      expect(refused.message).toContain('bigint')
      // The message contains no part of the value.
      expect(refused.message).not.toMatch(/\d{6}/)
    }
  })

  it('refuses a number that is not finite', async () => {
    for (const number of [Number.NaN, Infinity, -Infinity]) {
      const refused = await refusal([number])
      expect(refused.code).toBe('recipher_js::not_json')
      expect(refused.message).toContain('not finite')
    }
  })

  it('refuses a bigint outside 64 bits, at every size', async () => {
    for (const wide of [2n ** 64n, -(2n ** 63n) - 1n, 2n ** 200n]) {
      const refused = await refusal({ id: wide })
      expect(refused.code).toBe('recipher_js::not_json')
      expect(refused.message).toContain('64-bit')
      expect(refused.message).not.toMatch(/\d{6}/)
    }
  })

  it('refuses a value with no JSON form', async () => {
    const keyset = (await cipher()).defaultKeyset()
    // @ts-expect-error: bytes are not JSON.
    const result = await keyset.encrypt(json({ b: new Uint8Array([1]) }))
    expect(result.err()?.code).toBe('recipher_js::not_json')
    for (const value of [
      undefined,
      Buffer.from('4111 1111'),
      new Uint16Array(2),
      new Date('2031-04-01T00:00:00Z'),
      new RcDate('2031-04-01'),
      new RcTimestamp('2031-04-01T00:00:00.000000001Z'),
      new RcDecimal('4111.1111'),
      new RcUuid('123e4567-e89b-12d3-a456-426614174000'),
    ]) {
      for (const document of [value, [value], { member: value }]) {
        const refused = await refusal(document)
        expect(refused.code).toBe('recipher_js::not_json')
        expect(refused.message).not.toMatch(/4111|2031|123e4567/)
      }
    }
  })

  it('refuses a function and a symbol', async () => {
    for (const value of [() => 1, Symbol('s')]) {
      expect((await refusal({ member: value })).code).toBe(
        'recipher_js::not_a_value',
      )
    }
  })

  it('reads a document by the rules for any value', async () => {
    const cases: [unknown, string][] = [
      [new Map([['k', 1]]), 'recipher_js::not_plain'],
      [new (class Card {})(), 'recipher_js::not_plain'],
      // biome-ignore lint/suspicious/noSparseArray: a hole is the case.
      [[1, , 3], 'recipher_js::sparse_array'],
      [{ text: '\uD800' }, 'recipher_js::unpaired_surrogate'],
      [JSON.parse('{"__proto__":1}'), 'recipher_js::reserved_key'],
    ]
    for (const [document, code] of cases) {
      expect((await refusal(document)).code).toBe(code)
    }
    const cycle: unknown[] = []
    cycle.push(cycle)
    expect((await refusal(cycle)).code).toBe('recipher_js::too_deep')
  })

  it('encrypts one Json more than once', async () => {
    const c = await cipher()
    const keyset = c.defaultKeyset()
    const wrapped = json({ id: 2n ** 64n - 1n })
    const sealed = (await keyset.encrypt([wrapped, wrapped])).unwrap()
    expect((await c.decrypt(sealed)).unwrap()).toEqual([
      { id: 18446744073709551615n },
      { id: 18446744073709551615n },
    ])
    expect(
      (await c.decrypt((await keyset.encrypt(wrapped)).unwrap())).unwrap(),
    ).toEqual({ id: 18446744073709551615n })
  })

  it('builds a decrypted document from own properties, past a polluted prototype', async () => {
    const c = await cipher()
    const sealed = (
      await c
        .defaultKeyset()
        .encrypt(json({ leak: 'secret', list: ['secret'] }))
    ).unwrap()
    let captured = 'untouched'
    const capture = {
      set(value: string) {
        captured = value
      },
      configurable: true,
    }
    Object.defineProperty(Object.prototype, 'leak', capture)
    Object.defineProperty(Array.prototype, '0', capture)
    try {
      const opened = (await c.decrypt(sealed)).unwrap() as {
        leak: string
        list: string[]
      }
      expect(captured).toBe('untouched')
      expect(Object.hasOwn(opened, 'leak')).toBe(true)
      expect(opened.list[0]).toBe('secret')
    } finally {
      Reflect.deleteProperty(Object.prototype, 'leak')
      Reflect.deleteProperty(Array.prototype, '0')
    }
  })

  it('read back from stored bytes with kinds.json, opens as the document', async () => {
    const c = await cipher()
    const document = { id: 18446744073709551615n, name: 'Ada' }
    const sealed = (await c.defaultKeyset().encrypt(json(document))).unwrap()
    const stored = Ciphertext.fromBytes(sealed.toBytes(), kinds.json).unwrap()
    expect((await c.decrypt(stored)).unwrap()).toEqual(document)
    // With no kind named, the bytes say only that the value is text.
    const untyped = Ciphertext.fromBytes(sealed.toBytes()).unwrap()
    expect((await c.decrypt(untyped)).unwrap()).toBe(
      '{"id":18446744073709551615,"name":"Ada"}',
    )
  })

  it('nests 127 levels deep and refuses 128 as a value, not as damage', async () => {
    const keyset = (await cipher()).defaultKeyset()
    const nested = (depth: number) => {
      let value: unknown[] = []
      for (let level = 1; level < depth; level++) {
        value = [value]
      }
      return value
    }
    // biome-ignore lint/suspicious/noExplicitAny: a nested array of any depth.
    expect((await keyset.encrypt(json(nested(127) as any))).isOk()).toBe(true)
    // biome-ignore lint/suspicious/noExplicitAny: a nested array of any depth.
    const deep = await keyset.encrypt(json(nested(128) as any))
    expect(deep.err()?.code).toBe('recipher_js::too_deep')
    expect(deep.err()?.message).toContain('127 levels')
  })

  it('writes a large float as a float, so a document read back encrypts again', async () => {
    const c = await cipher()
    for (const document of [
      { x: 1e20 },
      { x: Number.MAX_VALUE },
      JSON.parse('{"x":6.02e23}'),
    ]) {
      const sealed = (await c.defaultKeyset().encrypt(json(document))).unwrap()
      const opened = (await c.decrypt(sealed)).unwrap()
      expect(opened).toEqual(document)
      expect(
        (await c.defaultKeyset().encrypt(json(opened as never))).isOk(),
      ).toBe(true)
    }
  })

  it('refuses a reserved property name, naming the rule, both ways', async () => {
    const c = await cipher()
    const keyset = c.defaultKeyset()
    for (const text of [
      '{"constructor":1}',
      '{"prototype":1}',
      '{"__proto__":{"inherited":1}}',
    ]) {
      const refused = await keyset.encrypt(json(JSON.parse(text)))
      expect(refused.err()?.code).toBe('recipher_js::reserved_key')
      // A document another SDK wrote, encrypted as the engine encrypts one:
      // as its JSON text.
      const sealed = (await keyset.encrypt(text)).unwrap()
      const stored = Ciphertext.fromBytes(sealed.toBytes(), kinds.json).unwrap()
      const opened = await c.decrypt(stored)
      expect(opened.err()?.code).toBe('recipher_js::reserved_key')
    }
  })

  it('reads the document when json(..) is called', async () => {
    const c = await cipher()
    const document = { a: 1 }
    const wrapped = json(document)
    document.a = 2
    const sealed = (await c.defaultKeyset().encrypt(wrapped)).unwrap()
    expect((await c.decrypt(sealed)).unwrap()).toEqual({ a: 1 })
    expect(String(wrapped)).toBe('Json(***)')
  })
})

describe('a ciphertext read back with a kind', () => {
  it('opens as the kind, at any integer width that holds the value', async () => {
    const c = await cipher()
    const sealed = (await c.defaultKeyset().encrypt(42n)).unwrap()
    const stored = Ciphertext.fromBytes(sealed.toBytes(), kinds.int64).unwrap()
    const opened: bigint = (await c.decrypt(stored)).unwrap()
    expect(opened).toBe(42n)
  })

  it('refuses a value sealed as another type', async () => {
    const c = await cipher()
    const sealed = (await c.defaultKeyset().encrypt('text')).unwrap()
    const stored = Ciphertext.fromBytes(sealed.toBytes(), kinds.int64).unwrap()
    const opened = await c.decrypt(stored)
    expect(opened.err()?.code).toBe('recipher_js::opened_type')
  })

  it('refuses something that is not a kind', () => {
    const bytes = new Uint8Array(4)
    // A kind is plain data, so this compiles. The addon checks the name.
    const result = Ciphertext.fromBytes(bytes, { name: 'nothing' })
    expect(result.err()?.code).toBe('recipher_js::not_a_kind')
  })

  it('takes each of `kinds`, and no other name the engine has', async () => {
    const c = await cipher()
    const bytes = (await c.defaultKeyset().encrypt('text')).unwrap().toBytes()
    for (const kind of Object.values(kinds)) {
      expect(Ciphertext.fromBytes(bytes, kind).isOk(), kind.name).toBe(true)
    }
    // The engine has these names too. No ciphertext decrypts as one, so
    // the package has no kind for it.
    const named = new Set<string>(Object.values(kinds).map((kind) => kind.name))
    for (const name of ['uuid', 'array', 'object']) {
      if (named.has(name)) continue
      const result = Ciphertext.fromBytes(bytes, { name })
      expect(result.err()?.code, name).toBe('recipher_js::not_a_kind')
    }
    expect(named.has('array') || named.has('object')).toBe(false)
  })
})

describe('refusals', () => {
  it('a UUID, which the engine does not hold yet', async () => {
    const keyset = (await cipher()).defaultKeyset()
    const uuid = new RcUuid('123e4567-e89b-12d3-a456-426614174000')
    // @ts-expect-error: a UUID is not a scalar of the engine's value model.
    const result = await keyset.encrypt(uuid)
    expect(result.err()?.code).toBe('recipher_js::uuid')
    expect(result.err()?.message).toContain('UUID')
  })

  it('a bigint outside 128 bits, with the code ERR_INTEGER_RANGE', async () => {
    const keyset = (await cipher()).defaultKeyset()
    const result = await keyset.encrypt(2n ** 128n)
    expect(result.isErr()).toBe(true)
    expect(result.err()?.code).toBe('ERR_INTEGER_RANGE')
    expect(result.err()?.message).not.toContain(String(2n ** 128n))
  })

  it('a plain object, which needs json(..)', async () => {
    const keyset = (await cipher()).defaultKeyset()
    // @ts-expect-error: a plain object is not a value.
    const result = await keyset.encrypt({ name: 'Ada' })
    expect(result.err()?.code).toBe('recipher_js::plain_object')
  })

  it('a map, a set and a class instance', async () => {
    const keyset = (await cipher()).defaultKeyset()
    for (const value of [new Map(), new Set(), new (class Thing {})()]) {
      // @ts-expect-error: none of them is a value.
      const result = await keyset.encrypt(value)
      expect(result.err()?.code).toBe('recipher_js::not_plain')
    }
  })

  it('a typed array other than a Uint8Array, at the top or in an array', async () => {
    const keyset = (await cipher()).defaultKeyset()
    // @ts-expect-error: only a Uint8Array is bytes.
    const one = await keyset.encrypt(new Uint16Array(2))
    expect(one.err()?.code).toBe('recipher_js::not_bytes')
    // @ts-expect-error: only a Uint8Array is bytes.
    const many = await keyset.encrypt(['x', new Uint16Array(2)])
    expect(many.err()?.code).toBe('recipher_js::not_bytes')
  })

  it('undefined', async () => {
    const keyset = (await cipher()).defaultKeyset()
    // @ts-expect-error: undefined is not a value.
    const result = await keyset.encrypt(undefined)
    expect(result.err()?.code).toBe('recipher_js::undefined')
  })

  it('a string with an unpaired surrogate', async () => {
    const keyset = (await cipher()).defaultKeyset()
    const result = await keyset.encrypt('\uD800')
    expect(result.err()?.code).toBe('recipher_js::unpaired_surrogate')
  })

  it('a getter that throws, without its message', async () => {
    const keyset = (await cipher()).defaultKeyset()
    const document = {
      get secret(): string {
        throw new Error('card 4111 is invalid')
      },
    }
    const result = await keyset.encrypt(json(document))
    expect(result.err()?.code).toBe('recipher_js::threw')
    expect(result.err()?.message).not.toContain('4111')
  })
})
