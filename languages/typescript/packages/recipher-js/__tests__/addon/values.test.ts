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

    // A timestamp of whole milliseconds opens as a Date.
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
    // The safe integer comes back as a number; the big one as a bigint.
    expect((await c.decrypt(sealed)).unwrap()).toEqual({
      big: 18446744073709551615n,
      small: 5,
    })
  })

  it('refuses a number that is an integer outside the safe range', async () => {
    const keyset = (await cipher()).defaultKeyset()
    const result = await keyset.encrypt(json({ n: 2 ** 60 }))
    expect(result.err()?.code).toBe('recipher_js::not_json')
  })

  it('refuses a value with no JSON form', async () => {
    const keyset = (await cipher()).defaultKeyset()
    // @ts-expect-error: bytes are not JSON.
    const result = await keyset.encrypt(json({ b: new Uint8Array([1]) }))
    expect(result.err()?.code).toBe('recipher_js::not_json')
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
    for (const text of ['{"constructor":1}', '{"prototype":1}']) {
      const refused = await keyset.encrypt(json(JSON.parse(text)))
      expect(refused.err()?.code).toBe('recipher_js::reserved_key')
      // A document another SDK wrote, sealed as the engine seals one: as its
      // JSON text.
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
    // A kind is plain data, so this compiles; the build checks the name.
    const result = Ciphertext.fromBytes(bytes, { name: 'nothing' })
    expect(result.err()?.code).toBe('recipher_js::not_a_kind')
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
