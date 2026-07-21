/**
 * Pure tests for the EQL v3 attribute mapping (#657).
 *
 * The v2 equivalents live in `helpers.test.ts` and are the characterisation
 * baseline; this file asserts only what v3 changes:
 *
 *  - v3 scalars carry NO `k` discriminator, so the write path must key off the
 *    presence of a ciphertext. Gating on `k === 'ct'` (as the v2 code did)
 *    dropped every v3 scalar through to the nested-object branch and wrote it
 *    out as a raw map.
 *  - the read path synthesizes a v3 envelope (`v: 3`, no `k`) for a v3 table
 *    and a v2 one (`v: 2`, `k: 'ct'`) for a v2 table.
 *  - a v3 JSON document keeps `k: 'sv'`, which is mandatory — deserialization
 *    fails with "missing field `k`" without it.
 */
import { describe, expect, it, vi } from 'vitest'
import {
  buildReadContext,
  deepClone,
  isV3Table,
  toEncryptedDynamoItem,
  toItemWithEqlPayloads,
} from '@/dynamodb/helpers'
import { encryptedTable, types } from '@/eql/v3'
import {
  encryptedColumn,
  encryptedField,
  encryptedTable as encryptedTableV2,
} from '@/schema'
import { logger } from '@/utils/logger'

const users = encryptedTable('users', {
  email: types.TextEq('email'),
  name: types.Text('name'),
  age: types.IntegerOrd('age'),
  meta: types.Json('meta'),
})

const encryptedAttrs = Object.keys(users.build().columns)

/** A v3 scalar payload as the FFI returns it — note the absent `k`. */
const scalar = (
  column: string,
  c: string,
  terms: Record<string, unknown> = {},
) => ({
  v: 3,
  i: { t: 'users', c: column },
  c,
  ...terms,
})

describe('isV3Table', () => {
  it('recognises a v3 table by its concrete-domain columns', () => {
    expect(isV3Table(users)).toBe(true)
  })

  it('recognises a flat v2 table', () => {
    const v2 = encryptedTableV2('users', {
      email: encryptedColumn('email').equality(),
    })

    expect(isV3Table(v2)).toBe(false)
  })

  it('recognises a v2 table whose columns are nested under a group', () => {
    const v2 = encryptedTableV2('users', {
      example: { protected: encryptedField('example.protected') },
    })

    expect(isV3Table(v2)).toBe(false)
  })
})

describe('toEncryptedDynamoItem with v3 payloads', () => {
  it('splits an untagged v3 scalar into __source and __hmac', () => {
    const result = toEncryptedDynamoItem(
      {
        pk: 'user#1',
        email: scalar('email', 'ciphertext', { hm: 'hmac-value' }),
      },
      encryptedAttrs,
    )

    expect(result).toEqual({
      pk: 'user#1',
      email__source: 'ciphertext',
      email__hmac: 'hmac-value',
    })
  })

  it('stores a storage-only column with no search term', () => {
    const result = toEncryptedDynamoItem(
      { name: scalar('name', 'ciphertext') },
      encryptedAttrs,
    )

    expect(result).toEqual({ name__source: 'ciphertext' })
  })

  it('drops the ordering term of an *Ord domain — DynamoDB cannot use it', () => {
    const result = toEncryptedDynamoItem(
      { age: scalar('age', 'ciphertext', { op: 'ordering-term' }) },
      encryptedAttrs,
    )

    // Decryptable, but not orderable and not usable in a key condition.
    expect(result).toEqual({ age__source: 'ciphertext' })
    expect(result).not.toHaveProperty('age__hmac')
  })

  it('keeps the equality term of a TextSearch domain and drops the rest', () => {
    const result = toEncryptedDynamoItem(
      {
        email: scalar('email', 'ciphertext', {
          hm: 'hmac-value',
          op: 'ordering-term',
          bf: [1, 2, 3],
        }),
      },
      encryptedAttrs,
    )

    expect(result).toEqual({
      email__source: 'ciphertext',
      email__hmac: 'hmac-value',
    })
  })

  it('stores a v3 ste_vec document as its entries plus the KeyHeader', () => {
    const entries = [{ s: 'sel', c: 'ct', a: false, hm: 'h' }]
    // Only the non-reconstructable parts are stored: the `sv` entries and the
    // per-document KeyHeader `h` (protect-ffi 0.30 decrypt requires `h`). The
    // `v`/`i`/`k` envelope fields are rebuilt on read, so they are not stored.
    const result = toEncryptedDynamoItem(
      {
        meta: {
          v: 3,
          k: 'sv',
          i: { t: 'users', c: 'meta' },
          h: 'key-header',
          sv: entries,
        },
      },
      encryptedAttrs,
    )

    expect(result).toEqual({ meta__source: { h: 'key-header', sv: entries } })
  })
})

describe('toItemWithEqlPayloads for a v3 table', () => {
  it('rebuilds an untagged v3 scalar envelope', () => {
    const result = toItemWithEqlPayloads({ email__source: 'ciphertext' }, users)

    expect(result).toEqual({
      email: { i: { c: 'email', t: 'users' }, v: 3, c: 'ciphertext' },
    })
    expect(result.email).not.toHaveProperty('k')
  })

  it('rebuilds a v3 ste_vec envelope, restoring k and the KeyHeader', () => {
    // The stored __source is `{ h, sv }`; the read path rebuilds the full
    // envelope, restoring the `k` tag and the `h` KeyHeader that 0.30 decrypt
    // requires, with `i`/`v` reconstructed from the schema.
    const entries = [{ s: 'sel', c: 'ct' }]
    const result = toItemWithEqlPayloads(
      { meta__source: { h: 'key-header', sv: entries } },
      users,
    )

    expect(result).toEqual({
      meta: {
        i: { c: 'meta', t: 'users' },
        v: 3,
        k: 'sv',
        h: 'key-header',
        sv: entries,
      },
    })
  })

  it('still emits a v2 envelope for a v2 table', () => {
    const v2 = encryptedTableV2('users', {
      email: encryptedColumn('email').equality(),
    })

    expect(toItemWithEqlPayloads({ email__source: 'ct' }, v2)).toEqual({
      email: { i: { c: 'email', t: 'users' }, v: 2, k: 'ct', c: 'ct' },
    })
  })

  it('discards __hmac and passes plaintext through, as in v2', () => {
    const result = toItemWithEqlPayloads(
      { pk: 'user#1', email__source: 'ct', email__hmac: 'h', role: 'admin' },
      users,
    )

    expect(result).toEqual({
      pk: 'user#1',
      email: { i: { c: 'email', t: 'users' }, v: 3, c: 'ct' },
      role: 'admin',
    })
  })

  it('always emits both `v` and `i` — a payload missing either is returned raw', () => {
    const rebuilt = toItemWithEqlPayloads({ email__source: 'ct' }, users)
      .email as Record<string, unknown>

    // Not a cosmetic assertion: the FFI treats `v`/`i` as the "is this
    // encrypted" detection keys. A payload missing either is silently passed
    // through undecrypted rather than erroring.
    expect(rebuilt).toHaveProperty('v')
    expect(rebuilt).toHaveProperty('i')
  })

  it('round-trips a v3 item through both directions', () => {
    const stored = toEncryptedDynamoItem(
      {
        pk: 'user#1',
        email: scalar('email', 'email-ct', { hm: 'email-hmac' }),
        role: 'admin',
      },
      encryptedAttrs,
    )

    expect(toItemWithEqlPayloads(stored, users)).toEqual({
      pk: 'user#1',
      email: { i: { c: 'email', t: 'users' }, v: 3, c: 'email-ct' },
      role: 'admin',
    })
  })
})

describe('regressions found in review', () => {
  it('does not mistake a nested plaintext object with a `c` key for a payload', () => {
    // `c` is an ordinary attribute name (country, currency, count). Treating
    // it as a ciphertext rewrote the object to `<attr>__source` and DISCARDED
    // every sibling key — silent data loss on a PutCommand.
    const item = { shipping: { address: { c: 'AU', street: '1 Main St' } } }

    expect(toEncryptedDynamoItem(item, encryptedAttrs)).toEqual(item)
  })

  it('does not drop a plaintext attribute that merely ends in __hmac', () => {
    const item = { pk: 'u#1', signature__hmac: 'an app-level hmac' }

    expect(toItemWithEqlPayloads(item, users)).toEqual(item)
  })

  it('does not treat an unregistered nested __source attribute as an envelope', () => {
    const item = { grp: { unrelated__source: 'plaintext' } }

    expect(toItemWithEqlPayloads(item, users)).toEqual(item)
  })

  it('logs a debug when a *__source attribute names no declared column', () => {
    // A schema rename leaves the stored `<old>__source` orphaned; it reads back
    // as raw base64 with no error. Make the silent drop observable.
    const spy = vi.spyOn(logger, 'debug').mockImplementation(() => {})

    try {
      toItemWithEqlPayloads({ unknown__source: 'CT' }, users)

      expect(spy).toHaveBeenCalledWith(
        expect.stringContaining('unknown__source'),
      )
      expect(spy).toHaveBeenCalledWith(
        expect.stringContaining('no declared column'),
      )
    } finally {
      spy.mockRestore()
    }
  })

  it('does not rebuild a nested <leaf>__source whose leaf collides with a top-level column', () => {
    // `note` is a TOP-LEVEL column; there is no `profile.note`. A v3 table
    // registers full dotted paths, so a nested `note__source` must NOT match
    // the top-level `note` by bare leaf — doing so rewrote a plaintext sibling
    // as an envelope and handed it to the FFI as a decrypt target.
    const t = encryptedTable('t', {
      email: types.TextEq('email'),
      note: types.Text('note'),
    })
    const item = { profile: { note__source: 'plaintext, not a ciphertext' } }

    expect(toItemWithEqlPayloads(item, t)).toEqual(item)
  })

  it('still rebuilds a v3 column declared with a dotted path', () => {
    const t = encryptedTable('t', {
      'profile.ssn': types.TextEq('profile.ssn'),
    })

    expect(
      toItemWithEqlPayloads({ profile: { ssn__source: 'CT' } }, t),
    ).toEqual({
      profile: { ssn: { i: { c: 'profile.ssn', t: 't' }, v: 3, c: 'CT' } },
    })
  })

  it('round-trips a three-level dotted path', () => {
    const t = encryptedTable('t', { 'a.b.c': types.TextEq('a.b.c') })
    const stored = toEncryptedDynamoItem(
      {
        a: { b: { c: { v: 3, i: { t: 't', c: 'a.b.c' }, c: 'CT', hm: 'H' } } },
      },
      Object.keys(t.buildColumnKeyMap()),
    )

    expect(stored).toEqual({ a: { b: { c__source: 'CT', c__hmac: 'H' } } })
    expect(toItemWithEqlPayloads(stored, t)).toEqual({
      a: { b: { c: { i: { c: 'a.b.c', t: 't' }, v: 3, c: 'CT' } } },
    })
  })

  it('identifies a column by its DB name when it differs from the property', () => {
    // `emailAddress: types.TextEq('email_address')` — matching must happen on
    // the property name, identification on the DB name.
    const t = encryptedTable('t', {
      emailAddress: types.TextEq('email_address'),
    })

    const stored = toEncryptedDynamoItem(
      {
        emailAddress: {
          v: 3,
          i: { t: 't', c: 'email_address' },
          c: 'CT',
          hm: 'H',
        },
      },
      Object.keys(t.buildColumnKeyMap()),
    )
    expect(stored).toEqual({
      emailAddress__source: 'CT',
      emailAddress__hmac: 'H',
    })

    expect(toItemWithEqlPayloads(stored, t)).toEqual({
      emailAddress: { i: { c: 'email_address', t: 't' }, v: 3, c: 'CT' },
    })
  })
})

describe('read context is resolved once per batch', () => {
  it('does not call table.build() per item when a context is passed', () => {
    // `buildReadContext` resolves the row-invariant facts once; the 3-arg form
    // of `toItemWithEqlPayloads` reuses them. Dropping the 3rd arg would rebuild
    // (and re-`build()`) per item — the invariant this pins.
    const buildSpy = vi.spyOn(users, 'build')

    const context = buildReadContext(users)
    buildSpy.mockClear()

    const items = [
      { email__source: 'a' },
      { email__source: 'b' },
      { email__source: 'c' },
    ]
    for (const item of items) {
      toItemWithEqlPayloads(item, users, context)
    }

    expect(buildSpy).not.toHaveBeenCalled()

    buildSpy.mockRestore()
  })
})

describe('deepClone preserves structured values', () => {
  it('preserves Date instances — the whole Timestamp domain family depends on it', () => {
    const at = new Date('2020-01-02T03:04:05.000Z')

    expect(deepClone(at)).toBeInstanceOf(Date)
    expect(deepClone({ at }).at.getTime()).toBe(at.getTime())
  })

  it('preserves Map, Set and typed arrays', () => {
    expect(deepClone(new Map([['a', 1]])).get('a')).toBe(1)
    expect(deepClone(new Set([1, 2])).has(2)).toBe(true)
    expect(deepClone(new Uint8Array([1, 2]))).toBeInstanceOf(Uint8Array)
  })

  it('does not blow the stack on a circular reference', () => {
    const o: Record<string, unknown> = { a: 1 }
    o.self = o

    expect(() => deepClone(o)).not.toThrow()
  })

  it('never hands back the caller original when structuredClone throws', () => {
    // A function-valued property makes `structuredClone` throw. The catch must
    // still produce a NEW object — returning the original voids the docblock
    // guarantee that encryption never mutates a caller's object.
    const input = { pk: 'u#1', onSave: () => {} }

    const cloned = deepClone(input)

    expect(cloned).not.toBe(input)
    expect(cloned.pk).toBe('u#1')
  })

  it('clones a class instance into a plain object, dropping the prototype', () => {
    class Model {
      pk = 'u#1'
      // An own function property forces the structuredClone fallback.
      onSave = () => {}
    }
    const input = new Model()

    const cloned = deepClone(input)

    expect(cloned).not.toBe(input)
    expect(cloned).not.toBeInstanceOf(Model)
    expect(cloned.pk).toBe('u#1')
  })
})
