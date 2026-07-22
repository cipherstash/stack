/**
 * Characterisation tests for the pure DynamoDB attribute-mapping helpers.
 *
 * These pin the CURRENT (EQL v2) behaviour of `toEncryptedDynamoItem` and
 * `toItemWithEqlPayloads` before the EQL v3 port (#657). They need no
 * credentials and make no network calls — every assertion is about the shape
 * of the attribute map on the way into and out of DynamoDB.
 *
 * Read them as a specification of the storage format:
 *   `<attr>` (an EQL payload) <-> `<attr>__source` (+ `<attr>__hmac`)
 */
import { describe, expect, it } from 'vitest'
import {
  ciphertextAttrSuffix,
  deepClone,
  EncryptedDynamoDBErrorImpl,
  handleError,
  searchTermAttrSuffix,
  toEncryptedDynamoItem,
  toItemWithEqlPayloads,
} from '@/dynamodb/helpers'
import { encryptedColumn, encryptedField, encryptedTable } from '@/schema'

const users = encryptedTable('users', {
  email: encryptedColumn('email').equality(),
  name: encryptedColumn('name'),
  blob: encryptedColumn('blob').dataType('json'),
  example: {
    protected: encryptedField('example.protected'),
  },
})

const encryptedAttrs = Object.keys(users.build().columns)

/** A minimal v2 scalar-ciphertext payload as the FFI returns it. */
const ct = (c: string, hm?: string) => ({
  k: 'ct' as const,
  v: 2,
  i: { t: 'users', c: 'email' },
  c,
  ...(hm ? { hm } : {}),
})

describe('attribute suffixes', () => {
  it('are the documented DynamoDB naming convention', () => {
    expect(ciphertextAttrSuffix).toBe('__source')
    expect(searchTermAttrSuffix).toBe('__hmac')
  })
})

describe('toEncryptedDynamoItem (write path)', () => {
  it('splits a ciphertext payload with an HMAC into __source and __hmac', () => {
    const result = toEncryptedDynamoItem(
      { pk: 'user#1', email: ct('ciphertext', 'hmac-value') },
      encryptedAttrs,
    )

    expect(result).toEqual({
      pk: 'user#1',
      email__source: 'ciphertext',
      email__hmac: 'hmac-value',
    })
    // The original attribute name is consumed, not retained alongside.
    expect(result).not.toHaveProperty('email')
  })

  it('emits only __source when the payload carries no HMAC', () => {
    const result = toEncryptedDynamoItem(
      { name: { ...ct('ciphertext'), i: { t: 'users', c: 'name' } } },
      encryptedAttrs,
    )

    expect(result).toEqual({ name__source: 'ciphertext' })
    expect(result).not.toHaveProperty(`name${searchTermAttrSuffix}`)
  })

  it('passes attributes absent from the schema through untouched', () => {
    const item = {
      pk: 'user#1',
      role: 'admin',
      count: 42,
      flag: true,
      tags: ['a', 'b'],
    }

    expect(toEncryptedDynamoItem(item, encryptedAttrs)).toEqual(item)
  })

  it('preserves null and undefined without adding suffixed attributes', () => {
    const result = toEncryptedDynamoItem(
      { email: null, name: undefined },
      encryptedAttrs,
    )

    expect(result).toEqual({ email: null, name: undefined })
  })

  it('recurses into nested objects and splits payloads found inside', () => {
    const result = toEncryptedDynamoItem(
      {
        example: {
          protected: { ...ct('nested-ct'), i: { t: 'users', c: 'protected' } },
          notProtected: 'plaintext',
        },
      },
      encryptedAttrs,
    )

    expect(result).toEqual({
      example: {
        protected__source: 'nested-ct',
        notProtected: 'plaintext',
      },
    })
  })

  it('leaves arrays untouched rather than recursing into them', () => {
    const result = toEncryptedDynamoItem(
      { items: [{ c: 'looks-like-a-payload' }] },
      encryptedAttrs,
    )

    expect(result).toEqual({ items: [{ c: 'looks-like-a-payload' }] })
  })

  it('leaves a real v2 payload inside an array whole and round-trips it', () => {
    // The array carve-out with a genuine `v+i+c` payload (the case above uses a
    // `{ c }` lookalike the detector skips anyway): stored whole, not split, and
    // symmetrically passed through on read so it still decrypts.
    const item = { tags: [ct('array-ct', 'array-hmac')] }

    const stored = toEncryptedDynamoItem(item, encryptedAttrs)
    expect(stored).toEqual(item)
    expect(stored).not.toHaveProperty('tags__source')
    expect(toItemWithEqlPayloads(stored, users)).toEqual(item)
  })

  it('does not split a nested payload whose leaf names no declared v2 column', () => {
    // The v2 branch carries the bare-leaf fallback; its POSITIVE case is tested
    // above. The negative — a nested leaf that is NOT a declared column must be
    // left whole (the read path rebuilds only declared columns, so a split here
    // would be unrecoverable). Only the v3 branch (no fallback) covered this.
    const item = { profile: { secret: ct('CT', 'H') } }

    const stored = toEncryptedDynamoItem(item, encryptedAttrs)
    expect(stored).toEqual(item)
    expect(toItemWithEqlPayloads(stored, users)).toEqual(item)
  })
})

describe('toItemWithEqlPayloads (read path)', () => {
  it('rebuilds a v2 scalar ciphertext envelope from __source', () => {
    const result = toItemWithEqlPayloads(
      { pk: 'user#1', email__source: 'ciphertext' },
      users,
    )

    expect(result).toEqual({
      pk: 'user#1',
      email: {
        i: { c: 'email', t: 'users' },
        v: 2,
        k: 'ct',
        c: 'ciphertext',
      },
    })
  })

  it('drops the __hmac attribute — it is not part of the envelope', () => {
    const result = toItemWithEqlPayloads(
      { email__source: 'ciphertext', email__hmac: 'hmac-value' },
      users,
    )

    expect(Object.keys(result)).toEqual(['email'])
    expect(result.email).not.toHaveProperty('hm')
  })

  it('rebuilds a scalar envelope for a JSON column without a ste_vec index', () => {
    const result = toItemWithEqlPayloads({ blob__source: 'ciphertext' }, users)

    expect(result).toEqual({
      blob: {
        i: { c: 'blob', t: 'users' },
        v: 2,
        k: 'ct',
        c: 'ciphertext',
      },
    })
  })

  it('rebuilds nested payloads, identifying them by their registered dotted name', () => {
    const result = toItemWithEqlPayloads(
      { example: { protected__source: 'nested-ct', notProtected: 'plain' } },
      users,
    )

    expect(result).toEqual({
      example: {
        protected: {
          // The column is registered as `example.protected`, so that is what
          // the rebuilt identifier carries. This originally emitted the bare
          // leaf (`protected`), which only worked because the FFI treats `i` as
          // a detection key and never validates it against the ciphertext.
          i: { c: 'example.protected', t: 'users' },
          v: 2,
          k: 'ct',
          c: 'nested-ct',
        },
        notProtected: 'plain',
      },
    })
  })

  it('falls back to the leaf name when only the leaf is registered', () => {
    // `encryptedField('amount')` under a `details` group — the convention the
    // schema docs show — registers `amount`, not `details.amount`.
    const orders = encryptedTable('orders', {
      details: { amount: encryptedField('amount') },
    })

    const result = toItemWithEqlPayloads(
      { details: { amount__source: 'ct' } },
      orders,
    )

    expect(result).toEqual({
      details: {
        amount: { i: { c: 'amount', t: 'orders' }, v: 2, k: 'ct', c: 'ct' },
      },
    })
  })

  it('splits and drops a nested v2 grouped field __hmac via the bare-leaf fallback', () => {
    // `encryptedField('amount')` under a `details` group registers the bare
    // leaf `amount`. A nested equality payload must split to `amount__hmac` on
    // write and have it dropped on read through the v2 bare-leaf fallback — the
    // v2 twin of the v3 dotted-path __hmac coverage, which was otherwise only
    // exercised in the live suite.
    const orders = encryptedTable('orders', {
      details: { amount: encryptedField('amount') },
    })
    const attrs = Object.keys(orders.build().columns)

    const stored = toEncryptedDynamoItem(
      {
        details: {
          amount: {
            k: 'ct',
            v: 2,
            i: { t: 'orders', c: 'amount' },
            c: 'ct',
            hm: 'h',
          },
        },
      },
      attrs,
    )
    expect(stored).toEqual({
      details: { amount__source: 'ct', amount__hmac: 'h' },
    })

    expect(toItemWithEqlPayloads(stored, orders)).toEqual({
      details: {
        amount: { i: { c: 'amount', t: 'orders' }, v: 2, k: 'ct', c: 'ct' },
      },
    })
  })

  it('passes plaintext attributes and null/undefined through untouched', () => {
    const item = { pk: 'user#1', role: 'admin', a: null, b: undefined }

    expect(toItemWithEqlPayloads(item, users)).toEqual(item)
  })

  it('round-trips an item through both directions', () => {
    const payloads = {
      pk: 'user#1',
      email: ct('email-ct', 'email-hmac'),
      role: 'admin',
    }

    const stored = toEncryptedDynamoItem(payloads, encryptedAttrs)
    const rebuilt = toItemWithEqlPayloads(stored, users)

    // The HMAC is not recoverable from the rebuilt envelope: it lives only in
    // the `__hmac` attribute, which the read path deliberately discards.
    expect(rebuilt).toEqual({
      pk: 'user#1',
      email: { i: { c: 'email', t: 'users' }, v: 2, k: 'ct', c: 'email-ct' },
      role: 'admin',
    })
  })
})

describe('deepClone', () => {
  it('returns primitives unchanged', () => {
    expect(deepClone(1)).toBe(1)
    expect(deepClone('a')).toBe('a')
    expect(deepClone(null)).toBe(null)
    expect(deepClone(undefined)).toBe(undefined)
  })

  it('clones nested objects and arrays without sharing references', () => {
    const source = { a: { b: [1, { c: 2 }] } }
    const clone = deepClone(source)

    expect(clone).toEqual(source)
    expect(clone.a).not.toBe(source.a)
    expect(clone.a.b).not.toBe(source.a.b)
  })
})

describe('handleError', () => {
  it('falls back to DYNAMODB_ENCRYPTION_ERROR for a plain Error', () => {
    const error = handleError(new Error('boom'), 'encryptModel')

    expect(error).toBeInstanceOf(EncryptedDynamoDBErrorImpl)
    expect(error.name).toBe('EncryptedDynamoDBError')
    expect(error.message).toBe('boom')
    expect(error.code).toBe('DYNAMODB_ENCRYPTION_ERROR')
    expect(error.details).toEqual({ context: 'encryptModel' })
  })

  it('preserves a `code` carried on the thrown object', () => {
    const thrown = Object.assign(new Error('nope'), { code: 'UNKNOWN_COLUMN' })

    expect(handleError(thrown, 'encryptModel').code).toBe('UNKNOWN_COLUMN')
  })

  it('stringifies a non-Error throw', () => {
    expect(handleError('just a string', 'decryptModel').message).toBe(
      'just a string',
    )
  })

  it('invokes the errorHandler and logger callbacks when supplied', () => {
    const seen: unknown[] = []
    const logged: string[] = []

    const error = handleError(new Error('boom'), 'decryptModel', {
      errorHandler: (e) => seen.push(e),
      logger: { error: (message) => logged.push(message) },
    })

    expect(seen).toEqual([error])
    expect(logged).toEqual(['Error in decryptModel'])
  })
})
