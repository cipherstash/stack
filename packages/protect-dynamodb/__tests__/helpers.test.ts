import { csColumn, csTable } from '@cipherstash/protect'
import { describe, expect, it } from 'vitest'
import {
  ciphertextAttrSuffix,
  searchTermAttrSuffix,
  toItemWithEqlPayloads,
} from '../src/helpers'

describe('toItemWithEqlPayloads', () => {
  it('wraps searchable JSON columns as ste_vec (k: "sv") EQL payloads', () => {
    // Regression test for `cast_as === 'json'` (previously 'jsonb'). The
    // searchableJson() builder produces cast_as: 'json' + ste_vec index, and
    // this branch must emit k: 'sv' so DynamoDB items round-trip through
    // decrypt without losing the ste_vec discriminant.
    const schema = csTable('users', {
      preferences: csColumn('preferences').searchableJson(),
    })

    const stored = [{ s: 'selector', t: 'term' }]
    const item = {
      id: 'user-1',
      [`preferences${ciphertextAttrSuffix}`]: stored,
    }

    const result = toItemWithEqlPayloads(item, schema)

    expect(result).toEqual({
      id: 'user-1',
      preferences: {
        i: { c: 'preferences', t: 'users' },
        v: 2,
        k: 'sv',
        sv: stored,
      },
    })
  })

  it('wraps non-ste_vec columns as scalar ciphertext (k: "ct") EQL payloads', () => {
    const schema = csTable('users', {
      email: csColumn('email').equality(),
    })

    const ciphertext = 'mp_base85_ciphertext'
    const item = {
      id: 'user-1',
      [`email${ciphertextAttrSuffix}`]: ciphertext,
      [`email${searchTermAttrSuffix}`]: 'hmac-value',
    }

    const result = toItemWithEqlPayloads(item, schema)

    // HMAC attribute is stripped; ciphertext is wrapped as k: 'ct'.
    expect(result).toEqual({
      id: 'user-1',
      email: {
        i: { c: 'email', t: 'users' },
        v: 2,
        k: 'ct',
        c: ciphertext,
      },
    })
  })

  it('wraps non-searchable JSON columns as scalar ciphertext (k: "ct")', () => {
    // A plain `dataType('json')` column has cast_as: 'json' but no ste_vec
    // index — it must take the default `k: 'ct'` branch, not `k: 'sv'`.
    const schema = csTable('users', {
      metadata: csColumn('metadata').dataType('json'),
    })

    const ciphertext = 'mp_base85_ciphertext'
    const item = {
      id: 'user-1',
      [`metadata${ciphertextAttrSuffix}`]: ciphertext,
    }

    const result = toItemWithEqlPayloads(item, schema)

    expect(result).toEqual({
      id: 'user-1',
      metadata: {
        i: { c: 'metadata', t: 'users' },
        v: 2,
        k: 'ct',
        c: ciphertext,
      },
    })
  })
})
