/**
 * v3 override divergence — `assertV3SchemasAgree` compares EXACT domain
 * identity (`getEqlType()` → `public.eql_v3_*`), not just cast_as +
 * index families: `integer_ord` and `integer_ord_ore` share
 * `cast_as: number` and an ordering index family, but are different
 * domains with different on-disk CHECKs, so an override swapping one
 * for the other must throw at setup.
 */

import { encryptedTable, types } from '@cipherstash/stack/eql/v3'
import { describe, expect, it } from 'vitest'
import { assertV3SchemasAgree } from '../../src/v3/from-stack-v3-validate'

describe('v3 override divergence — same cast_as, different domain', () => {
  it('rejects integer_ord vs integer_ord_ore (both cast_as number)', () => {
    const derived = encryptedTable('user', { score: types.IntegerOrd('score') })
    const override = encryptedTable('user', {
      score: types.IntegerOrdOre('score'),
    })
    expect(() => assertV3SchemasAgree(derived, override)).toThrow(/domain/)
    expect(() => assertV3SchemasAgree(derived, override)).toThrow(
      /eql_v3_integer_ord_ore/,
    )
  })

  it('rejects text_eq vs text_search (both cast_as string)', () => {
    const derived = encryptedTable('user', { email: types.TextEq('email') })
    const override = encryptedTable('user', {
      email: types.TextSearch('email'),
    })
    expect(() => assertV3SchemasAgree(derived, override)).toThrow(/domain/)
  })

  it('accepts an exact domain match', () => {
    const derived = encryptedTable('user', { score: types.IntegerOrd('score') })
    const override = encryptedTable('user', {
      score: types.IntegerOrd('score'),
    })
    expect(() => assertV3SchemasAgree(derived, override)).not.toThrow()
  })

  it('rejects a column missing from the override', () => {
    const derived = encryptedTable('user', {
      score: types.IntegerOrd('score'),
      email: types.TextEq('email'),
    })
    const override = encryptedTable('user', {
      score: types.IntegerOrd('score'),
    })
    expect(() => assertV3SchemasAgree(derived, override)).toThrow(/missing/)
  })

  it('rejects a column the contract does not declare', () => {
    const derived = encryptedTable('user', {
      score: types.IntegerOrd('score'),
    })
    const override = encryptedTable('user', {
      score: types.IntegerOrd('score'),
      email: types.TextEq('email'),
    })
    expect(() => assertV3SchemasAgree(derived, override)).toThrow(/missing/)
  })
})
