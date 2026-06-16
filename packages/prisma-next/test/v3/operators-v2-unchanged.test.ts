/**
 * v2-unchanged regression guard for the EQL v3 work.
 *
 * The v3 changes reshaped the operator factories (template now computed inside
 * `impl` via `dialectForCodecId`) and converted `cipherstashEq`/`cipherstashIlike`
 * from single-codec to the `cipherstash:string` trait. This file pins that the v2
 * emission on a `cipherstash/string@1` column is byte-for-byte unchanged AND that
 * v2 string-operator visibility is preserved. Complements the family-specific
 * operator-lowering-*.test.ts snapshots.
 */
import { describe, expect, it } from 'vitest'
import {
  CIPHERSTASH_STRING_CODEC_ID,
  CIPHERSTASH_TRAIT_STRING,
} from '../../src/extension-metadata/constants'
import {
  callOperator,
  columnAccessor,
  contract,
  getOperator,
  makeAdapter,
  selectWithWhere,
  TABLE,
  COLUMN,
} from '../operator-lowering.helpers'

function lowerV2(method: string, ...args: unknown[]): string {
  const predicate = callOperator(getOperator(method), columnAccessor(TABLE, COLUMN, CIPHERSTASH_STRING_CODEC_ID), ...args)
  return makeAdapter().lower(selectWithWhere(predicate), { contract }).sql
}

const WHERE = `SELECT "user"."id" AS "id" FROM "user" WHERE `

describe('v2 string-column operator emission is byte-for-byte unchanged', () => {
  it('cipherstashEq', () => {
    expect(lowerV2('cipherstashEq', 'x')).toBe(`${WHERE}eql_v2.eq("user"."email", $1::eql_v2_encrypted)`)
  })
  it('cipherstashNe', () => {
    expect(lowerV2('cipherstashNe', 'x')).toBe(`${WHERE}NOT eql_v2.eq("user"."email", $1::eql_v2_encrypted)`)
  })
  it('cipherstashIlike', () => {
    expect(lowerV2('cipherstashIlike', '%x%')).toBe(`${WHERE}eql_v2.ilike("user"."email", $1::eql_v2_encrypted)`)
  })
  it('cipherstashNotIlike', () => {
    expect(lowerV2('cipherstashNotIlike', '%x%')).toBe(`${WHERE}NOT eql_v2.ilike("user"."email", $1::eql_v2_encrypted)`)
  })
  it('cipherstashGt / Gte / Lt / Lte', () => {
    expect(lowerV2('cipherstashGt', 'x')).toBe(`${WHERE}eql_v2.gt("user"."email", $1::eql_v2_encrypted)`)
    expect(lowerV2('cipherstashGte', 'x')).toBe(`${WHERE}eql_v2.gte("user"."email", $1::eql_v2_encrypted)`)
    expect(lowerV2('cipherstashLt', 'x')).toBe(`${WHERE}eql_v2.lt("user"."email", $1::eql_v2_encrypted)`)
    expect(lowerV2('cipherstashLte', 'x')).toBe(`${WHERE}eql_v2.lte("user"."email", $1::eql_v2_encrypted)`)
  })
  it('cipherstashBetween / NotBetween', () => {
    expect(lowerV2('cipherstashBetween', 'a', 'b')).toBe(
      `${WHERE}eql_v2.gte("user"."email", $1::eql_v2_encrypted) AND eql_v2.lte("user"."email", $2::eql_v2_encrypted)`,
    )
    expect(lowerV2('cipherstashNotBetween', 'a', 'b')).toBe(
      `${WHERE}NOT (eql_v2.gte("user"."email", $1::eql_v2_encrypted) AND eql_v2.lte("user"."email", $2::eql_v2_encrypted))`,
    )
  })
  it('cipherstashInArray / NotInArray', () => {
    expect(lowerV2('cipherstashInArray', ['a', 'b'])).toBe(
      `${WHERE}(eql_v2.eq("user"."email", $1::eql_v2_encrypted) OR eql_v2.eq("user"."email", $2::eql_v2_encrypted))`,
    )
    expect(lowerV2('cipherstashNotInArray', ['a', 'b'])).toBe(
      `${WHERE}NOT (eql_v2.eq("user"."email", $1::eql_v2_encrypted) OR eql_v2.eq("user"."email", $2::eql_v2_encrypted))`,
    )
  })
})

describe('v2 operator registry self-shapes (visibility preserved)', () => {
  it('cipherstashEq / cipherstashIlike dispatch on the cipherstash:string trait (both string codecs only)', () => {
    expect(getOperator('cipherstashEq').self).toEqual({ traits: [CIPHERSTASH_TRAIT_STRING] })
    expect(getOperator('cipherstashIlike').self).toEqual({ traits: [CIPHERSTASH_TRAIT_STRING] })
  })
  it('trait-based operators keep their single v2 traits', () => {
    expect(getOperator('cipherstashNe').self).toEqual({ traits: ['cipherstash:equality'] })
    expect(getOperator('cipherstashGt').self).toEqual({ traits: ['cipherstash:order-and-range'] })
    expect(getOperator('cipherstashNotIlike').self).toEqual({ traits: ['cipherstash:free-text-search'] })
    expect(getOperator('cipherstashJsonbPathExists').self).toEqual({ traits: ['cipherstash:searchable-json'] })
  })
})
