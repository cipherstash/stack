/**
 * v3 operator lowering — order/range family (`cipherstashGt` / `Gte` /
 * `Lt` / `Lte` / `Between` / `NotBetween`) plus the free-standing
 * ordering helpers (`cipherstashV3Asc` / `cipherstashV3Desc`).
 *
 * Canonical dialect (mirrors `packages/stack-drizzle/src/v3/sql-dialect.ts`):
 *
 *     eql_v3.gt(<col>, $n::eql_v3.query_<domain>)
 *     (eql_v3.gte(...) AND eql_v3.lte(...))          -- between, self-parenthesised
 *     NOT (eql_v3.gte(...) AND eql_v3.lte(...))      -- notBetween
 *     ORDER BY eql_v3.ord_term(<col>)                -- OPE `_ord` domains
 *     ORDER BY eql_v3.ord_term_ore(<col>)            -- block-ORE `_ord_ore` domains
 *
 * `between`'s parentheses are load-bearing, not cosmetic: Postgres
 * binds NOT tighter than AND, so an unparenthesised `gte AND lte`
 * under a generic negation parses as `(NOT gte) AND lte` — rows BELOW
 * the lower bound instead of the range complement.
 */

import { describe, expect, it } from 'vitest'
import { EncryptedBigInt } from '../../src/execution/envelope-bigint'
import { EncryptedNumber } from '../../src/v3/envelope-number'
import {
  cipherstashV3Asc,
  cipherstashV3Desc,
  v3QueryTermTypeOf,
} from '../../src/v3/operators-v3'
import {
  BIGINT_ORD_ORE_CODEC_ID,
  callOperator,
  columnAccessorV3,
  contractV3,
  getOperator,
  INTEGER_ORD_CODEC_ID,
  literalParamValue,
  makeV3Adapter,
  selectWithOrderBy,
  selectWithWhere,
  TABLE,
} from './operator-lowering-v3.helpers'

describe('cipherstash v3 operator lowering — comparisons', () => {
  it.each([
    ['cipherstashGt', 'gt'],
    ['cipherstashGte', 'gte'],
    ['cipherstashLt', 'lt'],
    ['cipherstashLte', 'lte'],
  ] as const)('%s lowers to eql_v3.%s(col, $1::eql_v3.query_integer_ord)', (method, fn) => {
    const predicate = callOperator(
      getOperator(method),
      columnAccessorV3(TABLE, 'score', INTEGER_ORD_CODEC_ID),
      10,
    )
    const lowered = makeV3Adapter().lower(selectWithWhere(predicate), {
      contract: contractV3,
    })
    expect(lowered.sql).toBe(
      `SELECT "user"."id" AS "id" FROM "user" WHERE eql_v3.${fn}("user"."score", $1::eql_v3.query_integer_ord)`,
    )
    const envelope = literalParamValue(lowered.params[0])
    expect(envelope).toBeInstanceOf(EncryptedNumber)
    expect(v3QueryTermTypeOf(envelope as EncryptedNumber)).toBe('orderAndRange')
  })

  it('casts to the ord_ore query domain on a block-ORE column (bigint envelope dispatch)', () => {
    const predicate = callOperator(
      getOperator('cipherstashGt'),
      columnAccessorV3(TABLE, 'balance', BIGINT_ORD_ORE_CODEC_ID),
      100n,
    )
    const lowered = makeV3Adapter().lower(selectWithWhere(predicate), {
      contract: contractV3,
    })
    expect(lowered.sql).toMatchInlineSnapshot(
      `"SELECT "user"."id" AS "id" FROM "user" WHERE eql_v3.gt("user"."balance", $1::eql_v3.query_bigint_ord_ore)"`,
    )
    expect(literalParamValue(lowered.params[0])).toBeInstanceOf(EncryptedBigInt)
  })
})

describe('cipherstash v3 operator lowering — between / notBetween', () => {
  it('cipherstashBetween is a SELF-PARENTHESISED conjunction (composition-safe)', () => {
    const predicate = callOperator(
      getOperator('cipherstashBetween'),
      columnAccessorV3(TABLE, 'score', INTEGER_ORD_CODEC_ID),
      1,
      9,
    )
    const lowered = makeV3Adapter().lower(selectWithWhere(predicate), {
      contract: contractV3,
    })
    expect(lowered.sql).toMatchInlineSnapshot(
      `"SELECT "user"."id" AS "id" FROM "user" WHERE (eql_v3.gte("user"."score", $1::eql_v3.query_integer_ord) AND eql_v3.lte("user"."score", $2::eql_v3.query_integer_ord))"`,
    )
    expect(lowered.params).toHaveLength(2)
    expect(
      (literalParamValue(lowered.params[0]) as EncryptedNumber).expose()
        .plaintext,
    ).toBe(1)
    expect(
      (literalParamValue(lowered.params[1]) as EncryptedNumber).expose()
        .plaintext,
    ).toBe(9)
  })

  it('cipherstashNotBetween wraps the WHOLE conjunction: NOT (gte AND lte)', () => {
    const predicate = callOperator(
      getOperator('cipherstashNotBetween'),
      columnAccessorV3(TABLE, 'score', INTEGER_ORD_CODEC_ID),
      1,
      9,
    )
    const lowered = makeV3Adapter().lower(selectWithWhere(predicate), {
      contract: contractV3,
    })
    expect(lowered.sql).toMatchInlineSnapshot(
      `"SELECT "user"."id" AS "id" FROM "user" WHERE NOT (eql_v3.gte("user"."score", $1::eql_v3.query_integer_ord) AND eql_v3.lte("user"."score", $2::eql_v3.query_integer_ord))"`,
    )
    // Regression guard on the `NOT gte AND lte` degradation: the NOT
    // must never bind to the gte term alone.
    expect(lowered.sql).not.toMatch(/NOT eql_v3\.gte/)
  })

  it('cipherstashBetween enforces its 2-argument arity', () => {
    expect(() =>
      callOperator(
        getOperator('cipherstashBetween'),
        columnAccessorV3(TABLE, 'score', INTEGER_ORD_CODEC_ID),
        1,
      ),
    ).toThrow(/expected 2 argument/)
  })
})

describe('cipherstash v3 ordering — cipherstashV3Asc / cipherstashV3Desc', () => {
  it('lowers ASC on an OPE `_ord` column to ORDER BY eql_v3.ord_term(col) ASC', () => {
    const item = cipherstashV3Asc(
      columnAccessorV3(TABLE, 'score', INTEGER_ORD_CODEC_ID),
    )
    const lowered = makeV3Adapter().lower(selectWithOrderBy([item]), {
      contract: contractV3,
    })
    expect(lowered.sql).toMatchInlineSnapshot(
      `"SELECT "user"."id" AS "id" FROM "user" ORDER BY eql_v3.ord_term("user"."score") ASC"`,
    )
    expect(lowered.params).toHaveLength(0)
  })

  it('lowers DESC on a block-ORE `_ord_ore` column to ORDER BY eql_v3.ord_term_ore(col) DESC', () => {
    const item = cipherstashV3Desc(
      columnAccessorV3(TABLE, 'balance', BIGINT_ORD_ORE_CODEC_ID),
    )
    const lowered = makeV3Adapter().lower(selectWithOrderBy([item]), {
      contract: contractV3,
    })
    expect(lowered.sql).toMatchInlineSnapshot(
      `"SELECT "user"."id" AS "id" FROM "user" ORDER BY eql_v3.ord_term_ore("user"."balance") DESC"`,
    )
  })
})
