/**
 * v3 operator lowering — equality family (`eqlEq`,
 * `eqlNeq`, `eqlIn`, `eqlNotIn`).
 *
 * The canonical v3 dialect (mirrors
 * `packages/stack-drizzle/src/v3/{operators,sql-dialect}.ts`):
 * operands are QUERY TERMS cast to the column domain's
 * `eql_v3.query_<domain>` type —
 *
 *     eql_v3.eq(<col>, $n::eql_v3.query_<domain>)
 *     eql_v3.neq(<col>, $n::eql_v3.query_<domain>)
 *
 * The cast is what reaches the bundle's `(domain, query_<domain>)`
 * overloads — the storage-domain overload's CHECK demands the
 * ciphertext `c` a query term deliberately omits. The bound param is
 * an `Encrypted*` envelope stamped with the `(table, column)` routing
 * key AND a query-term type mark (`'equality'`) so Task 7's SDK
 * boundary encrypts it via `encryptQuery` (a ciphertext-free term),
 * never the storage `bulkEncrypt` path.
 */

import { describe, expect, it } from 'vitest'
import { EncryptedString } from '../../src/execution/envelope-string'
import { EncryptedNumber } from '../../src/v3/envelope-number'
import {
  EncryptionOperatorError,
  v3QueryTermTypeOf,
} from '../../src/v3/operators-v3'
import {
  callOperator,
  columnAccessorV3,
  contractV3,
  getOperator,
  INTEGER_ORD_CODEC_ID,
  literalParamValue,
  makeV3Adapter,
  selectWithWhere,
  TABLE,
  TEXT_EQ_CODEC_ID,
  TEXT_SEARCH_CODEC_ID,
} from './operator-lowering-v3.helpers'

describe('cipherstash v3 operator lowering — eqlEq', () => {
  it('lowers nickname.eqlEq(plaintext) to eql_v3.eq(col, $1::eql_v3.query_text_eq)', () => {
    const predicate = callOperator(
      getOperator('eqlEq'),
      columnAccessorV3(TABLE, 'nickname', TEXT_EQ_CODEC_ID),
      'alice',
    )
    const lowered = makeV3Adapter().lower(selectWithWhere(predicate), {
      contract: contractV3,
    })
    expect(lowered.sql).toMatchInlineSnapshot(
      `"SELECT "user"."id" AS "id" FROM "user" WHERE eql_v3.eq("user"."nickname", $1::eql_v3.query_text_eq)"`,
    )
  })

  it('lowers email.eqlEq on a text_search column with the query_text_search cast', () => {
    const predicate = callOperator(
      getOperator('eqlEq'),
      columnAccessorV3(TABLE, 'email', TEXT_SEARCH_CODEC_ID),
      'alice@example.com',
    )
    const lowered = makeV3Adapter().lower(selectWithWhere(predicate), {
      contract: contractV3,
    })
    expect(lowered.sql).toMatchInlineSnapshot(
      `"SELECT "user"."id" AS "id" FROM "user" WHERE eql_v3.eq("user"."email", $1::eql_v3.query_text_search)"`,
    )
  })

  it('accepts equality on an OPE-ordered domain (integer_ord answers equality via its ordering term)', () => {
    const predicate = callOperator(
      getOperator('eqlEq'),
      columnAccessorV3(TABLE, 'score', INTEGER_ORD_CODEC_ID),
      42,
    )
    const lowered = makeV3Adapter().lower(selectWithWhere(predicate), {
      contract: contractV3,
    })
    expect(lowered.sql).toMatchInlineSnapshot(
      `"SELECT "user"."id" AS "id" FROM "user" WHERE eql_v3.eq("user"."score", $1::eql_v3.query_integer_ord)"`,
    )
  })

  it('binds the plaintext as an envelope stamped with the routing key and the equality query-term mark', () => {
    const predicate = callOperator(
      getOperator('eqlEq'),
      columnAccessorV3(TABLE, 'score', INTEGER_ORD_CODEC_ID),
      42,
    )
    const lowered = makeV3Adapter().lower(selectWithWhere(predicate), {
      contract: contractV3,
    })
    expect(lowered.params).toHaveLength(1)
    const envelope = literalParamValue(lowered.params[0])
    expect(envelope).toBeInstanceOf(EncryptedNumber)
    const handle = (envelope as EncryptedNumber).expose()
    expect(handle.plaintext).toBe(42)
    expect(handle.table).toBe(TABLE)
    expect(handle.column).toBe('score')
    // The seam Task 7's SDK adapter consumes: this operand must be
    // encrypted as an `encryptQuery` term (queryType 'equality'), not
    // storage-encrypted.
    expect(v3QueryTermTypeOf(envelope as EncryptedNumber)).toBe('equality')
  })

  it('passes a pre-built envelope through unchanged (advanced caller path)', () => {
    const userEnvelope = EncryptedString.from('alice')
    const predicate = callOperator(
      getOperator('eqlEq'),
      columnAccessorV3(TABLE, 'nickname', TEXT_EQ_CODEC_ID),
      userEnvelope,
    )
    const lowered = makeV3Adapter().lower(selectWithWhere(predicate), {
      contract: contractV3,
    })
    expect(literalParamValue(lowered.params[0])).toBe(userEnvelope)
    const handle = userEnvelope.expose()
    expect(handle.table).toBe(TABLE)
    expect(handle.column).toBe('nickname')
    expect(v3QueryTermTypeOf(userEnvelope)).toBe('equality')
  })

  it('rejects a plaintext that does not match the domain castAs with a specific diagnostic', () => {
    expect(() =>
      callOperator(
        getOperator('eqlEq'),
        columnAccessorV3(TABLE, 'score', INTEGER_ORD_CODEC_ID),
        'not-a-number',
      ),
    ).toThrow(EncryptionOperatorError)
    expect(() =>
      callOperator(
        getOperator('eqlEq'),
        columnAccessorV3(TABLE, 'score', INTEGER_ORD_CODEC_ID),
        'not-a-number',
      ),
    ).toThrow(/number/)
  })

  it('rejects a null operand with an isNull() hint', () => {
    expect(() =>
      callOperator(
        getOperator('eqlEq'),
        columnAccessorV3(TABLE, 'score', INTEGER_ORD_CODEC_ID),
        null,
      ),
    ).toThrow(/isNull/)
  })
})

describe('cipherstash v3 operator lowering — eqlNeq', () => {
  it('lowers to eql_v3.neq(col, $1::eql_v3.query_<domain>)', () => {
    const predicate = callOperator(
      getOperator('eqlNeq'),
      columnAccessorV3(TABLE, 'score', INTEGER_ORD_CODEC_ID),
      42,
    )
    const lowered = makeV3Adapter().lower(selectWithWhere(predicate), {
      contract: contractV3,
    })
    expect(lowered.sql).toMatchInlineSnapshot(
      `"SELECT "user"."id" AS "id" FROM "user" WHERE eql_v3.neq("user"."score", $1::eql_v3.query_integer_ord)"`,
    )
    expect(v3QueryTermTypeOf(literalParamValue(lowered.params[0]))).toBe(
      'equality',
    )
  })
})

describe('cipherstash v3 operator lowering — eqlIn / eqlNotIn', () => {
  it('lowers a single-element inArray to a one-term OR (outer parens retained)', () => {
    const predicate = callOperator(
      getOperator('eqlIn'),
      columnAccessorV3(TABLE, 'score', INTEGER_ORD_CODEC_ID),
      [1],
    )
    const lowered = makeV3Adapter().lower(selectWithWhere(predicate), {
      contract: contractV3,
    })
    expect(lowered.sql).toMatchInlineSnapshot(
      `"SELECT "user"."id" AS "id" FROM "user" WHERE (eql_v3.eq("user"."score", $1::eql_v3.query_integer_ord))"`,
    )
  })

  it('lowers a two-element inArray to an OR of eq terms, one query-term param per value', () => {
    const predicate = callOperator(
      getOperator('eqlIn'),
      columnAccessorV3(TABLE, 'score', INTEGER_ORD_CODEC_ID),
      [1, 2],
    )
    const lowered = makeV3Adapter().lower(selectWithWhere(predicate), {
      contract: contractV3,
    })
    expect(lowered.sql).toMatchInlineSnapshot(
      `"SELECT "user"."id" AS "id" FROM "user" WHERE (eql_v3.eq("user"."score", $1::eql_v3.query_integer_ord) OR eql_v3.eq("user"."score", $2::eql_v3.query_integer_ord))"`,
    )
    expect(lowered.params).toHaveLength(2)
    for (const param of lowered.params) {
      const envelope = literalParamValue(param)
      expect(envelope).toBeInstanceOf(EncryptedNumber)
      const handle = (envelope as EncryptedNumber).expose()
      expect(handle.table).toBe(TABLE)
      expect(handle.column).toBe('score')
      expect(v3QueryTermTypeOf(envelope as EncryptedNumber)).toBe('equality')
    }
  })

  it('lowers eqlNotIn to NOT-prefixed OR-of-equalities (whole disjunction negated)', () => {
    const predicate = callOperator(
      getOperator('eqlNotIn'),
      columnAccessorV3(TABLE, 'score', INTEGER_ORD_CODEC_ID),
      [1, 2],
    )
    const lowered = makeV3Adapter().lower(selectWithWhere(predicate), {
      contract: contractV3,
    })
    expect(lowered.sql).toMatchInlineSnapshot(
      `"SELECT "user"."id" AS "id" FROM "user" WHERE NOT (eql_v3.eq("user"."score", $1::eql_v3.query_integer_ord) OR eql_v3.eq("user"."score", $2::eql_v3.query_integer_ord))"`,
    )
  })

  it('rejects empty arrays with a descriptive error', () => {
    expect(() =>
      callOperator(
        getOperator('eqlIn'),
        columnAccessorV3(TABLE, 'score', INTEGER_ORD_CODEC_ID),
        [],
      ),
    ).toThrow(/empty array/)
  })

  it('rejects non-array arguments with a descriptive error', () => {
    expect(() =>
      callOperator(
        getOperator('eqlIn'),
        columnAccessorV3(TABLE, 'score', INTEGER_ORD_CODEC_ID),
        'not-an-array',
      ),
    ).toThrow(/expected an array/)
  })
})
