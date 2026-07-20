/**
 * v3 operator lowering — encrypted-JSONB containment
 * (`eqlJsonContains`, trait `cipherstash:searchable-json`).
 *
 * Canonical dialect (mirrors `v3Dialect.containsJson` in
 * `packages/stack-drizzle/src/v3/sql-dialect.ts`): `eql_v3_json_search` has NO
 * `eql_v3.matches` overload — containment is the `@>` operator, whose
 * `(eql_v3_json_search, eql_v3.query_json)` form takes a NARROWED query term
 * (searchableJson → no ciphertext) cast to the irregular
 * `eql_v3.query_json` type:
 *
 *     <col> OPERATOR(public.@>) $n::eql_v3.query_json
 *
 * The four `eql_v3_json_search @> ?` RHS overloads mean a bare operand would
 * be ambiguous ("operator is not unique", 42725) — the explicit cast
 * is load-bearing.
 *
 * Unlike the bloom `eqlMatch`, this is EXACT jsonb containment with no false
 * positives. JSONPath equality uses the same value-selector containment
 * primitive; JSONPath ordering combines a selector hash with a scalar term.
 */

import { describe, expect, it } from 'vitest'
import { EncryptedJson } from '../../src/execution/envelope-json'
import {
  EncryptionOperatorError,
  v3QueryTermTypeOf,
} from '../../src/v3/operators-v3'
import {
  callOperator,
  columnAccessorV3,
  contractV3,
  getOperator,
  JSON_CODEC_ID,
  literalParamValue,
  makeV3Adapter,
  selectWithWhere,
  TABLE,
} from './operator-lowering-v3.helpers'

describe('cipherstash v3 operator lowering — eqlJsonContains', () => {
  it('lowers to col OPERATOR(public.@>) $1::eql_v3.query_json', () => {
    const predicate = callOperator(
      getOperator('eqlJsonContains'),
      columnAccessorV3(TABLE, 'payload', JSON_CODEC_ID),
      { role: 'admin' },
    )
    const lowered = makeV3Adapter().lower(selectWithWhere(predicate), {
      contract: contractV3,
    })
    expect(lowered.sql).toMatchInlineSnapshot(
      `"SELECT "user"."id" AS "id" FROM "user" WHERE "user"."payload" OPERATOR(public.@>) $1::eql_v3.query_json"`,
    )
  })

  it('binds the needle as an EncryptedJson envelope with the searchableJson query-term mark', () => {
    const predicate = callOperator(
      getOperator('eqlJsonContains'),
      columnAccessorV3(TABLE, 'payload', JSON_CODEC_ID),
      { role: 'admin' },
    )
    const lowered = makeV3Adapter().lower(selectWithWhere(predicate), {
      contract: contractV3,
    })
    expect(lowered.params).toHaveLength(1)
    const envelope = literalParamValue(lowered.params[0])
    expect(envelope).toBeInstanceOf(EncryptedJson)
    const handle = (envelope as EncryptedJson).expose()
    expect(handle.plaintext).toEqual({ role: 'admin' })
    expect(handle.table).toBe(TABLE)
    expect(handle.column).toBe('payload')
    expect(v3QueryTermTypeOf(envelope as EncryptedJson)).toBe('searchableJson')
  })

  it('rejects the empty-object needle (it matches every row)', () => {
    // `doc @> '{}'` holds for EVERY document (jsonb `{} ⊆ anything`) —
    // the same whole-table footgun the drizzle reference guards.
    expect(() =>
      callOperator(
        getOperator('eqlJsonContains'),
        columnAccessorV3(TABLE, 'payload', JSON_CODEC_ID),
        {},
      ),
    ).toThrow(/matches every row/)
  })

  it('rejects a null needle with an isNull() hint', () => {
    expect(() =>
      callOperator(
        getOperator('eqlJsonContains'),
        columnAccessorV3(TABLE, 'payload', JSON_CODEC_ID),
        null,
      ),
    ).toThrow(EncryptionOperatorError)
    // The hint must actually name the NULL-check alternative.
    expect(() =>
      callOperator(
        getOperator('eqlJsonContains'),
        columnAccessorV3(TABLE, 'payload', JSON_CODEC_ID),
        null,
      ),
    ).toThrow(/isNull\(\)/)
  })
})

describe('cipherstash v3 operator lowering — JSONPath selectors', () => {
  it('uses a value-selector containment needle for exact equality', () => {
    const predicate = callOperator(
      getOperator('eqlJsonPathEq'),
      columnAccessorV3(TABLE, 'payload', JSON_CODEC_ID),
      'profile.age',
      42,
    )
    const lowered = makeV3Adapter().lower(selectWithWhere(predicate), {
      contract: contractV3,
    })

    expect(lowered.sql).toContain(
      '"user"."payload" OPERATOR(public.@>) $1::eql_v3.query_json',
    )
    const envelope = literalParamValue(lowered.params[0]) as EncryptedJson
    expect(envelope.expose().plaintext).toEqual({
      path: '$.profile.age',
      value: 42,
    })
    expect(v3QueryTermTypeOf(envelope)).toBe('steVecValueSelector')
  })

  it('includes SQL NULL and absent-path rows for inequality', () => {
    const predicate = callOperator(
      getOperator('eqlJsonPathNeq'),
      columnAccessorV3(TABLE, 'payload', JSON_CODEC_ID),
      '$.profile.age',
      42,
    )
    const lowered = makeV3Adapter().lower(selectWithWhere(predicate), {
      contract: contractV3,
    })

    expect(lowered.sql).toContain(
      '("user"."payload" IS NULL OR NOT ("user"."payload" OPERATOR(public.@>) $1::eql_v3.query_json))',
    )
  })

  it('orders an extracted path entry against a ciphertext-free scalar term', () => {
    const predicate = callOperator(
      getOperator('eqlJsonPathGt'),
      columnAccessorV3(TABLE, 'payload', JSON_CODEC_ID),
      '$.profile.age',
      42,
    )
    const lowered = makeV3Adapter().lower(selectWithWhere(predicate), {
      contract: contractV3,
    })

    expect(lowered.sql).toContain(
      'eql_v3.gt(eql_v3.jsonb_path_query_first("user"."payload", $1::text), $2::eql_v3.query_double_ord)',
    )
    const selector = literalParamValue(lowered.params[0]) as EncryptedJson
    const term = literalParamValue(lowered.params[1]) as EncryptedJson
    expect(selector.expose().plaintext).toBe('$.profile.age')
    expect(term.expose().plaintext).toBe(42)
    expect(v3QueryTermTypeOf(selector)).toBe('steVecSelector')
    expect(v3QueryTermTypeOf(term)).toBe('steVecTerm')
  })

  it('uses the text ordering query domain for string leaves', () => {
    const predicate = callOperator(
      getOperator('eqlJsonPathLte'),
      columnAccessorV3(TABLE, 'payload', JSON_CODEC_ID),
      '$.profile.name',
      'zoe',
    )
    const lowered = makeV3Adapter().lower(selectWithWhere(predicate), {
      contract: contractV3,
    })
    expect(lowered.sql).toContain('$2::eql_v3.query_text_ord')
  })

  it('rejects malformed paths and non-orderable leaves before encryption', () => {
    const col = columnAccessorV3(TABLE, 'payload', JSON_CODEC_ID)
    expect(() =>
      callOperator(getOperator('eqlJsonPathEq'), col, '$.a[0]', 'x'),
    ).toThrow(/array\/wildcard syntax/)
    expect(() =>
      callOperator(getOperator('eqlJsonPathEq'), col, '$.a', { nested: true }),
    ).toThrow(/JSON scalar leaf/)
    expect(() =>
      callOperator(getOperator('eqlJsonPathGt'), col, '$.a', true),
    ).toThrow(/boolean leaf has no ordering/)
    expect(() =>
      callOperator(
        getOperator('eqlJsonPathEq'),
        col,
        '$.a',
        Number.POSITIVE_INFINITY,
      ),
    ).toThrow(/JSON supports only finite numbers/)
  })
})
