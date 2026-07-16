/**
 * v3 operator lowering — encrypted-JSONB containment
 * (`eqlJsonContains`, trait `cipherstash:searchable-json`).
 *
 * Canonical dialect (mirrors `v3Dialect.containsJson` in
 * `packages/stack-drizzle/src/v3/sql-dialect.ts`): `eql_v3_json` has NO
 * `eql_v3.contains` overload — containment is the `@>` operator, whose
 * `(eql_v3_json, eql_v3.query_jsonb)` form takes a NARROWED query term
 * (searchableJson → no ciphertext) cast to the irregular
 * `eql_v3.query_jsonb` type:
 *
 *     <col> OPERATOR(public.@>) $n::eql_v3.query_jsonb
 *
 * The four `eql_v3_json @> ?` RHS overloads mean a bare operand would
 * be ambiguous ("operator is not unique", 42725) — the explicit cast
 * is load-bearing.
 *
 * Unlike the bloom `eqlMatch`, this is EXACT jsonb containment:
 * no false positives. This is the drizzle reference's full JSON
 * operator surface (`contains`); the reference exposes neither a
 * containedBy direction nor selector querying, so neither is
 * registered here.
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
  it('lowers to col OPERATOR(public.@>) $1::eql_v3.query_jsonb', () => {
    const predicate = callOperator(
      getOperator('eqlJsonContains'),
      columnAccessorV3(TABLE, 'payload', JSON_CODEC_ID),
      { role: 'admin' },
    )
    const lowered = makeV3Adapter().lower(selectWithWhere(predicate), {
      contract: contractV3,
    })
    expect(lowered.sql).toMatchInlineSnapshot(
      `"SELECT "user"."id" AS "id" FROM "user" WHERE "user"."payload" OPERATOR(public.@>) $1::eql_v3.query_jsonb"`,
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
