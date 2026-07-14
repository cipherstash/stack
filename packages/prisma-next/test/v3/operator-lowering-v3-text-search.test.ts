/**
 * v3 operator lowering — free-text search family (`cipherstashIlike` /
 * `cipherstashNotIlike`).
 *
 * Canonical dialect: `eql_v3.contains(<col>, $n::eql_v3.query_<domain>)`.
 * The SQL function keeps its bundle name `contains`, but the semantics
 * are a bloom-filter TOKEN MATCH, not SQL LIKE/ILIKE and not
 * containment: the needle's downcased 3-gram set is tested as a subset
 * of the haystack's — order- and multiplicity-insensitive, and
 * one-sided (a `true` may be a false positive; a `false` never is).
 * The method names stay `cipherstashIlike` / `cipherstashNotIlike` to
 * mirror the v2 operator surface (decision 1b — same method names, v3
 * descriptor only).
 */

import { describe, expect, it } from 'vitest'
import { EncryptedString } from '../../src/execution/envelope-string'
import { v3QueryTermTypeOf } from '../../src/v3/operators-v3'
import {
  callOperator,
  columnAccessorV3,
  contractV3,
  getOperator,
  literalParamValue,
  makeV3Adapter,
  selectWithWhere,
  TABLE,
  TEXT_SEARCH_CODEC_ID,
} from './operator-lowering-v3.helpers'

describe('cipherstash v3 operator lowering — cipherstashIlike', () => {
  it('lowers to eql_v3.contains(col, $1::eql_v3.query_text_search)', () => {
    const predicate = callOperator(
      getOperator('cipherstashIlike'),
      columnAccessorV3(TABLE, 'email', TEXT_SEARCH_CODEC_ID),
      'alice',
    )
    const lowered = makeV3Adapter().lower(selectWithWhere(predicate), {
      contract: contractV3,
    })
    expect(lowered.sql).toMatchInlineSnapshot(
      `"SELECT "user"."id" AS "id" FROM "user" WHERE eql_v3.contains("user"."email", $1::eql_v3.query_text_search)"`,
    )
  })

  it('binds the needle as an EncryptedString envelope with the freeTextSearch query-term mark', () => {
    const predicate = callOperator(
      getOperator('cipherstashIlike'),
      columnAccessorV3(TABLE, 'email', TEXT_SEARCH_CODEC_ID),
      'alice',
    )
    const lowered = makeV3Adapter().lower(selectWithWhere(predicate), {
      contract: contractV3,
    })
    expect(lowered.params).toHaveLength(1)
    const envelope = literalParamValue(lowered.params[0])
    expect(envelope).toBeInstanceOf(EncryptedString)
    const handle = (envelope as EncryptedString).expose()
    expect(handle.plaintext).toBe('alice')
    expect(handle.table).toBe(TABLE)
    expect(handle.column).toBe('email')
    expect(v3QueryTermTypeOf(envelope as EncryptedString)).toBe(
      'freeTextSearch',
    )
  })
})

describe('cipherstash v3 operator lowering — cipherstashNotIlike', () => {
  it('lowers to NOT eql_v3.contains(col, $1::eql_v3.query_text_search)', () => {
    const predicate = callOperator(
      getOperator('cipherstashNotIlike'),
      columnAccessorV3(TABLE, 'email', TEXT_SEARCH_CODEC_ID),
      'alice',
    )
    const lowered = makeV3Adapter().lower(selectWithWhere(predicate), {
      contract: contractV3,
    })
    expect(lowered.sql).toMatchInlineSnapshot(
      `"SELECT "user"."id" AS "id" FROM "user" WHERE NOT eql_v3.contains("user"."email", $1::eql_v3.query_text_search)"`,
    )
  })
})
