/**
 * Type-level drift guards for the EQL v3 entries in
 * `src/types/codec-types.ts`.
 *
 * The v3 block of the `CodecTypes` table is hand-written (same
 * rationale as the v2 block: the literal `cipherstash:*` trait strings
 * must survive, which `ExtractCodecTypes` would collapse). These
 * assertions keep it honest against the pinned codec-id union and the
 * per-domain capability tiers:
 *
 *   1. Every pinned `CipherstashV3CodecId` has a `CodecTypes` entry,
 *      and (2) no `cipherstash/eql-v3/...` entry exists outside the
 *      pinned union — the table and the catalog can only drift
 *      together, and `constants-v3.ts` already locks the catalog.
 *   3. Spot-pins for each capability tier: output envelope class and
 *      the exact type-level trait union (shared strings + `v3-*`
 *      markers) for a representative domain per tier.
 *
 * AGENTS.md permits `@ts-expect-error` exclusively in negative
 * type-test files; this is one of them.
 */

import { describe, expectTypeOf, it } from 'vitest'
import type { EncryptedBigInt } from '../../src/execution/envelope-bigint'
import type { EncryptedBoolean } from '../../src/execution/envelope-boolean'
import type { EncryptedJson } from '../../src/execution/envelope-json'
import type { EncryptedString } from '../../src/execution/envelope-string'
import type { CipherstashV3CodecId } from '../../src/extension-metadata/constants-v3'
import type { CodecTypes } from '../../src/types/codec-types'
import type { EncryptedNumber } from '../../src/v3/envelope-number'

// -- 1. Every pinned v3 codec id has a CodecTypes entry ----------------------

type MissingFromCodecTypes = Exclude<CipherstashV3CodecId, keyof CodecTypes>
type _AllPinnedIdsCovered = [MissingFromCodecTypes] extends [never]
  ? true
  : ['CodecTypes is missing v3 entries', MissingFromCodecTypes]
const _allPinnedIdsCovered: _AllPinnedIdsCovered = true
void _allPinnedIdsCovered

// -- 2. No v3-shaped CodecTypes key outside the pinned union -----------------

type V3ShapedKeys = Extract<keyof CodecTypes, `cipherstash/eql-v3/${string}`>
type UnpinnedEntries = Exclude<V3ShapedKeys, CipherstashV3CodecId>
type _NoUnpinnedEntries = [UnpinnedEntries] extends [never]
  ? true
  : ['CodecTypes has v3 entries the pinned union does not', UnpinnedEntries]
const _noUnpinnedEntries: _NoUnpinnedEntries = true
void _noUnpinnedEntries

// -- 3. Per-tier spot pins ----------------------------------------------------

describe('v3 CodecTypes entries', () => {
  it('storage-only domains carry no type-level traits', () => {
    expectTypeOf<
      CodecTypes['cipherstash/eql-v3/eql_v3_boolean@1']['traits']
    >().toEqualTypeOf<never>()
    expectTypeOf<
      CodecTypes['cipherstash/eql-v3/eql_v3_boolean@1']['output']
    >().toEqualTypeOf<EncryptedBoolean>()
    expectTypeOf<
      CodecTypes['cipherstash/eql-v3/eql_v3_text@1']['traits']
    >().toEqualTypeOf<never>()
  })

  it('_eq domains carry equality + the v3-equality marker', () => {
    expectTypeOf<
      CodecTypes['cipherstash/eql-v3/eql_v3_bigint_eq@1']['traits']
    >().toEqualTypeOf<'cipherstash:equality' | 'cipherstash:v3-equality'>()
    expectTypeOf<
      CodecTypes['cipherstash/eql-v3/eql_v3_bigint_eq@1']['output']
    >().toEqualTypeOf<EncryptedBigInt>()
  })

  it('_ord domains add order-and-range', () => {
    expectTypeOf<
      CodecTypes['cipherstash/eql-v3/eql_v3_double_ord@1']['traits']
    >().toEqualTypeOf<
      | 'cipherstash:equality'
      | 'cipherstash:v3-equality'
      | 'cipherstash:order-and-range'
    >()
    // v3 `number`-castAs domains decode to EncryptedNumber, NOT the v2
    // EncryptedDouble.
    expectTypeOf<
      CodecTypes['cipherstash/eql-v3/eql_v3_double_ord@1']['output']
    >().toEqualTypeOf<EncryptedNumber>()
  })

  it('text_match carries only the free-text pair', () => {
    expectTypeOf<
      CodecTypes['cipherstash/eql-v3/eql_v3_text_match@1']['traits']
    >().toEqualTypeOf<
      'cipherstash:free-text-search' | 'cipherstash:v3-free-text-search'
    >()
  })

  it('text_search carries the full scalar tier', () => {
    expectTypeOf<
      CodecTypes['cipherstash/eql-v3/eql_v3_text_search@1']['traits']
    >().toEqualTypeOf<
      | 'cipherstash:equality'
      | 'cipherstash:v3-equality'
      | 'cipherstash:order-and-range'
      | 'cipherstash:free-text-search'
      | 'cipherstash:v3-free-text-search'
    >()
    expectTypeOf<
      CodecTypes['cipherstash/eql-v3/eql_v3_text_search@1']['output']
    >().toEqualTypeOf<EncryptedString>()
  })

  it('json carries ONLY the v3-searchable-json marker (v2 jsonb-path methods must not surface)', () => {
    expectTypeOf<
      CodecTypes['cipherstash/eql-v3/eql_v3_json@1']['traits']
    >().toEqualTypeOf<'cipherstash:v3-searchable-json'>()
    expectTypeOf<
      CodecTypes['cipherstash/eql-v3/eql_v3_json@1']['output']
    >().toEqualTypeOf<EncryptedJson>()
  })
})
