/**
 * `CodecControlHooks` for the EQL v3 string codec.
 *
 * v3 diverges from the v2 hooks factory in two ways:
 *
 *   - **`expandNativeType` is NOT identity.** A v3 column's DDL type is the
 *     per-index domain (`eql_v3.text_eq` / `text_match` / `text_ord`), derived
 *     from `typeParams.index`. The base `eql_v3.text` is narrowed here at plan
 *     time — this is what makes the column's domain CHECK enforce the chosen
 *     index capability.
 *   - **`onFieldEvent` emits NO `add_search_config`.** In v2 the search capability
 *     is wired by `eql_v2.add_search_config` rows; in v3 the domain type itself
 *     encodes the capability (applied via `expandNativeType`), so no config rows
 *     are emitted on add/drop/alter.
 */

import type { CodecControlHooks } from '@prisma-next/family-sql/control'
import { eqlV3Domain, isV3Index } from '../v3/domain-map'

const expandNativeType: NonNullable<CodecControlHooks['expandNativeType']> = ({ typeParams }) => {
  const index = typeParams?.['index']
  // Per-index domain when the column declares one (it always does); fall back to
  // the base storage domain otherwise so the hook never throws on a degenerate ctx.
  return eqlV3Domain('text', isV3Index(index) ? index : undefined)
}

export const cipherstashStringV3CodecHooks: CodecControlHooks = {
  // v3 capability is encoded by the domain type (expandNativeType), not by
  // add_search_config rows — so no field-event ops are emitted.
  onFieldEvent: () => [],
  expandNativeType,
}
