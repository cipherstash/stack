/**
 * Control-plane hooks for the EQL v3 codecs — a schema-stripping
 * `expandNativeType` only, NO `onFieldEvent`.
 *
 * ## Why the hook must exist
 *
 * The Postgres planner requires an `expandNativeType` hook to EXIST for
 * any column that carries `typeParams` (`expandParameterizedTypeSql` in
 * target-postgres's `planner-ddl-builders.ts` throws otherwise), and
 * every v3 column carries the static `{ castAs, capabilities }`
 * typeParams block that v3 authoring emits.
 *
 * ## Why it strips `public.` instead of the v2 identity expansion
 *
 * The v3 contract `nativeType` is the schema-qualified domain
 * (`public.eql_v3_bigint_ord`), and BOTH downstream consumers of this
 * hook want the bare name:
 *
 *   - **DDL** (`buildColumnTypeSql`): an identity return means "no
 *     expansion" and falls through to `assertSafeNativeType`, whose
 *     `/^[a-zA-Z][a-zA-Z0-9_ ]*(\[\])?$/` pattern rejects the dot. The
 *     stripped name renders `CREATE TABLE ... "x" eql_v3_bigint_ord`,
 *     which resolves to the `public` schema via the search path — the
 *     bundle creates every v3 domain in `public` by design.
 *   - **Schema verify** (`renderExpectedNativeType`): the expected type
 *     is compared against the introspected column's `udt_name`, which
 *     Postgres reports UNQUALIFIED (`eql_v3_bigint_ord`). The stripped
 *     name is exactly that spelling, so post-apply verification and
 *     re-plan diffs see the column as clean.
 *
 * ## Deliberately NO `onFieldEvent`
 *
 * v3 needs no per-column search configuration (no
 * `eql_v2.add_search_config` analogue exists — the domain itself
 * carries the index metadata), so added/dropped/altered v3 columns
 * contribute zero extra migration ops. `test/v3/migration-v3.test.ts`
 * and the example app's e2e suite pin the absence of search-config ops
 * end-to-end.
 */

import type { CodecControlHooks } from '@prisma-next/family-sql/control'
import {
  CIPHERSTASH_V3_CODEC_IDS,
  type CipherstashV3CodecId,
} from '../extension-metadata/constants-v3'

const PUBLIC_SCHEMA_PREFIX = 'public.'

const stripPublicSchema: NonNullable<CodecControlHooks['expandNativeType']> = ({
  nativeType,
}) =>
  nativeType.startsWith(PUBLIC_SCHEMA_PREFIX)
    ? nativeType.slice(PUBLIC_SCHEMA_PREFIX.length)
    : nativeType

const v3Hooks: CodecControlHooks = { expandNativeType: stripPublicSchema }

/**
 * One hooks entry per pinned v3 codec id, all sharing the
 * schema-stripping `expandNativeType`. Spread into the control
 * descriptor's `types.codecTypes.controlPlaneHooks` alongside the six
 * v2 entries.
 */
export const cipherstashV3CodecControlHooks: Readonly<
  Record<CipherstashV3CodecId, CodecControlHooks>
> = Object.fromEntries(
  CIPHERSTASH_V3_CODEC_IDS.map((codecId) => [codecId, v3Hooks]),
  // Object.fromEntries widens keys to `string`; the entries are exactly
  // the pinned `CIPHERSTASH_V3_CODEC_IDS` tuple, so the record type
  // holds by construction.
) as Record<CipherstashV3CodecId, CodecControlHooks>
