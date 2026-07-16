/**
 * TS contract factories for cipherstash-encrypted columns.
 *
 * ## v3: one factory per exposed domain
 *
 * Counterparts to the argument-less PSL constructors
 * `cipherstash.Encrypted<Stem><Suffix>()` registered in
 * `../contract-authoring`. Each factory returns the domain's concrete
 * descriptor — static codec id, `public.eql_v3_*` native type, and a static
 * `{ castAs, capabilities }` typeParams block — identical to what its PSL
 * counterpart lowers to, so PSL- and TS-authored contracts emit
 * byte-identical `contract.json`. There are NO options: the factory IS the
 * capability set (`encryptedTextSearch` vs `encryptedText`, and so on).
 *
 * ## v2: legacy `*V2` aliases
 *
 * The six pre-rename factories (`encryptedStringV2`, `encryptedDoubleV2`,
 * `encryptedBigIntV2`, `encryptedDateV2`, `encryptedBooleanV2`,
 * `encryptedJsonV2`) keep their previous bodies verbatim: single optional
 * options object, every search-mode flag defaulting to `true` — searchable
 * encryption is the legitimate default for an extension whose entire reason
 * for existing is to make encrypted columns queryable — and the
 * `cipherstash/*@1` codec + `eql_v2_encrypted` native type outputs. They
 * mirror the `*V2` PSL constructors' `true` defaults declared via
 * `AuthoringArgRef.default`.
 */

// `stripDomainSchema` is adapter-seam surface (`adapter-kit`), same import
// route as the Drizzle and Supabase adapters; `types` and the column union
// stay on the public authoring entry.
import { stripDomainSchema } from '@cipherstash/stack/adapter-kit'
import type { AnyEncryptedV3Column } from '@cipherstash/stack/eql/v3'
import { types } from '@cipherstash/stack/eql/v3'
import {
  CIPHERSTASH_BIGINT_CODEC_ID,
  CIPHERSTASH_BOOLEAN_CODEC_ID,
  CIPHERSTASH_DATE_CODEC_ID,
  CIPHERSTASH_DOUBLE_CODEC_ID,
  CIPHERSTASH_JSON_CODEC_ID,
  CIPHERSTASH_STRING_CODEC_ID,
  EQL_V2_ENCRYPTED_TYPE,
} from '../extension-metadata/constants'
import { toV3CodecId, type V3CastAs } from '../v3/catalog'

// ---------------------------------------------------------------------------
// v3 factories (derived from the concrete stack columns)
// ---------------------------------------------------------------------------

/**
 * Per-column literal inference via the getters, NOT `EncryptedV3Column<infer D>`:
 * the stack's bundled `.d.ts` drops the private `definition` field's type, so
 * inferring through the class widens to the constraint. The getters' declared
 * return types survive d.ts bundling (see
 * `../extension-metadata/constants-v3.ts` for the full rationale).
 */
type EqlTypeFromGetter<C> = C extends { getEqlType(): infer T extends string }
  ? T
  : never
type CapabilitiesFromGetter<C> = C extends { getQueryCapabilities(): infer T }
  ? T
  : never

type StripPublic<T extends string> = T extends `public.${infer D}` ? D : never

/**
 * Literal-preserving authoring descriptor, generic over the concrete stack
 * column `C`. `codecId`, `nativeType`, and `capabilities` are the domain's
 * LITERAL types (not `string` / `unknown`), so two domains' factories are
 * mutually non-assignable — this is the type spine (design "Type Discipline").
 * `castAs` is the one field the stack widens (`build(): ColumnSchema`), which
 * is harmless: `nativeType` already discriminates every domain. Pinned by the
 * type-level tests in `test/v3/column-types.test-d.ts`.
 */
export interface V3ColumnDescriptor<C extends AnyEncryptedV3Column> {
  readonly codecId: `cipherstash/eql-v3/${StripPublic<EqlTypeFromGetter<C>>}@1`
  readonly nativeType: EqlTypeFromGetter<C>
  readonly typeParams: {
    readonly castAs: V3CastAs
    readonly capabilities: CapabilitiesFromGetter<C>
  }
}

/**
 * Build one authoring factory from a concrete stack `types.*` factory. VALUES
 * are read from the column (`getEqlType` / `getQueryCapabilities` / `build`) —
 * nothing is hardcoded — and the codec id goes through the catalog's
 * `toV3CodecId` (registry key VERBATIM, never a name transform), while the
 * literal TYPES flow from `C`. The factory set is a typed 1:1 mirror of the
 * exposed catalog domains, which is how "derive from the catalog" and
 * "distinct static type per domain" coexist: TypeScript cannot hand distinct
 * static types to values pulled from a runtime record, so each factory names
 * its stack factory. Drift is caught by the 1:1 runtime test in
 * `test/column-types.test.ts` (exposed factory set === catalog minus
 * `*_ord_ore`) and the catalog drift tests.
 */
function v3Authored<C extends AnyEncryptedV3Column>(
  make: (name: string) => C,
): () => V3ColumnDescriptor<C> {
  const probe = make('__probe__')
  const nativeType = probe.getEqlType()
  const codecId = toV3CodecId(stripDomainSchema(nativeType))
  // Narrowing assertion, mirrors ../v3/catalog.ts: `build()` widens
  // `cast_as` in the bundled d.ts; the value is the domain's literal.
  const castAs = probe.build().cast_as as V3CastAs
  const capabilities = probe.getQueryCapabilities()
  // A FRESH descriptor per invocation: descriptors flow into caller-owned
  // contract structures, so a shared instance would let one caller's
  // mutation alter every later contract (call-order-dependent output).
  return () =>
    ({
      codecId,
      nativeType,
      typeParams: {
        castAs,
        capabilities: { ...capabilities },
      },
      // Narrowing assertion: runtime strings are the literals the getters
      // declare; `toV3CodecId` returns `string` by signature.
    }) as V3ColumnDescriptor<C>
}

// Each factory has a DISTINCT return type (V3ColumnDescriptor<EncryptedXColumn>);
// `encryptedBigIntOrd()` is not assignable to `encryptedText()` and vice-versa.
// Note the stack factory names: bigint is `types.Bigint*` (not `BigInt*`).
// text family
export const encryptedText = v3Authored(types.Text)
export const encryptedTextEq = v3Authored(types.TextEq)
export const encryptedTextOrd = v3Authored(types.TextOrd)
export const encryptedTextMatch = v3Authored(types.TextMatch)
export const encryptedTextSearch = v3Authored(types.TextSearch)
// integer
export const encryptedInteger = v3Authored(types.Integer)
export const encryptedIntegerEq = v3Authored(types.IntegerEq)
export const encryptedIntegerOrd = v3Authored(types.IntegerOrd)
// smallint
export const encryptedSmallint = v3Authored(types.Smallint)
export const encryptedSmallintEq = v3Authored(types.SmallintEq)
export const encryptedSmallintOrd = v3Authored(types.SmallintOrd)
// bigint
export const encryptedBigInt = v3Authored(types.Bigint)
export const encryptedBigIntEq = v3Authored(types.BigintEq)
export const encryptedBigIntOrd = v3Authored(types.BigintOrd)
// numeric
export const encryptedNumeric = v3Authored(types.Numeric)
export const encryptedNumericEq = v3Authored(types.NumericEq)
export const encryptedNumericOrd = v3Authored(types.NumericOrd)
// real
export const encryptedReal = v3Authored(types.Real)
export const encryptedRealEq = v3Authored(types.RealEq)
export const encryptedRealOrd = v3Authored(types.RealOrd)
// double
export const encryptedDouble = v3Authored(types.Double)
export const encryptedDoubleEq = v3Authored(types.DoubleEq)
export const encryptedDoubleOrd = v3Authored(types.DoubleOrd)
// date
export const encryptedDate = v3Authored(types.Date)
export const encryptedDateEq = v3Authored(types.DateEq)
export const encryptedDateOrd = v3Authored(types.DateOrd)
// timestamp
export const encryptedTimestamp = v3Authored(types.Timestamp)
export const encryptedTimestampEq = v3Authored(types.TimestampEq)
export const encryptedTimestampOrd = v3Authored(types.TimestampOrd)
// boolean (storage-only)
export const encryptedBoolean = v3Authored(types.Boolean)
// json (encrypted JSONB, ste_vec containment)
export const encryptedJson = v3Authored(types.Json)

// ---------------------------------------------------------------------------
// v2 legacy aliases (verbatim pre-rename bodies, now named *V2)
// ---------------------------------------------------------------------------

/**
 * Search-mode parameters for `encryptedStringV2({...})`. Every flag is
 * optional and defaults to `true` when omitted — searchable
 * encryption is the legitimate default. `orderAndRange` gives string
 * columns the same sortable / range-queryable surface the numeric +
 * date codecs already had.
 */
export interface EncryptedStringOptions {
  readonly equality?: boolean
  readonly freeTextSearch?: boolean
  readonly orderAndRange?: boolean
}

export interface EncryptedStringColumnDescriptor {
  readonly codecId: typeof CIPHERSTASH_STRING_CODEC_ID
  readonly nativeType: typeof EQL_V2_ENCRYPTED_TYPE
  readonly typeParams: {
    readonly equality: boolean
    readonly freeTextSearch: boolean
    readonly orderAndRange: boolean
  }
}

/**
 * `encryptedStringV2({ equality?, freeTextSearch?, orderAndRange? })` —
 * TS contract factory that lowers to a `ColumnTypeDescriptor` with
 * the `cipherstash/string@1` codec and the `eql_v2_encrypted`
 * Postgres native type. Each boolean flag becomes a `typeParams.*`
 * slot; all default to `true`.
 *
 * The shape matches what the PSL constructor
 * `cipherstash.EncryptedStringV2({...})` lowers to, byte-for-byte.
 */
export function encryptedStringV2(
  options: EncryptedStringOptions = {},
): EncryptedStringColumnDescriptor {
  return {
    codecId: CIPHERSTASH_STRING_CODEC_ID,
    nativeType: EQL_V2_ENCRYPTED_TYPE,
    typeParams: {
      equality: options.equality ?? true,
      freeTextSearch: options.freeTextSearch ?? true,
      orderAndRange: options.orderAndRange ?? true,
    },
  }
}

/**
 * Search-mode parameters for `encryptedDoubleV2({...})` and
 * `encryptedBigIntV2({...})`. Both flags are optional and default to
 * `true` when omitted — searchable encryption is the legitimate
 * default.
 */
export interface EncryptedNumericOptions {
  readonly equality?: boolean
  readonly orderAndRange?: boolean
}

export interface EncryptedDoubleColumnDescriptor {
  readonly codecId: typeof CIPHERSTASH_DOUBLE_CODEC_ID
  readonly nativeType: typeof EQL_V2_ENCRYPTED_TYPE
  readonly typeParams: {
    readonly equality: boolean
    readonly orderAndRange: boolean
  }
}

export interface EncryptedBigIntColumnDescriptor {
  readonly codecId: typeof CIPHERSTASH_BIGINT_CODEC_ID
  readonly nativeType: typeof EQL_V2_ENCRYPTED_TYPE
  readonly typeParams: {
    readonly equality: boolean
    readonly orderAndRange: boolean
  }
}

/**
 * `encryptedDoubleV2({ equality?, orderAndRange? })` — TS contract
 * factory that lowers to a `ColumnTypeDescriptor` with the
 * `cipherstash/double@1` codec and the `eql_v2_encrypted` Postgres
 * native type. Mirrors what
 * `cipherstash.EncryptedDoubleV2({...})` lowers to byte-for-byte.
 */
export function encryptedDoubleV2(
  options: EncryptedNumericOptions = {},
): EncryptedDoubleColumnDescriptor {
  return {
    codecId: CIPHERSTASH_DOUBLE_CODEC_ID,
    nativeType: EQL_V2_ENCRYPTED_TYPE,
    typeParams: {
      equality: options.equality ?? true,
      orderAndRange: options.orderAndRange ?? true,
    },
  }
}

/**
 * `encryptedBigIntV2({ equality?, orderAndRange? })` — TS contract
 * factory matching `cipherstash.EncryptedBigIntV2({...})`.
 */
export function encryptedBigIntV2(
  options: EncryptedNumericOptions = {},
): EncryptedBigIntColumnDescriptor {
  return {
    codecId: CIPHERSTASH_BIGINT_CODEC_ID,
    nativeType: EQL_V2_ENCRYPTED_TYPE,
    typeParams: {
      equality: options.equality ?? true,
      orderAndRange: options.orderAndRange ?? true,
    },
  }
}

/**
 * Search-mode parameters for `encryptedDateV2({...})`. Both flags are
 * optional and default to `true`.
 */
export interface EncryptedDateOptions {
  readonly equality?: boolean
  readonly orderAndRange?: boolean
}

export interface EncryptedDateColumnDescriptor {
  readonly codecId: typeof CIPHERSTASH_DATE_CODEC_ID
  readonly nativeType: typeof EQL_V2_ENCRYPTED_TYPE
  readonly typeParams: {
    readonly equality: boolean
    readonly orderAndRange: boolean
  }
}

/**
 * `encryptedDateV2({ equality?, orderAndRange? })` — TS contract factory
 * matching `cipherstash.EncryptedDateV2({...})`.
 */
export function encryptedDateV2(
  options: EncryptedDateOptions = {},
): EncryptedDateColumnDescriptor {
  return {
    codecId: CIPHERSTASH_DATE_CODEC_ID,
    nativeType: EQL_V2_ENCRYPTED_TYPE,
    typeParams: {
      equality: options.equality ?? true,
      orderAndRange: options.orderAndRange ?? true,
    },
  }
}

/**
 * Search-mode parameters for `encryptedBooleanV2({...})`. The flag is
 * optional and defaults to `true`. Booleans only support equality
 * search (no meaningful range predicate over a 2-value domain).
 */
export interface EncryptedBooleanOptions {
  readonly equality?: boolean
}

export interface EncryptedBooleanColumnDescriptor {
  readonly codecId: typeof CIPHERSTASH_BOOLEAN_CODEC_ID
  readonly nativeType: typeof EQL_V2_ENCRYPTED_TYPE
  readonly typeParams: {
    readonly equality: boolean
  }
}

/**
 * `encryptedBooleanV2({ equality? })` — TS contract factory matching
 * `cipherstash.EncryptedBooleanV2({...})`.
 */
export function encryptedBooleanV2(
  options: EncryptedBooleanOptions = {},
): EncryptedBooleanColumnDescriptor {
  return {
    codecId: CIPHERSTASH_BOOLEAN_CODEC_ID,
    nativeType: EQL_V2_ENCRYPTED_TYPE,
    typeParams: {
      equality: options.equality ?? true,
    },
  }
}

/**
 * Search-mode parameters for `encryptedJsonV2({...})`. Single flag —
 * `searchableJson` gates the entire `ste_vec` index family (containment
 * + path-extraction predicates). Defaults to `true`.
 */
export interface EncryptedJsonOptions {
  readonly searchableJson?: boolean
}

export interface EncryptedJsonColumnDescriptor {
  readonly codecId: typeof CIPHERSTASH_JSON_CODEC_ID
  readonly nativeType: typeof EQL_V2_ENCRYPTED_TYPE
  readonly typeParams: {
    readonly searchableJson: boolean
  }
}

/**
 * `encryptedJsonV2({ searchableJson? })` — TS contract factory matching
 * `cipherstash.EncryptedJsonV2({...})`.
 */
export function encryptedJsonV2(
  options: EncryptedJsonOptions = {},
): EncryptedJsonColumnDescriptor {
  return {
    codecId: CIPHERSTASH_JSON_CODEC_ID,
    nativeType: EQL_V2_ENCRYPTED_TYPE,
    typeParams: {
      searchableJson: options.searchableJson ?? true,
    },
  }
}
