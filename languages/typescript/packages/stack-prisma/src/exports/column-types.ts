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
 * capability set (`textSearch` vs `text`, and so on).
 */

// `stripDomainSchema` is adapter-seam surface (`adapter-kit`), same import
// route as the Drizzle and Supabase adapters; `types` and the column union
// stay on the public authoring entry.
import { stripDomainSchema } from '@cipherstash/stack/adapter-kit'
import type { AnyEncryptedV3Column } from '@cipherstash/stack/eql/v3'
import { types } from '@cipherstash/stack/eql/v3'
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
// `bigIntOrd()` is not assignable to `text()` and vice-versa.
// Note the stack factory names: bigint is `types.Bigint*` (not `BigInt*`).
// text family
export const text = v3Authored(types.Text)
export const textEq = v3Authored(types.TextEq)
export const textOrd = v3Authored(types.TextOrd)
export const textMatch = v3Authored(types.TextMatch)
export const textSearch = v3Authored(types.TextSearch)
// integer
export const integer = v3Authored(types.Integer)
export const integerEq = v3Authored(types.IntegerEq)
export const integerOrd = v3Authored(types.IntegerOrd)
// smallint
export const smallint = v3Authored(types.Smallint)
export const smallintEq = v3Authored(types.SmallintEq)
export const smallintOrd = v3Authored(types.SmallintOrd)
// bigint
export const bigInt = v3Authored(types.Bigint)
export const bigIntEq = v3Authored(types.BigintEq)
export const bigIntOrd = v3Authored(types.BigintOrd)
// numeric
export const numeric = v3Authored(types.Numeric)
export const numericEq = v3Authored(types.NumericEq)
export const numericOrd = v3Authored(types.NumericOrd)
// real
export const real = v3Authored(types.Real)
export const realEq = v3Authored(types.RealEq)
export const realOrd = v3Authored(types.RealOrd)
// double
export const double = v3Authored(types.Double)
export const doubleEq = v3Authored(types.DoubleEq)
export const doubleOrd = v3Authored(types.DoubleOrd)
// date
export const date = v3Authored(types.Date)
export const dateEq = v3Authored(types.DateEq)
export const dateOrd = v3Authored(types.DateOrd)
// timestamp
export const timestamp = v3Authored(types.Timestamp)
export const timestampEq = v3Authored(types.TimestampEq)
export const timestampOrd = v3Authored(types.TimestampOrd)
// boolean (storage-only)
export const boolean = v3Authored(types.Boolean)
// json (encrypted JSONB, ste_vec containment)
export const json = v3Authored(types.Json)
