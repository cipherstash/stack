import { stripDomainSchema } from '@cipherstash/stack/adapter-kit'
import {
  type AnyEncryptedV3Column,
  types as v3Types,
} from '@cipherstash/stack/eql/v3'
import type { Encrypted } from '@cipherstash/stack/types'
import { is } from 'drizzle-orm'
import { customType, ExtraConfigColumn } from 'drizzle-orm/pg-core'
import { v3FromDriver, v3ToDriver } from './codec.js'

/** The schema the concrete `eql_v3_*` domains are created in. */
const EQL_V3_DOMAIN_SCHEMA = 'public'

/**
 * Re-attach the `public.` schema to a bare domain name, leaving an
 * already-qualified name untouched. Recovery keys (`buildersByDomain`,
 * {@link EQL_V3_DOMAINS}) are the qualified `public.eql_v3_*` identities, but a
 * live column now reports its type UNqualified (see {@link makeEqlV3Column}), so
 * the value read back off a column has to be re-qualified before it can match.
 * A name that already carries a schema (a test double, an introspected snapshot)
 * passes through unchanged.
 */
function qualifyDomain(sqlType: string): string {
  return sqlType.includes('.') ? sqlType : `${EQL_V3_DOMAIN_SCHEMA}.${sqlType}`
}

const buildersByDomain: ReadonlyMap<
  string,
  (name: string) => AnyEncryptedV3Column
> = new Map(
  Object.values(v3Types).map((factory) => [
    factory('__probe__').getEqlType(),
    factory,
  ]),
)

/** Every concrete `public.<domain>` string, derived from the eql/v3 factories. */
export const EQL_V3_DOMAINS: ReadonlySet<string> = new Set(
  buildersByDomain.keys(),
)

/**
 * Drizzle passes `config.customTypeParams` from the builder into the processed
 * PgColumn by reference — it is never cloned or serialized — so a `Symbol.for`
 * key survives the whole builder→column path. Stashing the v3 builder there
 * keeps recovery tied to the concrete column instance instead of a
 * module-global name lookup. `Symbol.for` is registry-global, so a CJS/ESM
 * duality of this module still resolves the same key.
 */
const EQL_V3_COLUMN_PARAM = Symbol.for('cipherstash:eqlv3Column')

type EqlV3ColumnCarrier = Record<symbol, unknown>

function readBuilder(
  carrier: EqlV3ColumnCarrier | undefined,
): AnyEncryptedV3Column | undefined {
  return carrier?.[EQL_V3_COLUMN_PARAM] as AnyEncryptedV3Column | undefined
}

function writeBuilder(
  carrier: EqlV3ColumnCarrier | undefined,
  builder: AnyEncryptedV3Column,
): void {
  if (!carrier) return
  carrier[EQL_V3_COLUMN_PARAM] = builder
}

function getCarrier(column: unknown): EqlV3ColumnCarrier | undefined {
  if (!column || typeof column !== 'object') return undefined

  const direct = column as EqlV3ColumnCarrier
  if (readBuilder(direct)) return direct

  const maybeWithConfig = column as {
    config?: { customTypeParams?: EqlV3ColumnCarrier }
  }
  return maybeWithConfig.config?.customTypeParams
}

function getSqlType(column: unknown): string | undefined {
  if (!column || typeof column !== 'object') return undefined

  // The extras-callback columns (`pgTable(name, cols, (t) => …)`) are
  // ExtraConfigColumn wrappers whose `getSQLType()` in drizzle-orm ≤0.45 is
  // `return this.getSQLType()` — unconditional self-recursion (upstream bug),
  // so calling it blows the stack on ANY column, encrypted or not. Recover the
  // type the way `PgCustomColumn`'s constructor does instead: the wrapper
  // shares the real column's config, so `customTypeParams.dataType()` yields
  // the same bare domain name. A non-custom column has no `customTypeParams`
  // and resolves to undefined — correctly "not an EQL column".
  if (is(column, ExtraConfigColumn)) {
    // `config` is `protected` on the class, so the read goes through a plain
    // structural view of the instance rather than the narrowed class type.
    const view: unknown = column
    const config = (
      view as {
        config?: {
          customTypeParams?: { dataType?: (fieldConfig?: unknown) => unknown }
          fieldConfig?: unknown
        }
      }
    ).config
    const viaCustomType = config?.customTypeParams?.dataType?.(
      config?.fieldConfig,
    )
    return typeof viaCustomType === 'string'
      ? qualifyDomain(viaCustomType)
      : undefined
  }

  const columnAny = column as {
    getSQLType?: () => unknown
    dataType?: unknown
    sqlName?: unknown
  }
  const sqlType =
    typeof columnAny.getSQLType === 'function'
      ? columnAny.getSQLType()
      : undefined
  // Re-qualify: a live column reports its type bare (see `makeEqlV3Column`), but
  // the recovery keys are the qualified `public.eql_v3_*` identities.
  if (typeof sqlType === 'string') return qualifyDomain(sqlType)
  const dt = columnAny.dataType
  const domain = typeof dt === 'function' ? dt() : (columnAny.sqlName ?? dt)
  return typeof domain === 'string' ? qualifyDomain(domain) : undefined
}

/**
 * Build the bare Drizzle carrier column for an EQL v3 domain.
 *
 * Split out of {@link makeEqlV3Column} for one reason: it gives the Drizzle
 * builder type a NAME (`ReturnType<typeof makeCarrierColumn>`) without this
 * module having to restate `customType`'s deeply-generic return type by hand —
 * which would silently rot the day drizzle-orm changes it.
 */
function makeCarrierColumn(sqlType: string, name: string) {
  // What is stored/inserted/selected is the ENCRYPTED EQL v3 jsonb envelope
  // (produced by `client.encrypt` / `bulkEncryptModels`), NOT the column's
  // plaintext. So `data` is the envelope type — an insert takes an already-
  // encrypted `Encrypted`, and a select yields one, ready for `decryptModel`.
  return customType<{ data: Encrypted; driverData: string | null }>({
    dataType() {
      return sqlType
    },
    toDriver(value: Encrypted): string | null {
      return v3ToDriver(value)
    },
    fromDriver(value: string | object | null | undefined): Encrypted {
      // A present jsonb value round-trips to an envelope; the driver only
      // reaches here for non-null values, so the SQL-NULL branch is a safety
      // net rather than a live path (the boundary cast covers it).
      return v3FromDriver(value) as Encrypted
    },
  })(name)
}

/**
 * Key for the phantom v3-builder carrier on {@link EqlV3Column}. Declared, never
 * defined — it exists only in the type layer. Deliberately NOT exported, so the
 * brand is unnameable (and so uncounterfeitable) outside this module while
 * staying just as inferrable through {@link V3BuilderOf}. Same trick, and the
 * same reasoning, as the core's `domainCarrier` on `EncryptedV3Column`.
 */
declare const v3BuilderCarrier: unique symbol

/** The unbranded Drizzle column {@link makeCarrierColumn} produces. */
type CarrierColumn = ReturnType<typeof makeCarrierColumn>

/**
 * A Drizzle column for the concrete v3 builder `C`, carrying `C` at the type
 * level so {@link V3BuilderOf} can recover it downstream.
 *
 * The brand rides on the builder's `_` config, NOT on the builder object type,
 * because `pgTable()` does not hand its column *builders* through to the table —
 * it rebuilds each one via drizzle's `BuildColumn`, which keeps only `_`. (The
 * surviving part is `Omit<TBuilder['_'], keyof MakeColumnConfig<…>>`, drizzle's
 * own extension point — `NotNull<T> = T & { _: { notNull: true } }` uses exactly
 * this shape.) A brand on the builder object would be dropped by `pgTable()` and
 * `extractEncryptionSchema` would have nothing left to read.
 *
 * The property is REQUIRED, not optional: an optional phantom is structurally
 * satisfied by every column, so `types.TextEq(…)` and a plain `text()` would
 * both match the recovery conditional and the non-encrypted columns could not be
 * filtered out. Nothing constructs this property at runtime — it is type-only,
 * which is why {@link makeEqlV3Column} asserts its return.
 */
export type EqlV3Column<C extends AnyEncryptedV3Column> = CarrierColumn & {
  _: { [v3BuilderCarrier]: C }
}

/**
 * `true` only for `any`. The usual idiom: `1 & T` collapses to `any` when `T` is
 * `any` (and `0 extends any` holds), and to `1`/`never`/an intersection for
 * every other `T` (where `0 extends …` does not).
 */
type IsAny<T> = 0 extends 1 & T ? true : false

/**
 * Recover the concrete v3 builder branded onto a Drizzle column (or column
 * builder) by {@link makeEqlV3Column}. Resolves to `never` for a plain,
 * non-encrypted Drizzle column — which is what lets a mapped type filter a
 * table's columns down to just the encrypted ones. The type-level mirror of
 * {@link getEqlV3Column}'s runtime recovery.
 *
 * An `any` column short-circuits to the widened `AnyEncryptedV3Column` rather
 * than falling through the conditional. A conditional type over `any` resolves
 * to the UNION of both branches with `infer C` bound to `any`, so without this
 * guard an untyped table (`const table: any`, the shape a dynamically-built
 * adapter table has) would brand every column `any` and degrade the whole
 * schema instead of landing on the widened-but-usable type it had before #589.
 */
export type V3BuilderOf<Col> =
  IsAny<Col> extends true
    ? AnyEncryptedV3Column
    : Col extends { _: { [v3BuilderCarrier]: infer C } }
      ? C extends AnyEncryptedV3Column
        ? C
        : never
      : never

export function makeEqlV3Column<C extends AnyEncryptedV3Column>(
  builder: C,
): EqlV3Column<C> {
  const domain = builder.getEqlType()
  const name = builder.getName()

  // The SQL type drizzle emits is the domain name WITHOUT its `public.` schema.
  // drizzle-kit renders a customType's `dataType()` by wrapping the whole string
  // in one pair of double quotes, so a qualified `public.eql_v3_text_search`
  // becomes the invalid identifier `"public.eql_v3_text_search"` (Postgres reads
  // it as a single type name containing a dot, not schema.type) — the DDL then
  // fails with `type "public.eql_v3_text_search" does not exist`. Emitting the
  // bare `eql_v3_text_search` yields a valid `"eql_v3_text_search"` that resolves
  // via the search_path (the domains live in `public`, always in-path), and it
  // also matches what drizzle-kit introspection reads back for a `push` diff, so
  // the two sides no longer disagree.
  //
  // Stripping the schema is only safe BECAUSE every domain lives in `public`:
  // `stripDomainSchema`/`qualifyDomain` are inverses over exactly that set. If a
  // domain ever lived elsewhere, `stripDomainSchema` would pass its qualified
  // name through untouched and drizzle-kit would emit the invalid dotted
  // identifier again — silently. Assert the invariant so that day fails loudly at
  // column construction instead of shipping a broken migration.
  if (!domain.startsWith(`${EQL_V3_DOMAIN_SCHEMA}.`)) {
    throw new Error(
      `EQL v3 domain "${domain}" is not in the "${EQL_V3_DOMAIN_SCHEMA}" schema. ` +
        'drizzle-kit cannot emit a schema-qualified custom type as valid DDL, so ' +
        'the bare domain name is emitted and resolved via search_path — which only ' +
        `works when the domain lives in "${EQL_V3_DOMAIN_SCHEMA}".`,
    )
  }
  const sqlType = stripDomainSchema(domain)

  const column = makeCarrierColumn(sqlType, name)

  writeBuilder(getCarrier(column), builder)
  writeBuilder(column as unknown as EqlV3ColumnCarrier, builder)
  // The brand is type-only — no runtime property backs it (see EqlV3Column) —
  // so the carrier column is narrowed to the branded type here. The runtime
  // carrier (`writeBuilder` above) is what `getEqlV3Column` actually reads.
  return column as EqlV3Column<C>
}

export function getEqlV3Column(
  columnName: string,
  column: unknown,
): AnyEncryptedV3Column | undefined {
  const stashed = readBuilder(getCarrier(column))
  if (stashed) return stashed

  const sqlType = getSqlType(column)
  const builderFactory = sqlType ? buildersByDomain.get(sqlType) : undefined
  return builderFactory?.(columnName)
}

export function isEqlV3Column(column: unknown): boolean {
  if (!column || typeof column !== 'object') return false
  if (readBuilder(getCarrier(column))) return true
  const sqlType = getSqlType(column)
  return typeof sqlType === 'string' && EQL_V3_DOMAINS.has(sqlType)
}
