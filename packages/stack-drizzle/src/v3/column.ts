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

export function makeEqlV3Column<C extends AnyEncryptedV3Column>(builder: C) {
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

  // What is stored/inserted/selected is the ENCRYPTED EQL v3 jsonb envelope
  // (produced by `client.encrypt` / `bulkEncryptModels`), NOT the column's
  // plaintext. So `data` is the envelope type — an insert takes an already-
  // encrypted `Encrypted`, and a select yields one, ready for `decryptModel`.
  const column = customType<{ data: Encrypted; driverData: string | null }>({
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

  writeBuilder(getCarrier(column), builder)
  writeBuilder(column as unknown as EqlV3ColumnCarrier, builder)
  return column
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
