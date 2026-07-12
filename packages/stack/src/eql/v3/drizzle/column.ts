import { customType } from 'drizzle-orm/pg-core'
import { type AnyEncryptedV3Column, types as v3Types } from '@/eql/v3'
import type { Encrypted } from '@/types'
import { v3FromDriver, v3ToDriver } from './codec.js'

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
  const columnAny = column as {
    getSQLType?: () => unknown
    dataType?: unknown
    sqlName?: unknown
  }
  const sqlType =
    typeof columnAny.getSQLType === 'function'
      ? columnAny.getSQLType()
      : undefined
  if (typeof sqlType === 'string') return sqlType
  const dt = columnAny.dataType
  const domain = typeof dt === 'function' ? dt() : (columnAny.sqlName ?? dt)
  return typeof domain === 'string' ? domain : undefined
}

export function makeEqlV3Column<C extends AnyEncryptedV3Column>(builder: C) {
  const domain = builder.getEqlType()
  const name = builder.getName()

  // What is stored/inserted/selected is the ENCRYPTED EQL v3 jsonb envelope
  // (produced by `client.encrypt` / `bulkEncryptModels`), NOT the column's
  // plaintext. So `data` is the envelope type — an insert takes an already-
  // encrypted `Encrypted`, and a select yields one, ready for `decryptModel`.
  const column = customType<{ data: Encrypted; driverData: string | null }>({
    dataType() {
      return domain
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
