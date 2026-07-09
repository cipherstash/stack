import { customType } from 'drizzle-orm/pg-core'
import {
  type AnyEncryptedV3Column,
  type PlaintextForColumn,
  types as v3Types,
} from '@/eql/v3'
import { v3FromDriver, v3ToDriver } from './codec.js'

/** Every concrete `eql_v3.<domain>` string, derived from the eql/v3 factories. */
export const EQL_V3_DOMAINS: ReadonlySet<string> = new Set(
  Object.values(v3Types).map((factory) => factory('__probe__').getEqlType()),
)

const buildersByDomain: ReadonlyMap<
  string,
  (name: string) => AnyEncryptedV3Column
> = new Map(
  Object.values(v3Types).map((factory) => [
    factory('__probe__').getEqlType(),
    factory,
  ]),
)

/**
 * Drizzle copies `config.customTypeParams` from the builder into the processed
 * PgColumn. Stashing the v3 builder there keeps recovery tied to the concrete
 * column instance instead of a module-global name lookup.
 */
const EQL_V3_COLUMN_PARAM = Symbol.for('cipherstash:eqlv3Column')
const EQL_V3_COLUMN_LEGACY_PARAM = '_eqlv3Column'

type EqlV3ColumnCarrier = Record<symbol, unknown> & {
  [EQL_V3_COLUMN_LEGACY_PARAM]?: AnyEncryptedV3Column
}

function readBuilder(
  carrier: EqlV3ColumnCarrier | undefined,
): AnyEncryptedV3Column | undefined {
  return (
    (carrier?.[EQL_V3_COLUMN_PARAM] as AnyEncryptedV3Column | undefined) ??
    carrier?.[EQL_V3_COLUMN_LEGACY_PARAM]
  )
}

function writeBuilder(
  carrier: EqlV3ColumnCarrier | undefined,
  builder: AnyEncryptedV3Column,
): void {
  if (!carrier) return
  carrier[EQL_V3_COLUMN_PARAM] = builder
  carrier[EQL_V3_COLUMN_LEGACY_PARAM] = builder
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
  type TData = PlaintextForColumn<C>
  const domain = builder.getEqlType()
  const name = builder.getName()

  const column = customType<{ data: TData; driverData: string | null }>({
    dataType() {
      return domain
    },
    toDriver(value: TData): string | null {
      return v3ToDriver(value)
    },
    fromDriver(value: string | object | null | undefined): TData {
      return v3FromDriver<TData>(value)
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
