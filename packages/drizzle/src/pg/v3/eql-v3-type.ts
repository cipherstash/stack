import { customType } from 'drizzle-orm/pg-core'
import { type EncryptedColumnConfig, registerColumnConfig } from '../index.js'
import { v3FromDriver, v3ToDriver } from './codec.js'
import {
  type V3DataType,
  type V3Index,
  eqlV3Domain,
  v3CastAs,
} from './domain-map.js'

export type EqlV3Config = {
  /** Only 'text' in this milestone. */
  dataType: V3DataType
  /** Omit for a storage-only column. One capability per column. */
  index?: V3Index
}

/**
 * Single-capability EQL v3 encrypted column. dataType() returns the v3 domain
 * string; values are plain-jsonb encoded (spec §5.1).
 */
export const eqlV3Type = <TData>(name: string, config: EqlV3Config) => {
  const domain = eqlV3Domain(config.dataType, config.index)

  const customColumnType = customType<{
    data: TData
    driverData: string | null
  }>({
    dataType() {
      return domain
    },
    // null/undefined bind as SQL NULL (see v3ToDriver) — never the JSONB null literal.
    toDriver(value: TData): string | null {
      return v3ToDriver(value)
    },
    fromDriver(value: string | null): TData {
      return v3FromDriver<TData>(value)
    },
  })

  const column = customColumnType(name)

  // Translate to the EncryptedColumnConfig flag shape the encrypt half consumes.
  // dataType is the INTERNAL CastAs ('string'), not the v3 scalar name (spec §5.1).
  const fullConfig: EncryptedColumnConfig & { name: string } = {
    name,
    dataType: v3CastAs(config.dataType),
    equality: config.index === 'equality' ? true : undefined,
    freeTextSearch: config.index === 'freeTextSearch' ? true : undefined,
    orderAndRange: config.index === 'orderAndRange' ? true : undefined,
  }

  // Registered in BOTH places (mirrors the v2 encryptedType builder): the
  // module-global map is the lookup keyed by column name during extraction, while
  // `_protectConfig` rides on the column object itself so detection can read the
  // config directly before pgTable processing strips custom props / loses identity.
  registerColumnConfig(fullConfig)
  // biome-ignore lint/suspicious/noExplicitAny: Drizzle columns don't expose custom props
  ;(column as any)._protectConfig = fullConfig

  return column
}
