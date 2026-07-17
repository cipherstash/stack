/**
 * Derive `@cipherstash/stack/eql/v3` schemas from a Prisma Next
 * contract — the v3 twin of `../stack/derive-schemas.ts`.
 *
 * `contract.json` already declares every encrypted column the framework
 * knows about: its physical table name (after `@map(...)` collapsing),
 * its physical column name, its v3 codec id
 * (`cipherstash/eql-v3/eql_v3_*@1`), and its concrete `public.eql_v3_*`
 * domain as `nativeType`. `deriveStackSchemasV3` walks the
 * `storage.namespaces.<ns>.entries.table` envelope and returns one v3
 * `EncryptedTable` per table with at least one v3-codec'd column, ready
 * to pass to `EncryptionV3({ schemas })`.
 *
 * The v3-specific delta vs the v2 derivation: the concrete column
 * factory is selected by `nativeType` via the catalog's
 * `V3_FACTORY_BY_NATIVE_TYPE` (the `(codec id) ⟺ (public.* domain)`
 * bijection), never by `typeParams` flags — a v3 domain's capabilities
 * are intrinsic to the domain, not per-column authoring options. The
 * derived column keeps its concrete class (`EncryptedTextSearchColumn`,
 * `EncryptedIntegerOrdColumn`, …), so exact domain identity survives
 * into override validation (`assertV3SchemasAgree`).
 */

import {
  type AnyEncryptedV3Column,
  type AnyV3Table,
  encryptedTable,
} from '@cipherstash/stack/eql/v3'

import { isCipherstashV3CodecId } from '../extension-metadata/constants-v3'
import { V3_FACTORY_BY_NATIVE_TYPE } from './catalog'

interface V3ColumnView {
  readonly codecId?: string | null
  readonly nativeType?: string
  readonly typeParams?: unknown
}

interface V3TableView {
  readonly columns?: Readonly<Record<string, V3ColumnView>>
}

/**
 * Structural shape of the subset of `contract.json` this derivation
 * reads — the 0.14 `storage.namespaces.<ns>.entries.table` envelope,
 * mirroring the v2 `ContractStorageView`. Declared structurally (vs
 * importing the framework type) so the derivation has no
 * `@prisma-next/*` import-edge and is callable against a raw
 * JSON-typed import.
 */
export interface V3ContractShape {
  readonly storage?: {
    readonly namespaces?: Readonly<
      Record<
        string,
        {
          readonly entries?: {
            readonly table?: Readonly<Record<string, V3TableView>>
          }
        }
      >
    >
  }
}

function contractTables(
  contractJson: V3ContractShape,
): Record<string, V3TableView> {
  const namespaces = contractJson.storage?.namespaces
  if (!namespaces) return {}
  const tables: Record<string, V3TableView> = {}
  for (const namespace of Object.values(namespaces)) {
    Object.assign(tables, namespace.entries?.table)
  }
  return tables
}

/** One contract column, flattened out of the namespace envelope. */
export interface V3ContractColumnEntry {
  readonly tableName: string
  readonly columnName: string
  readonly codecId: string | undefined
  readonly nativeType: string | undefined
}

/**
 * Flatten every contract column across all namespaces/tables. Shared by
 * {@link deriveStackSchemasV3} and `cipherstashFromStack`'s
 * v2-codec-id scan (a v3 client is v3-only; foreign cipherstash codec
 * ids are a hard error there).
 */
export function v3ContractColumnEntries(
  contractJson: V3ContractShape,
): V3ContractColumnEntry[] {
  const entries: V3ContractColumnEntry[] = []
  for (const [tableName, table] of Object.entries(
    contractTables(contractJson),
  )) {
    for (const [columnName, column] of Object.entries(table.columns ?? {})) {
      entries.push({
        tableName,
        columnName,
        codecId: column.codecId ?? undefined,
        nativeType: column.nativeType,
      })
    }
  }
  return entries
}

/**
 * Derive an array of v3 `EncryptedTable` builders from a Prisma Next
 * contract. Returns an empty array when no v3 cipherstash columns are
 * present; callers must still pass at least one table to
 * `EncryptionV3({ schemas })`, which requires a non-empty array.
 */
export function deriveStackSchemasV3(
  contractJson: V3ContractShape,
): ReadonlyArray<AnyV3Table> {
  const result: AnyV3Table[] = []

  for (const [tableName, table] of Object.entries(
    contractTables(contractJson),
  )) {
    const columns: Record<string, AnyEncryptedV3Column> = {}
    for (const [columnName, column] of Object.entries(table.columns ?? {})) {
      const codecId = column.codecId
      if (codecId == null || !isCipherstashV3CodecId(codecId)) continue

      const nativeType = column.nativeType
      const factory =
        nativeType !== undefined
          ? V3_FACTORY_BY_NATIVE_TYPE.get(nativeType)
          : undefined
      if (!factory) {
        throw new Error(
          `deriveStackSchemasV3: column "${tableName}"."${columnName}" has v3 codec id "${codecId}" ` +
            `but nativeType "${nativeType}" maps to no eql/v3 factory. ` +
            'Re-emit the contract with a current @cipherstash/prisma-next.',
        )
      }
      columns[columnName] = factory(columnName)
    }

    if (Object.keys(columns).length === 0) continue
    result.push(encryptedTable(tableName, columns))
  }

  return result
}
