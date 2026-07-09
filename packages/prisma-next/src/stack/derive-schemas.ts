/**
 * Derive `@cipherstash/stack` encryption schemas from a Prisma Next
 * contract.
 *
 * `contract.json` already declares every encrypted column the
 * framework knows about — its physical table name (after `@map(...)`
 * collapsing), its physical column name, its codec id
 * (`cipherstash/<type>@1`), and its per-flag search-mode `typeParams`.
 * `deriveStackSchemas` walks the tables of every `storage.namespaces`
 * entry and returns one
 * `EncryptedTable` per table with at least one cipherstash-codec'd
 * column, ready to pass to `Encryption({ schemas })`. Skipping the
 * hand-written second declaration removes a runtime-correctness
 * footgun where the SDK's index set silently disagrees with the EQL
 * bundle's installed configuration.
 */

import {
  type EncryptedColumn,
  type EncryptedTable,
  type EncryptedTableColumn,
  encryptedColumn,
  encryptedTable,
} from '@cipherstash/stack/schema'

import {
  CIPHERSTASH_BIGINT_CODEC_ID,
  CIPHERSTASH_BOOLEAN_CODEC_ID,
  CIPHERSTASH_DATE_CODEC_ID,
  CIPHERSTASH_DOUBLE_CODEC_ID,
  CIPHERSTASH_JSON_CODEC_ID,
  CIPHERSTASH_STRING_CODEC_ID,
  type CipherstashCodecId,
  isCipherstashCodecId,
} from '../extension-metadata/constants'

/**
 * Structural shape of the subset of `contract.json` this derivation
 * reads. Declared structurally (vs importing the framework type) so
 * the derivation has no `@prisma-next/*` import-edge and is callable
 * against a raw JSON-typed import.
 */
export interface ContractStorageView {
  readonly storage?: {
    readonly namespaces?: Readonly<
      Record<
        string,
        {
          readonly tables?: Readonly<Record<string, StorageTableView>>
        }
      >
    >
  }
}

interface StorageTableView {
  readonly columns?: Readonly<Record<string, StorageColumnView>>
}

interface StorageColumnView {
  readonly codecId?: string | null
  readonly typeParams?: Readonly<Record<string, unknown>> | null
}

type DataType = 'string' | 'number' | 'bigint' | 'date' | 'boolean' | 'json'

const CODEC_ID_TO_DATA_TYPE: Readonly<Record<CipherstashCodecId, DataType>> = {
  [CIPHERSTASH_STRING_CODEC_ID]: 'string',
  [CIPHERSTASH_DOUBLE_CODEC_ID]: 'number',
  [CIPHERSTASH_BIGINT_CODEC_ID]: 'bigint',
  [CIPHERSTASH_DATE_CODEC_ID]: 'date',
  [CIPHERSTASH_BOOLEAN_CODEC_ID]: 'boolean',
  [CIPHERSTASH_JSON_CODEC_ID]: 'json',
}

// Single source of truth for the cipherstash typeParams flag set: the
// keys drive both the dispatch table in `applyTypeParams` and the
// "Known flags" line in its error message.
const FLAG_DISPATCH = {
  equality: (b: EncryptedColumn) => b.equality(),
  freeTextSearch: (b: EncryptedColumn) => b.freeTextSearch(),
  orderAndRange: (b: EncryptedColumn) => b.orderAndRange(),
  searchableJson: (b: EncryptedColumn) => b.searchableJson(),
} as const

type CipherstashFlag = keyof typeof FLAG_DISPATCH

/**
 * Derive an array of `EncryptedTable` builders from a Prisma Next
 * contract. Returns an empty array when no cipherstash columns are
 * present; callers must still pass at least one `EncryptedTable` to
 * `Encryption({ schemas })`, which requires a non-empty array.
 */
export function deriveStackSchemas(
  contractJson: ContractStorageView,
): ReadonlyArray<EncryptedTable<EncryptedTableColumn>> {
  const namespaces = contractJson.storage?.namespaces
  if (!namespaces) return []
  const tables: Record<string, StorageTableView> = {}
  for (const namespace of Object.values(namespaces)) {
    Object.assign(tables, namespace.tables)
  }

  const result: EncryptedTable<EncryptedTableColumn>[] = []

  for (const [tableName, table] of Object.entries(tables)) {
    const columns = table.columns
    if (!columns) continue

    const builders: Record<string, EncryptedColumn> = {}
    for (const [columnName, column] of Object.entries(columns)) {
      const codecId = column.codecId
      if (codecId == null || !isCipherstashCodecId(codecId)) continue

      const dataType = CODEC_ID_TO_DATA_TYPE[codecId]
      builders[columnName] = applyTypeParams(
        encryptedColumn(columnName).dataType(dataType),
        column.typeParams ?? {},
        tableName,
        columnName,
      )
    }

    if (Object.keys(builders).length === 0) continue
    result.push(encryptedTable(tableName, builders))
  }

  return result
}

function applyTypeParams(
  builder: EncryptedColumn,
  typeParams: Readonly<Record<string, unknown>>,
  tableName: string,
  columnName: string,
): EncryptedColumn {
  let result = builder
  for (const [flag, value] of Object.entries(typeParams)) {
    if (value !== true) continue
    if (!isCipherstashFlag(flag)) {
      throw new Error(
        `deriveStackSchemas: unrecognised cipherstash typeParams flag "${flag}" ` +
          `on column "${tableName}"."${columnName}". ` +
          `Known flags: ${Object.keys(FLAG_DISPATCH).join(', ')}.`,
      )
    }
    result = FLAG_DISPATCH[flag](result)
  }
  return result
}

function isCipherstashFlag(value: string): value is CipherstashFlag {
  return value in FLAG_DISPATCH
}
