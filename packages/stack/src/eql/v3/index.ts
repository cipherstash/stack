// Public barrel for the EQL v3 authoring DSL (`@cipherstash/stack/eql/v3`).
//
// Curated on purpose: it re-exports the `types` namespace, the concrete column
// classes (load-bearing for the `AnyEncryptedV3Column` union and nominal
// typing), the table API, and the inference type aliases. It deliberately does
// NOT re-export the per-domain literal consts (`INT4`, `TEXT_EQ`, …) — those are
// internal building blocks for `types` — and there are no standalone
// `encrypted<Domain>Column` factories any more: `types.*` is the single
// authoring API.

export type {
  AnyEncryptedV3Column,
  EncryptedV3TableColumn,
  EqlTypeForColumn,
  PlaintextForColumn,
  QueryCapabilities,
  QueryTypesForColumn,
} from './columns'

export {
  EncryptedBoolColumn,
  EncryptedDateColumn,
  EncryptedDateEqColumn,
  EncryptedDateOrdColumn,
  EncryptedDateOrdOreColumn,
  EncryptedFloat4Column,
  EncryptedFloat4EqColumn,
  EncryptedFloat4OrdColumn,
  EncryptedFloat4OrdOreColumn,
  EncryptedFloat8Column,
  EncryptedFloat8EqColumn,
  EncryptedFloat8OrdColumn,
  EncryptedFloat8OrdOreColumn,
  EncryptedInt2Column,
  EncryptedInt2EqColumn,
  EncryptedInt2OrdColumn,
  EncryptedInt2OrdOreColumn,
  EncryptedInt4Column,
  EncryptedInt4EqColumn,
  EncryptedInt4OrdColumn,
  EncryptedInt4OrdOreColumn,
  EncryptedNumericColumn,
  EncryptedNumericEqColumn,
  EncryptedNumericOrdColumn,
  EncryptedNumericOrdOreColumn,
  EncryptedTextColumn,
  EncryptedTextEqColumn,
  EncryptedTextMatchColumn,
  EncryptedTextOrdColumn,
  EncryptedTextOrdOreColumn,
  EncryptedTextSearchColumn,
  EncryptedTimestamptzColumn,
  EncryptedTimestamptzEqColumn,
  EncryptedTimestamptzOrdColumn,
  EncryptedTimestamptzOrdOreColumn,
  TEXT_SEARCH_EQL_TYPE,
} from './columns'
export type {
  AnyV3Table,
  ColumnsOf,
  InferEncrypted,
  InferPlaintext,
  QueryableColumnsOf,
  V3DecryptedModel,
  V3EncryptedModel,
  V3ModelInput,
} from './table'

export { buildEncryptConfig, EncryptedTable, encryptedTable } from './table'
export { types } from './types'
