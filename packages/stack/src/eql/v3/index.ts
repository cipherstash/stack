// Public barrel for the EQL v3 authoring DSL (`@cipherstash/stack/eql/v3`).
//
// Curated on purpose: it re-exports the `types` namespace, the concrete column
// classes (load-bearing for the `AnyEncryptedV3Column` union and nominal
// typing), the table API, and the inference type aliases. It deliberately does
// NOT re-export the per-domain literal consts (`INTEGER`, `TEXT_EQ`, …) — those are
// internal building blocks for `types` — and there are no standalone
// `encrypted<Domain>Column` factories any more: `types.*` is the single
// authoring API.

export type {
  AnyEncryptedV3Column,
  EncryptedV3TableColumn,
  EqlTypeForColumn,
  JsonDocument,
  JsonValue,
  PlaintextForColumn,
  QueryCapabilities,
  QueryTypesForColumn,
} from './columns'

export {
  EncryptedBigintColumn,
  EncryptedBigintEqColumn,
  EncryptedBigintOrdColumn,
  EncryptedBigintOrdOreColumn,
  EncryptedBooleanColumn,
  EncryptedDateColumn,
  EncryptedDateEqColumn,
  EncryptedDateOrdColumn,
  EncryptedDateOrdOreColumn,
  EncryptedDoubleColumn,
  EncryptedDoubleEqColumn,
  EncryptedDoubleOrdColumn,
  EncryptedDoubleOrdOreColumn,
  EncryptedIntegerColumn,
  EncryptedIntegerEqColumn,
  EncryptedIntegerOrdColumn,
  EncryptedIntegerOrdOreColumn,
  EncryptedJsonColumn,
  EncryptedNumericColumn,
  EncryptedNumericEqColumn,
  EncryptedNumericOrdColumn,
  EncryptedNumericOrdOreColumn,
  EncryptedRealColumn,
  EncryptedRealEqColumn,
  EncryptedRealOrdColumn,
  EncryptedRealOrdOreColumn,
  EncryptedSmallintColumn,
  EncryptedSmallintEqColumn,
  EncryptedSmallintOrdColumn,
  EncryptedSmallintOrdOreColumn,
  EncryptedTextColumn,
  EncryptedTextEqColumn,
  EncryptedTextMatchColumn,
  EncryptedTextOrdColumn,
  EncryptedTextOrdOreColumn,
  EncryptedTextSearchColumn,
  EncryptedTimestampColumn,
  EncryptedTimestampEqColumn,
  EncryptedTimestampOrdColumn,
  EncryptedTimestampOrdOreColumn,
  TEXT_SEARCH_EQL_TYPE,
} from './columns'
export {
  DOMAIN_REGISTRY,
  factoryForDomain,
  stripDomainSchema,
  type V3ColumnFactory,
} from './domain-registry'
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
