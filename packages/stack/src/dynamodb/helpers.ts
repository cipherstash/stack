import type { ProtectErrorCode } from '@cipherstash/protect-ffi'
import { ProtectError as FfiProtectError } from '@cipherstash/protect-ffi'
import { resolveEncryptColumnMap } from '@/encryption/helpers/model-helpers'
import type { AnyV3Table } from '@/eql/v3'
import type { EncryptedValue } from '@/types'
import { logger } from '@/utils/logger'
import type { AnyEncryptedTable, EncryptedDynamoDBError } from './types'

export const ciphertextAttrSuffix = '__source'
export const searchTermAttrSuffix = '__hmac'

/**
 * Which EQL wire version to synthesize when rebuilding an envelope from the
 * stored `__source` attribute.
 *
 * `buildColumnKeyMap` is the canonical v3 marker in this codebase — see
 * `resolveEqlVersion` (`encryption/index.ts`) and `types.ts`, which document it
 * as *the* signal. Only v3 tables define it.
 */
export function isV3Table(table: AnyEncryptedTable): table is AnyV3Table {
  return (
    'buildColumnKeyMap' in table &&
    typeof table.buildColumnKeyMap === 'function'
  )
}

export class EncryptedDynamoDBErrorImpl
  extends Error
  implements EncryptedDynamoDBError
{
  constructor(
    message: string,
    public code: ProtectErrorCode | 'DYNAMODB_ENCRYPTION_ERROR',
    public details?: Record<string, unknown>,
  ) {
    super(message)
    this.name = 'EncryptedDynamoDBError'
  }
}

export function handleError(
  error: unknown,
  context: string,
  options?: {
    logger?: {
      error: (message: string, error: Error) => void
    }
    errorHandler?: (error: EncryptedDynamoDBError) => void
  },
): EncryptedDynamoDBError {
  // Preserve FFI error code if available, otherwise use generic DynamoDB error code
  // Check for FfiProtectError instance or plain error objects with code property
  const errorObj = error as Record<string, unknown>
  const errorCode =
    error instanceof FfiProtectError
      ? error.code
      : errorObj &&
          typeof errorObj === 'object' &&
          'code' in errorObj &&
          typeof errorObj.code === 'string'
        ? (errorObj.code as ProtectErrorCode)
        : 'DYNAMODB_ENCRYPTION_ERROR'

  const errorMessage =
    error instanceof Error
      ? error.message
      : errorObj && typeof errorObj.message === 'string'
        ? errorObj.message
        : String(error)

  const dynamoError = new EncryptedDynamoDBErrorImpl(errorMessage, errorCode, {
    context,
  })

  logger.error(`DynamoDB error in ${context}: ${errorMessage}`)

  if (options?.errorHandler) {
    options.errorHandler(dynamoError)
  }

  if (options?.logger) {
    options.logger.error(`Error in ${context}`, dynamoError)
  }

  return dynamoError
}

/**
 * Resolve a decrypt call against either client shape.
 *
 * The nominal `EncryptionClient` returns a chainable operation that carries
 * `.audit()`; the `TypedEncryptionClient` from `EncryptionV3` returns a plain
 * `Promise<Result<…>>`. Chain the audit metadata when the client can carry it,
 * otherwise await the promise directly — a typed client has no audit surface
 * on decrypt, so the metadata has nowhere to go.
 */
export async function resolveDecryptResult<T>(
  operation: unknown,
  auditData: { metadata?: Record<string, unknown> },
): Promise<
  { data: T; failure?: never } | { data?: never; failure: DecryptFailure }
> {
  const chainable = operation as {
    audit?: (data: { metadata?: Record<string, unknown> }) => unknown
  }

  if (typeof chainable?.audit !== 'function' && auditData.metadata) {
    // The typed EncryptionV3 client returns a plain promise with no decrypt
    // audit surface, so the metadata has nowhere to go. Make the drop
    // observable rather than silent — use the nominal client for audited
    // decrypts.
    logger.debug(
      'DynamoDB: decrypt audit metadata ignored — the typed client has no decrypt audit surface; use Encryption({ config: { eqlVersion: 3 } }) for audited decrypts.',
    )
  }

  const resolved =
    typeof chainable?.audit === 'function'
      ? await chainable.audit(auditData)
      : await operation

  return resolved as
    | { data: T; failure?: never }
    | { data?: never; failure: DecryptFailure }
}

type DecryptFailure = { message: string; code?: string }

/**
 * Rethrow a Result failure as an `Error` that preserves the FFI error code.
 * `withResult`'s `ensureError` wraps non-Error objects, which would otherwise
 * lose the code before `handleError` can read it.
 */
export function throwPreservingCode(failure: {
  message: string
  code?: string
}): never {
  const error = new Error(failure.message) as Error & { code?: string }
  error.code = failure.code
  throw error
}

/**
 * Clone caller input before it reaches the FFI, so encryption never mutates a
 * caller's object.
 *
 * `structuredClone` rather than a hand-rolled `Object.entries` reduce: the
 * reduce flattened every non-plain object to `{}`, which silently destroyed
 * `Date` values — making the whole `types.Timestamp*` / `types.Date*` domain
 * family unusable through this adapter — and blew the stack on a circular
 * reference. `structuredClone` handles Date, Map, Set, TypedArray and cycles
 * natively. Values it cannot structurally clone fall back to the original
 * reference rather than throwing.
 */
export function deepClone<T>(obj: T): T {
  if (obj === null || typeof obj !== 'object') {
    return obj
  }

  try {
    return structuredClone(obj)
  } catch {
    return obj
  }
}

/**
 * The storage payloads this adapter splits into DynamoDB attributes, across
 * both wire versions.
 *
 * `EncryptedValue` from `@/types` cannot describe these: its union is
 * `EncryptedScalar | EncryptedSteVec`, both v2-only, so it has no member
 * matching an untagged v3 scalar and reading `c`/`hm` off it does not compile
 * once the `k: 'ct'` narrowing is gone. The mapping only ever touches four
 * keys, so state them structurally.
 */
type StoredEqlPayload = {
  /** Wire version. Present on every payload in both versions. */
  v?: unknown
  /** Identifier `{ t, c }`. Present on every payload in both versions. */
  i?: unknown
  /** Absent on v3 scalars; `'ct'` on v2 scalars; `'sv'` on JSON in both. */
  k?: 'ct' | 'sv'
  /** Scalar ciphertext. */
  c?: unknown
  /** Deterministic equality term — the only one DynamoDB can query. */
  hm?: unknown
  /** ste_vec entries for a JSON document. */
  sv?: unknown
}

/**
 * Is this value an EQL payload, as opposed to a plaintext object that merely
 * looks like one?
 *
 * `v` and `i` are the discriminators, deliberately: they are the same keys the
 * FFI itself uses to decide whether a value is encrypted, and every payload in
 * both wire versions carries both. Testing for a ciphertext alone is not
 * enough — `c` is an ordinary attribute name (country, currency, count), and
 * treating `{ c: 'AU', d: 1 }` as a payload silently rewrites it to
 * `<attr>__source` and DISCARDS every sibling key.
 */
function isStoredEqlPayload(value: unknown): value is StoredEqlPayload {
  if (value === null || typeof value !== 'object') return false
  if (!('v' in value) || !('i' in value)) return false
  return 'c' in value || 'sv' in value
}

export function toEncryptedDynamoItem(
  encrypted: Record<string, unknown>,
  encryptedAttrs: string[],
): Record<string, unknown> {
  function processValue(
    attrName: string,
    attrValue: unknown,
    isNested: boolean,
  ): Record<string, unknown> {
    if (attrValue === null || attrValue === undefined) {
      return { [attrName]: attrValue }
    }

    // Handle encrypted payload. Both arms require the value to actually BE a
    // payload — a registered attribute name is not sufficient on its own, and
    // for a nested value the name tells us nothing at all.
    if (
      (encryptedAttrs.includes(attrName) || isNested) &&
      isStoredEqlPayload(attrValue)
    ) {
      const encryptPayload = attrValue

      // A JSON document, in either wire version, keeps its `k: 'sv'` tag. Its
      // index terms live *inside* the `sv` entries, so the whole array is
      // stored and there is no separate search-term attribute to split out.
      if (encryptPayload?.k === 'sv' && encryptPayload.sv) {
        const result: Record<string, unknown> = {}
        result[`${attrName}${ciphertextAttrSuffix}`] = encryptPayload.sv
        return result
      }

      // Scalars. v2 tags every payload `k: 'ct'`; v3 scalars carry NO `k`
      // discriminator at all, so the presence of a ciphertext is the signal —
      // gating on `k === 'ct'` would drop every v3 scalar through to the
      // nested-object branch below and write it out as a raw map.
      if (encryptPayload?.c) {
        const result: Record<string, unknown> = {}
        // `hm` is the deterministic equality term, and the only one a DynamoDB
        // key condition can use. Ordering terms (`op`/`ob`) and the match
        // bloom filter (`bf`) have no DynamoDB query surface, so they are not
        // stored — the value stays decryptable, it is just not orderable or
        // text-searchable inside DynamoDB.
        if (encryptPayload.hm) {
          result[`${attrName}${searchTermAttrSuffix}`] = encryptPayload.hm
        }
        result[`${attrName}${ciphertextAttrSuffix}`] = encryptPayload.c
        return result
      }
    }

    // Handle nested objects recursively
    if (typeof attrValue === 'object' && !Array.isArray(attrValue)) {
      const nestedResult = Object.entries(
        attrValue as Record<string, unknown>,
      ).reduce(
        (acc, [key, val]) => {
          const processed = processValue(key, val, true)
          return Object.assign({}, acc, processed)
        },
        {} as Record<string, unknown>,
      )
      return { [attrName]: nestedResult }
    }

    // Handle non-encrypted values
    return { [attrName]: attrValue }
  }

  return Object.entries(encrypted).reduce(
    (putItem, [attrName, attrValue]) => {
      const processed = processValue(attrName, attrValue, false)
      return Object.assign({}, putItem, processed)
    },
    {} as Record<string, unknown>,
  )
}

/**
 * The row-invariant table facts the read path needs. `build()` and
 * `resolveEncryptColumnMap` are not memoized, so a bulk decrypt of N items must
 * build this ONCE and reuse it — see `buildReadContext`. `columnPaths` are the
 * keys a model's fields are MATCHED on (JS property names); `toColumnName` maps
 * a match to the name the FFI config is keyed by. For v3 those differ whenever
 * a column is declared `emailAddress: types.TextEq('email_address')`.
 */
export type ReadContext = {
  isV3: boolean
  v: 2 | 3
  encryptConfig: {
    tableName: string
    columns: Record<
      string,
      { cast_as?: string; indexes: Record<string, unknown> }
    >
  }
  columnPaths: string[]
  toColumnName: (path: string) => string
}

/** Resolve the row-invariant read context for a table, once. */
export function buildReadContext(schema: AnyEncryptedTable): ReadContext {
  const isV3 = isV3Table(schema)
  const { columnPaths, toColumnName } = resolveEncryptColumnMap(schema)
  return {
    isV3,
    v: isV3 ? 3 : 2,
    encryptConfig: schema.build(),
    columnPaths,
    toColumnName,
  }
}

export function toItemWithEqlPayloads(
  decrypted: Record<string, EncryptedValue | unknown>,
  encryptionSchema: AnyEncryptedTable,
  // Resolved once here for the single-item path; passed in by the bulk path so
  // it is not rebuilt per item.
  context: ReadContext = buildReadContext(encryptionSchema),
): Record<string, unknown> {
  const { isV3, v, encryptConfig, columnPaths, toColumnName } = context

  /** Resolve an attribute back to the column path it was written from. */
  function matchColumn(leaf: string, prefix: string): string | undefined {
    const dotted = prefix ? `${prefix}.${leaf}` : leaf
    if (columnPaths.includes(dotted)) return dotted

    // Bare-leaf fallback, v2-only. A v2 `encryptedField('amount')` inside a
    // group registers the bare leaf `amount`, so a nested `amount__source` has
    // to match it by leaf. v3 always registers the full dotted path
    // (`'profile.ssn': types.TextEq('profile.ssn')`), so it never needs this —
    // and must NOT use it: a nested `note__source` would otherwise match a
    // same-named TOP-LEVEL `note` column and rewrite a plaintext sibling as an
    // envelope. Scope the fallback to nested v2 attributes only.
    if (!isV3 && prefix && columnPaths.includes(leaf)) return leaf
    return undefined
  }

  function processValue(
    attrName: string,
    attrValue: unknown,
    isNested: boolean,
    prefix = '',
  ): Record<string, unknown> {
    if (attrValue === null || attrValue === undefined) {
      return { [attrName]: attrValue }
    }

    // Drop the search term — but only when it belongs to a column we know
    // about. An unrelated customer attribute that merely ends in `__hmac`
    // (an app-level signature, say) must survive the read untouched.
    if (attrName.endsWith(searchTermAttrSuffix)) {
      const term = attrName.slice(0, -searchTermAttrSuffix.length)
      if (matchColumn(term, prefix)) return {}
      return { [attrName]: attrValue }
    }

    const columnName = attrName.slice(0, -ciphertextAttrSuffix.length)

    // Resolve the attribute back to a declared column. `matchColumn` prefers
    // the dotted path (`encryptedField('example.protected')`, and v3's dotted
    // property form) and falls back to the bare leaf (`encryptedField('amount')`
    // under a `details` group), so both authoring conventions resolve.
    const matched = matchColumn(columnName, prefix)

    // Handle encrypted payload. An unmatched attribute is NOT an envelope, even
    // when nested — previously `|| isNested` made every nested `*__source` a
    // decrypt target, so an unrelated customer attribute was handed to the FFI.
    if (attrName.endsWith(ciphertextAttrSuffix) && matched) {
      // Match on the property name, but identify by the DB column name — they
      // differ whenever a v3 column is declared
      // `emailAddress: types.TextEq('email_address')`.
      const i = { c: toColumnName(matched), t: encryptConfig.tableName }

      // A JSON document is stored as its ste_vec array and must be rebuilt with
      // `k: 'sv'`. Look the config up by the resolved identifier so a nested
      // JSON column (registered under a dotted path) is detected too — keyed on
      // the leaf it would be missing, and would be rebuilt as a scalar.
      // A v3 column builds the same `{ cast_as, indexes }` shape as a v2 one,
      // so this detection needs no version branch.
      const columnConfig = encryptConfig.columns[toColumnName(matched)]
      if (columnConfig?.cast_as === 'json' && columnConfig.indexes.ste_vec) {
        return {
          [columnName]: {
            i,
            v,
            // Mandatory in both versions — a v3 ste_vec document without it
            // fails deserialization with "missing field `k`".
            k: 'sv',
            sv: attrValue,
          },
        }
      }

      // v3 scalars are untagged; only v2 carries `k: 'ct'`. Both versions
      // require `v` and `i` — a payload missing either is not recognized as
      // encrypted and is returned to the caller verbatim rather than erroring.
      return {
        [columnName]: {
          i,
          v,
          ...(v === 2 ? { k: 'ct' } : {}),
          c: attrValue,
        },
      }
    }

    // Handle nested objects recursively, carrying the path so a nested column
    // can be matched against its registered dotted name.
    if (typeof attrValue === 'object' && !Array.isArray(attrValue)) {
      const nestedResult = Object.entries(
        attrValue as Record<string, unknown>,
      ).reduce(
        (acc, [key, val]) => {
          const processed = processValue(
            key,
            val,
            true,
            prefix ? `${prefix}.${attrName}` : attrName,
          )
          return Object.assign({}, acc, processed)
        },
        {} as Record<string, unknown>,
      )
      return { [attrName]: nestedResult }
    }

    // Handle non-encrypted values
    return { [attrName]: attrValue }
  }

  return Object.entries(decrypted).reduce(
    (formattedItem, [attrName, attrValue]) => {
      const processed = processValue(attrName, attrValue, false)
      return Object.assign({}, formattedItem, processed)
    },
    {} as Record<string, unknown>,
  )
}
