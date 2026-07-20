import type { ProtectErrorCode } from '@cipherstash/protect-ffi'
import { ProtectError as FfiProtectError } from '@cipherstash/protect-ffi'
import type { EncryptedValue } from '@/types'
import { logger } from '@/utils/logger'
import type { AnyEncryptedTable, EncryptedDynamoDBError } from './types'

export const ciphertextAttrSuffix = '__source'
export const searchTermAttrSuffix = '__hmac'

/**
 * Which EQL wire version to synthesize when rebuilding an envelope from the
 * stored `__source` attribute.
 *
 * v2 columns are `EncryptedColumn` instances from `@/schema`; v3 columns are
 * the concrete-domain classes from `@/eql/v3`, which are the only ones carrying
 * `getQueryCapabilities`. That method is the discriminator used elsewhere in
 * the codebase (see `encryption/helpers/infer-index-type.ts`), so reuse it
 * rather than inventing a second signal.
 *
 * A v2 table's builders may nest (`encryptedField` groups columns under an
 * object), so walk one level rather than assuming a flat map. v3 has no nested
 * columns at all.
 */
export function isV3Table(table: AnyEncryptedTable): boolean {
  return Object.values(table.columnBuilders).some(isV3Column)
}

function isV3Column(builder: unknown): boolean {
  if (builder === null || typeof builder !== 'object') return false
  if ('getQueryCapabilities' in builder) return true
  // A v2 nested group: `{ ssn: encryptedField(...), address: { ... } }`.
  return Object.values(builder as Record<string, unknown>).some(isV3Column)
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

export function deepClone<T>(obj: T): T {
  if (obj === null || typeof obj !== 'object') {
    return obj
  }

  if (Array.isArray(obj)) {
    return obj.map((item) => deepClone(item)) as unknown as T
  }

  return Object.entries(obj as Record<string, unknown>).reduce(
    (acc, [key, value]) => ({
      // biome-ignore lint/performance/noAccumulatingSpread: TODO later
      ...acc,
      [key]: deepClone(value),
    }),
    {} as T,
  )
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
  /** Absent on v3 scalars; `'ct'` on v2 scalars; `'sv'` on JSON in both. */
  k?: 'ct' | 'sv'
  /** Scalar ciphertext. */
  c?: unknown
  /** Deterministic equality term — the only one DynamoDB can query. */
  hm?: unknown
  /** ste_vec entries for a JSON document. */
  sv?: unknown
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

    // Handle encrypted payload
    if (
      encryptedAttrs.includes(attrName) ||
      (isNested &&
        typeof attrValue === 'object' &&
        'c' in (attrValue as object))
    ) {
      const encryptPayload = attrValue as StoredEqlPayload

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

export function toItemWithEqlPayloads(
  decrypted: Record<string, EncryptedValue | unknown>,
  encryptionSchema: AnyEncryptedTable,
): Record<string, unknown> {
  const v = isV3Table(encryptionSchema) ? 3 : 2

  function processValue(
    attrName: string,
    attrValue: unknown,
    isNested: boolean,
  ): Record<string, unknown> {
    if (attrValue === null || attrValue === undefined) {
      return { [attrName]: attrValue }
    }

    // Skip HMAC fields
    if (attrName.endsWith(searchTermAttrSuffix)) {
      return {}
    }

    const encryptConfig = encryptionSchema.build()
    const encryptedAttrs = Object.keys(encryptConfig.columns)
    const columnName = attrName.slice(0, -ciphertextAttrSuffix.length)

    // Handle encrypted payload
    if (
      attrName.endsWith(ciphertextAttrSuffix) &&
      (encryptedAttrs.includes(columnName) || isNested)
    ) {
      const i = { c: columnName, t: encryptConfig.tableName }

      // Nested values are not searchable, so we can just return the standard EQL payload.
      // Worth noting, that encryptConfig.columns[columnName] will be undefined if isNested is true.
      // A v3 column builds the same `{ cast_as, indexes }` shape as a v2 one,
      // so this detection needs no version branch.
      if (
        !isNested &&
        encryptConfig.columns[columnName].cast_as === 'json' &&
        encryptConfig.columns[columnName].indexes.ste_vec
      ) {
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

  return Object.entries(decrypted).reduce(
    (formattedItem, [attrName, attrValue]) => {
      const processed = processValue(attrName, attrValue, false)
      return Object.assign({}, formattedItem, processed)
    },
    {} as Record<string, unknown>,
  )
}
