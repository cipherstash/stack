import type { ProtectErrorCode } from '@cipherstash/protect-ffi'
import { ProtectError as FfiProtectError } from '@cipherstash/protect-ffi'
import { resolveEncryptColumnMap } from '@/encryption/helpers/model-helpers'
import { DATE_LIKE_CASTS } from '@/eql/v3/columns'
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
 * `assertV3Schemas` (`encryption/index.ts`) and `types.ts`, which document it
 * as *the* signal. Only v3 tables define it.
 */
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
 * `EncryptionClient` returns a chainable operation carrying `.audit()` on
 * decrypt (the schema-derived model operation is a
 * `MappedDecryptOperation`). Chain the audit metadata onto it.
 *
 * NOT every client this package accepts does that. `WasmEncryptionClient`
 * (`@cipherstash/stack/wasm-inline` — the documented entry for Deno, Workers
 * and Supabase Edge Functions) returns a bare promise from decrypt, so it takes
 * the branch below and its audit metadata is dropped. It ships in this package
 * and satisfies `DynamoDBEncryptionClient` structurally, so it is accepted
 * without a cast (#772 review, finding 10).
 */
export async function resolveDecryptResult<T>(
  operation: unknown,
  auditData: { metadata?: Record<string, unknown> },
): Promise<
  { data: T; failure?: never } | { data?: never; failure: ResultFailure }
> {
  const chainable = operation as {
    audit?: (data: { metadata?: Record<string, unknown> }) => unknown
  }

  if (typeof chainable?.audit !== 'function' && auditData.metadata) {
    // Reached by the wasm-inline client (bare promise, no `.audit()`) and by
    // any custom client whose decrypt returns something else. There is nowhere
    // to put the metadata, so make the drop observable rather than silent.
    logger.debug(
      "DynamoDB: decrypt audit metadata ignored — this client's decrypt does not return a chainable operation with .audit(). Audited decrypts need a client from the default @cipherstash/stack entry; the wasm-inline client's decrypt returns a plain promise.",
    )
  }

  const resolved =
    typeof chainable?.audit === 'function'
      ? await chainable.audit(auditData)
      : await operation

  // A conforming client resolves to `{ data }` or `{ failure }`. A bare value
  // (or wrong shape) has neither, so casting it straight through would surface a
  // fake success carrying `undefined`. Reject it as a failure instead.
  if (
    resolved === null ||
    typeof resolved !== 'object' ||
    (!('data' in resolved) && !('failure' in resolved))
  ) {
    return {
      failure: {
        message:
          'DynamoDB: decrypt returned a malformed result — expected { data } or { failure }.',
      },
    }
  }

  return resolved as
    | { data: T; failure?: never }
    | { data?: never; failure: ResultFailure }
}

/**
 * The failure member both resolvers hand back — shared, because the encrypt and
 * decrypt paths return structurally identical failures and `throwPreservingCode`
 * consumes either. `code` is the FFI error code, preserved so `handleError` can
 * read it back off the rethrown Error (the error-code contract in AGENTS.md).
 */
type ResultFailure = { message: string; code?: string }

/**
 * Resolve an encrypt call against either client shape — the write-path mirror
 * of {@link resolveDecryptResult}.
 *
 * Both paths face the same split, and only the read one handled it. The native
 * clients return a thenable operation carrying `.audit()`; the WASM client's
 * `encryptModel` / `bulkEncryptModels` return a plain `Promise<WasmResult>`
 * from `wasmResult`, with no `.audit()` on this entry at all. Chaining it
 * unconditionally threw `client.encryptModel(...).audit is not a function`,
 * which `withResult` caught and reported as a `DYNAMODB_ENCRYPTION_ERROR` —
 * so every v3 write through this adapter on the wasm entry looked like a
 * genuine encryption fault (#788 review follow-up).
 *
 * Audit metadata still has nowhere to go on that shape, so it is dropped, and
 * the drop is logged rather than silent — exactly as on decrypt.
 */
export async function resolveEncryptResult<T>(
  operation: unknown,
  auditData: { metadata?: Record<string, unknown> },
  context: 'encryptModel' | 'bulkEncryptModels',
): Promise<
  { data: T; failure?: never } | { data?: never; failure: ResultFailure }
> {
  const chainable = operation as {
    audit?: (data: { metadata?: Record<string, unknown> }) => unknown
  }

  if (typeof chainable?.audit !== 'function' && auditData.metadata) {
    logger.debug(
      `DynamoDB: ${context} audit metadata ignored — this client's encrypt does not return a chainable operation with .audit(). Audited encrypts need a client from the default @cipherstash/stack entry; the wasm-inline client's encrypt returns a plain promise.`,
    )
  }

  const resolved =
    typeof chainable?.audit === 'function'
      ? await chainable.audit(auditData)
      : await operation

  // Same fail-closed check the read path applies: a bare value has neither
  // `data` nor `failure`, and casting it through would surface a fake success
  // carrying `undefined` — here, an "encrypted" item that was never encrypted.
  if (
    resolved === null ||
    typeof resolved !== 'object' ||
    (!('data' in resolved) && !('failure' in resolved))
  ) {
    return {
      failure: {
        message: `DynamoDB: ${context} returned a malformed result — expected { data } or { failure }.`,
      },
    }
  }

  return resolved as
    | { data: T; failure?: never }
    | { data?: never; failure: ResultFailure }
}

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
 * natively. Values it cannot structurally clone (a function/symbol/WeakMap-valued
 * property) fall back to a per-key shallow copy into a FRESH object rather than
 * throwing — the offending value passes through by reference, every other key
 * is copied, so the caller's original is never handed to the FFI.
 */
export function deepClone<T>(obj: T): T {
  if (obj === null || typeof obj !== 'object') {
    return obj
  }

  try {
    return structuredClone(obj)
  } catch {
    // `structuredClone` rejects function/symbol/WeakMap-valued properties. Fall
    // back to a per-key shallow copy into a FRESH object so the caller's
    // original is never handed to the FFI — otherwise the docblock guarantee
    // "encryption never mutates a caller's object" is silently voided. The
    // offending value passes through by reference; every other key is copied,
    // and a class instance is flattened to a plain object (prototype dropped).
    if (Array.isArray(obj)) {
      return [...obj] as T
    }
    return { ...(obj as Record<string, unknown>) } as T
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
  /**
   * Per-document SteVec KeyHeader. Present on a v3 JSON (`k: 'sv'`) document;
   * protect-ffi 0.30 decrypt requires it, so it is stored alongside `sv`.
   */
  h?: unknown
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
 *
 * The shape checks (`v` a number, `i` an object) mirror the core
 * `isEncryptedPayload` exactly, so the two envelope detectors cannot drift
 * apart. The `matchColumn` gate already means this only runs against values at
 * a declared encrypted column, but pinning the same predicate closes the
 * residual window where a plaintext `{ v, i }` lookalike could be split.
 */
function isStoredEqlPayload(value: unknown): value is StoredEqlPayload {
  if (value === null || typeof value !== 'object') return false
  const obj = value as Record<string, unknown>
  if (!('v' in obj) || typeof obj.v !== 'number') return false
  if (!('i' in obj) || typeof obj.i !== 'object') return false
  return 'c' in obj || 'sv' in obj
}

/**
 * Resolve an attribute (`leaf` under `prefix`) back to the column path it was
 * declared under, or `undefined` if it names no declared column. Shared by the
 * write and read paths so the two split and rebuild EXACTLY the same set of
 * attributes — an asymmetry here writes data one side can never reassemble.
 *
 * `columnPaths` are the JS property paths a model's fields are matched on.
 * Nested v3 fields are registered by their full dotted path (`profile.ssn`),
 * preventing a nested leaf from colliding with a top-level column.
 */
export function makeColumnMatcher(
  columnPaths: string[],
  // Stored EQL v2 only. A v2 grouped column registered its build key on the
  // BARE LEAF, so a field inside a group was written as
  // `<group>.<leaf>__source` while the schema knew it only as `<leaf>`. Exact
  // dotted matching alone therefore orphans every such attribute, which reads
  // back as raw base64 inside a `{ data }` success.
  //
  // Deliberately NOT enabled for v3: a v3 table registers full dotted paths so
  // that a nested leaf CANNOT collide with a same-named top-level column, and
  // matching by bare leaf there rewrote a plaintext sibling as an envelope and
  // handed it to the FFI as a decrypt target.
  allowBareLeaf = false,
) {
  const paths = new Set(columnPaths)
  return function matchColumn(
    leaf: string,
    prefix: string,
  ): string | undefined {
    const dotted = prefix ? `${prefix}.${leaf}` : leaf
    if (paths.has(dotted)) return dotted
    if (allowBareLeaf && prefix && paths.has(leaf)) return leaf
    return undefined
  }
}

export function toEncryptedDynamoItem(
  encrypted: Record<string, unknown>,
  encryptedAttrs: string[],
): Record<string, unknown> {
  const matchColumn = makeColumnMatcher(encryptedAttrs)

  function processValue(
    attrName: string,
    attrValue: unknown,
    prefix: string,
  ): Record<string, unknown> {
    if (attrValue === null || attrValue === undefined) {
      return { [attrName]: attrValue }
    }

    // Handle encrypted payload. Split only a value that BOTH is a payload and
    // names a declared column — matched on its property path, exactly as the
    // read path rebuilds it. Splitting an undeclared nested payload (matched by
    // shape alone) would write a `<leaf>__source` the read path never
    // reassembles, i.e. silent undecryptable data.
    if (matchColumn(attrName, prefix) && isStoredEqlPayload(attrValue)) {
      const encryptPayload = attrValue

      // A JSON document keeps its `k: 'sv'` tag. Its index terms live *inside*
      // the `sv` entries, so there is no separate search-term attribute to split
      // out. Store the `sv` entries together with the per-document KeyHeader
      // `h`: protect-ffi 0.30's SteVec decrypt requires `h` (there is no root
      // `c` to reconstruct from) and it is not derivable, whereas `v`/`i`/`k`
      // ARE reconstructed on read and so are kept out of the stored attribute.
      if (encryptPayload?.k === 'sv' && encryptPayload.sv) {
        const result: Record<string, unknown> = {}
        result[`${attrName}${ciphertextAttrSuffix}`] = {
          h: encryptPayload.h,
          sv: encryptPayload.sv,
        }
        return result
      }

      // Scalars. v2 tags every payload `k: 'ct'`; v3 scalars carry NO `k`
      // discriminator at all, so the presence of a ciphertext is the signal —
      // gating on `k === 'ct'` would drop every v3 scalar through to the
      // nested-object branch below and write it out as a raw map. Test
      // PRESENCE, not truthiness: a `{ v, i, c: '' }` payload is still a
      // payload, and letting it fall through would leak `v`/`i` into storage.
      if ('c' in encryptPayload) {
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

    // Handle nested objects recursively, carrying the path so a nested column
    // is matched against its registered dotted name.
    //
    // Arrays are a deliberate carve-out: they are NOT recursed into, so a
    // payload inside an array is stored as its whole envelope rather than split
    // into `<attr>__source`/`<attr>__hmac`. A DynamoDB key condition cannot
    // target an array element anyway, so there is nothing to gain from a split;
    // the read path skips arrays symmetrically, so such a value still
    // round-trips and decrypts. Documented in the DynamoDB skill's limitations.
    if (typeof attrValue === 'object' && !Array.isArray(attrValue)) {
      const nestedResult = Object.entries(
        attrValue as Record<string, unknown>,
      ).reduce(
        (acc, [key, val]) => {
          const processed = processValue(
            key,
            val,
            prefix ? `${prefix}.${attrName}` : attrName,
          )
          Object.assign(acc, processed)
          return acc
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
      const processed = processValue(attrName, attrValue, '')
      Object.assign(putItem, processed)
      return putItem
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
export function buildReadContext(
  schema: AnyEncryptedTable,
  storedEqlVersion: 2 | 3 = 3,
): ReadContext {
  const { columnPaths, toColumnName } = resolveEncryptColumnMap(schema)
  return {
    v: storedEqlVersion,
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
  // Out-param: the ACTUAL dotted paths a bare-leaf-matched date-like column was
  // written back to. A grouped v2 field matched as `placedAt` lands at
  // `details.placedAt`, but both clients resolve their date columns from the
  // REGISTERED paths alone (`rowReconstructor` in `encryption/client-v3.ts`,
  // `dateFields` in `wasm-inline.ts`), so neither reconstructs it and the value
  // reads back as an ISO string. This is the only layer that knows the alias
  // happened; the decrypt operations reconstruct at what it reports.
  //
  // Per item, never shared across a bulk call: `details.placedAt` may be an
  // encrypted date column in one item and an ordinary plaintext string in the
  // next, and a shared set would convert the latter.
  aliasedDatePaths?: Set<string>,
): Record<string, unknown> {
  const { v, encryptConfig, columnPaths, toColumnName } = context

  // The same matcher the write path splits with, so the two stay symmetric.
  // The bare-leaf fallback is read-only and v2-only: writes are EQL v3 only, so
  // the write path never needs it and must stay strict.
  const matchColumn = makeColumnMatcher(columnPaths, v === 2)

  function processValue(
    attrName: string,
    attrValue: unknown,
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

    // Resolve the attribute back to its declared dotted property path.
    const matched = matchColumn(columnName, prefix)

    // A stored ciphertext attribute that names no declared column is almost
    // always a schema rename: the value reads back as raw base64 with no error.
    // Leave the passthrough behaviour intact (an unmatched `*__source` is not an
    // envelope), but make the silent drop observable.
    if (attrName.endsWith(ciphertextAttrSuffix) && !matched) {
      const dotted = prefix ? `${prefix}.${attrName}` : attrName
      logger.debug(
        `DynamoDB: attribute "${dotted}" ends in ${ciphertextAttrSuffix} but names no declared column — passing it through as raw ciphertext (a column rename can cause this).`,
      )
    }

    // Handle encrypted payload. An unmatched attribute is NOT an envelope, even
    // when nested — previously `|| isNested` made every nested `*__source` a
    // decrypt target, so an unrelated customer attribute was handed to the FFI.
    if (attrName.endsWith(ciphertextAttrSuffix) && matched) {
      // Match on the property name, but identify by the DB column name — they
      // differ whenever a v3 column is declared
      // `emailAddress: types.TextEq('email_address')`.
      const i = { c: toColumnName(matched), t: encryptConfig.tableName }

      // A JSON document is stored as `{ h, sv }` (see the write path); rebuild
      // the full SteVec envelope around it. protect-ffi 0.30 deserialization is
      // strict — it requires `k` ("missing field `k`") and the per-document
      // KeyHeader `h` ("missing field `h`"), and there is no root `c`. `i`/`v`/`k`
      // are reconstructed; `h`/`sv` come from storage. Look the config up by the
      // resolved identifier so a nested JSON column (registered under a dotted
      // path) is detected too. A v3 column builds the same `{ cast_as, indexes }`
      // shape as a v2 one, so this detection needs no version branch.
      const columnConfig = encryptConfig.columns[toColumnName(matched)]

      // The bare-leaf fallback fired iff the match is not the attribute's own
      // dotted path — an exact match returns `dotted`, the fallback returns the
      // leaf under a non-empty prefix. Only date-like casts need this: every
      // other kind decrypts to its final type with no per-path work.
      const dotted = prefix ? `${prefix}.${columnName}` : columnName
      if (
        aliasedDatePaths &&
        matched !== dotted &&
        (DATE_LIKE_CASTS as readonly string[]).includes(
          columnConfig?.cast_as as string,
        )
      ) {
        aliasedDatePaths.add(dotted)
      }

      if (columnConfig?.cast_as === 'json' && columnConfig.indexes.ste_vec) {
        const stored = attrValue as { h?: unknown; sv?: unknown }
        return {
          [columnName]: {
            i,
            v,
            k: 'sv',
            h: stored.h,
            sv: stored.sv,
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
    // can be matched against its registered dotted name. Arrays are skipped
    // symmetrically with the write path (which stores array-nested payloads
    // whole), so such a value passes straight to the FFI and still decrypts.
    if (typeof attrValue === 'object' && !Array.isArray(attrValue)) {
      const nestedResult = Object.entries(
        attrValue as Record<string, unknown>,
      ).reduce(
        (acc, [key, val]) => {
          const processed = processValue(
            key,
            val,
            prefix ? `${prefix}.${attrName}` : attrName,
          )
          Object.assign(acc, processed)
          return acc
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
      const processed = processValue(attrName, attrValue)
      Object.assign(formattedItem, processed)
      return formattedItem
    },
    {} as Record<string, unknown>,
  )
}
