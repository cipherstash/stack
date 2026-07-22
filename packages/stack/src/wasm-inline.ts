/**
 * WASM-inline entry for `@cipherstash/stack` — for Deno, Bun, Cloudflare
 * Workers, Supabase Edge Functions, and any runtime where the native
 * `@cipherstash/protect-ffi` NAPI bindings are unavailable.
 *
 * Mirrors the protect-ffi / auth `/wasm-inline` pattern: the WASM module
 * is inlined into the JS bundle as a base64 blob (no separate `.wasm`
 * fetch / file read), so this entry works in environments that disallow
 * `fs` or relative asset loading.
 *
 * Use this import path: `@cipherstash/stack/wasm-inline`
 *
 * This entry is EQL v3: author schemas with the `types` DSL / `encryptedTable`
 * re-exported here (the same authoring surface as `@cipherstash/stack/eql/v3`).
 *
 * @example
 * ```ts
 * import {
 *   Encryption, encryptedTable, types,
 * } from "@cipherstash/stack/wasm-inline"
 *
 * const users = encryptedTable("users", { email: types.TextSearch("email") })
 *
 * const client = await Encryption({
 *   schemas: [users],
 *   config: {
 *     workspaceCrn: Deno.env.get("CS_WORKSPACE_CRN")!,
 *     accessKey:    Deno.env.get("CS_CLIENT_ACCESS_KEY")!,
 *     clientId:     Deno.env.get("CS_CLIENT_ID")!,
 *     clientKey:    Deno.env.get("CS_CLIENT_KEY")!,
 *   },
 * })
 *
 * // Every fallible method returns `{ data } | { failure }` — the same
 * // contract as the native entry. Unwrap before use.
 * const enc = await client.encrypt("alice@example.com", {
 *   column: users.email,
 *   table: users,
 * })
 * if (enc.failure) throw new Error(enc.failure.message)
 *
 * const dec = await client.decrypt(enc.data)
 * if (dec.failure) throw new Error(dec.failure.message)
 *
 * // Searchable encryption: mint a ciphertext-free QUERY TERM and cast it
 * // to the column's `eql_v3.query_<domain>` type in SQL to hit the index.
 * const term = await client.encryptQuery("alice@example.com", {
 *   column: users.email,
 *   table: users,
 *   queryType: "freeTextSearch",
 * })
 * if (term.failure) throw new Error(term.failure.message)
 * // e.g. postgres-js — bind `term.data`, NOT the envelope:
 * //   sql`SELECT * FROM users
 * //       WHERE eql_v3.matches(email, ${term.data}::jsonb::eql_v3.query_text_search)`
 * ```
 *
 * For per-user, identity-bound encryption on the edge, build an
 * `OidcFederationStrategy` (federates an end user's OIDC JWT — Clerk,
 * Supabase, … — into a CTS service token) and pass it via
 * `config.authStrategy`:
 *
 * ```ts
 * import { OidcFederationStrategy } from "@cipherstash/stack/wasm-inline"
 * import { cookieStore } from "@cipherstash/auth/cookies"
 *
 * const authStrategy = OidcFederationStrategy.create(
 *   "crn:ap-southeast-2.aws:my-workspace-id", () => getClerkSessionToken(req),
 *   { store: cookieStore({ request: req, responseHeaders }) },
 * )
 * const client = await Encryption({ schemas, config: { authStrategy, clientId, clientKey } })
 * ```
 *
 * For service-to-service / CI use with a custom token store, build an
 * `AccessKeyStrategy.create(workspaceCrn, accessKey, { store })` the same
 * way (it derives the region from the CRN). Both strategies are
 * re-exported from this entry.
 */

import { withResult } from '@byteslice/result'
import {
  AccessKeyStrategy,
  type OidcFederationStrategy,
} from '@cipherstash/auth/wasm-inline'
import {
  decrypt as wasmDecrypt,
  decryptBulkFallible as wasmDecryptBulkFallible,
  encrypt as wasmEncrypt,
  encryptBulk as wasmEncryptBulk,
  encryptQuery as wasmEncryptQuery,
  encryptQueryBulk as wasmEncryptQueryBulk,
  isEncrypted as wasmIsEncrypted,
  newClient as wasmNewClient,
} from '@cipherstash/protect-ffi/wasm-inline'
import { resolveIndexType } from '@/encryption/helpers/infer-index-type'
import {
  prepareBulkModelsForOperation,
  resolveEncryptColumnMap,
  setNestedValue,
} from '@/encryption/helpers/model-traversal'
import {
  assertValidNumericValue,
  assertValueIndexCompatibility,
} from '@/encryption/helpers/validation'
import {
  type AnyV3Table,
  buildEncryptConfig,
  type V3DecryptedModel,
  type V3EncryptedModel,
  type V3ModelInput,
} from '@/eql/v3'
import { DATE_LIKE_CASTS } from '@/eql/v3/columns'
import { type EncryptionError, EncryptionErrorTypes } from '@/errors'
import {
  type CastAs,
  type EncryptConfig,
  encryptConfigSchema,
  toEqlCastAs,
} from '@/schema'
import type {
  BuildableV3QueryableColumn,
  Encrypted,
  EncryptedQuery,
  EncryptOptions,
  Plaintext,
  QueryTypeName,
} from '@/types'
import { hasBuildColumnKeyMap } from '@/types'

// -----------------------------------------------------------------------
// Schema + type re-exports
// -----------------------------------------------------------------------

// Auth strategies for `config.authStrategy` — `OidcFederationStrategy` for
// per-user identity-bound encryption, `AccessKeyStrategy` for M2M / CI.
// Re-exported so edge consumers don't need a separate `@cipherstash/auth`
// import (pair `OidcFederationStrategy` with `cookieStore` from
// `@cipherstash/auth/cookies` for cross-invocation token caching).
export {
  AccessKeyStrategy,
  OidcFederationStrategy,
} from '@cipherstash/auth/wasm-inline'
// The WASM entry is EQL v3. Its authoring surface — `types`, `encryptedTable`,
// the column classes, `buildEncryptConfig`, and the inference helpers — is the
// v3 one, re-exported wholesale so an edge consumer authors v3 schemas from this
// single import. The v2 builders are intentionally NOT exported here: the WASM
// path was never announced or documented for v2, and the edge targets v3. EQL v2
// remains fully available on the native `@cipherstash/stack` entry.
export * from '@/eql/v3'
// The failure vocabulary every method on this entry now returns. Exported here
// so an edge consumer can discriminate `result.failure.type` from the SAME
// single import they got the client from — without reaching for the
// Node-oriented `@cipherstash/stack/errors` subpath (undocumented on edge) or
// depending on `@byteslice/result` — which is bundled INTO this file, so it is
// not a package an edge consumer can import at all.
export { type EncryptionError, EncryptionErrorTypes } from '@/errors'
export type { Encrypted } from '@/types'

/** Re-exported convenience predicate — same as the raw protect-ffi one. */
export function isEncrypted(value: unknown): boolean {
  return wasmIsEncrypted(value as never)
}

// Note: the raw `newClient` / `encrypt` / `decrypt` from
// `@cipherstash/protect-ffi/wasm-inline` are intentionally NOT
// re-exported. The raw `newClient` does not normalise SDK-facing
// `cast_as` values (see `normalizeCastAs` below) and a re-export would
// invite consumers to build configs that this normaliser rejects. Import
// those names directly from their source package if you need raw access.

// -----------------------------------------------------------------------
// High-level `Encryption` factory + client.
// -----------------------------------------------------------------------

/**
 * The plaintext shape accepted by `encrypt` and returned by `decrypt`.
 * Mirrors protect-ffi's `JsPlaintext` (recursive: arrays of any of
 * these are valid), plus `bigint` for `int8` columns. Re-defined here so
 * the wasm-inline `.d.ts` doesn't pull in the Node-only protect-ffi types.
 *
 * `bigint` is carried natively across the wasm boundary by protect-ffi
 * 0.28's Rust `encode_plaintext` (which i64-bounds-checks on encrypt and
 * builds a `js_sys::BigInt` on decrypt), so widening the type here is all
 * the SDK needs to accept/return `bigint` on the wasm entry point.
 */
export type WasmPlaintext =
  | string
  | number
  | bigint
  | boolean
  | null
  | Record<string, unknown>
  | WasmPlaintext[]

/**
 * Config for {@link Encryption} on the WASM entry point.
 *
 * The workspace CRN is the single source of truth for workspace
 * identity and deployment region — matching the Node entry and
 * protect-ffi 0.25+, which read `CS_WORKSPACE_CRN` and no longer
 * consult a separate `CS_REGION`. The CRN is passed straight to the
 * underlying `AccessKeyStrategy`, which derives the region from it, so
 * there is no `region` field to keep in sync.
 *
 * For service-to-service / CI use, pass `accessKey` plus the workspace
 * `clientId` / `clientKey` and we construct an `AccessKeyStrategy` for
 * you. To plug in a custom token store (cookies on Supabase Edge, KV on
 * Cloudflare Workers, …) or to bind encryption to an end user, build the
 * strategy yourself — `AccessKeyStrategy` or `OidcFederationStrategy` —
 * and hand it to `config.authStrategy` instead. A pre-built strategy
 * already carries the CRN, so `workspaceCrn` is optional on that path.
 *
 * Mirrors the Node `ClientConfig`: `authStrategy` is the documented field,
 * `strategy` is retained as a deprecated alias (see below).
 */
export type WasmClientConfig = {
  /** Workspace client identifier — required by the WASM client. */
  clientId: string
  /** Workspace client key — required by the WASM client. */
  clientKey: string
  // Provide exactly one of `accessKey` (we build the strategy) or a
  // pre-built auth strategy — never both, never neither.
} & (
  | {
      /**
       * CipherStash workspace CRN, e.g.
       * `"crn:ap-southeast-2.aws:my-workspace-id"`. Required on the
       * access-key path — it is the single source of truth for workspace
       * identity and `AccessKeyStrategy` derives the region from it.
       */
      workspaceCrn: string
      accessKey: string
      authStrategy?: never
      strategy?: never
    }
  | {
      /**
       * Optional on the strategy path. A pre-built `authStrategy` (e.g.
       * `OidcFederationStrategy.create(workspaceCrn, …)`) already
       * encapsulates the workspace CRN and region, so the SDK never reads
       * this — supply it if convenient, omit it otherwise.
       */
      workspaceCrn?: string
      accessKey?: never
      /** A pre-built auth strategy for per-user or M2M authentication. */
      authStrategy: WasmAuthStrategy
      /**
       * @deprecated Renamed to `authStrategy`. Still honoured for backwards
       * compatibility (it logs a deprecation warning at runtime) but will be
       * removed in a future release.
       */
      strategy?: WasmAuthStrategy
    }
  | {
      workspaceCrn?: string
      accessKey?: never
      authStrategy?: never
      /**
       * @deprecated Renamed to `authStrategy`. Still honoured for backwards
       * compatibility (it logs a deprecation warning at runtime) but will be
       * removed in a future release.
       */
      strategy: WasmAuthStrategy
    }
)

/**
 * Any auth strategy accepted on the WASM path. Both expose
 * `getToken(): Promise<Result<TokenResult, AuthFailure>>` — as of
 * `@cipherstash/auth` 0.41 the token is wrapped in a `@byteslice/result`
 * envelope. `@cipherstash/protect-ffi` 0.28+ unwraps that envelope (reading
 * `.data.token`, surfacing `.failure`) inside its WASM `newClient`; 0.27 read
 * `.token` off the envelope and saw `undefined`, so keep the ffi floor at 0.28.
 *
 * - {@link AccessKeyStrategy} — static M2M / CI access key.
 * - {@link OidcFederationStrategy} — federates an end-user OIDC JWT into a
 *   CTS service token, for per-user identity-bound encryption.
 */
export type WasmAuthStrategy = AccessKeyStrategy | OidcFederationStrategy

export type WasmEncryptionConfig = {
  /** One or more EQL v3 tables, authored with `types` / `encryptedTable` from
   *  this entry. The WASM entry is EQL v3 only. */
  schemas: [AnyV3Table, ...AnyV3Table[]]
  config: WasmClientConfig
}

/**
 * Options for {@link WasmEncryptionClient.encryptQuery}.
 *
 * The column must be a QUERYABLE v3 column (authored via the `types.*`
 * factories re-exported from this entry) — storage-only columns like
 * `types.Text` with no indexes have nothing to query.
 */
export type WasmEncryptQueryOptions = {
  /** The `encryptedTable(...)` the column belongs to. */
  table: EncryptOptions['table']
  /** The queryable v3 column the term targets, e.g. `users.email`. */
  column: BuildableV3QueryableColumn
  /**
   * Which of the column's indexes the term targets:
   *
   * - `'equality'` — exact match (`unique` index; `=` / `IN`)
   * - `'freeTextSearch'` — fuzzy token match (`match` index; one-sided —
   *   a match may be a false positive, a non-match never is)
   * - `'orderAndRange'` — comparisons and ranges (`ore` index; `<` `>`
   *   `BETWEEN` / `ORDER BY`)
   * - `'searchableJson'` — encrypted JSON (`ste_vec` index): a **string**
   *   value is treated as a JSONPath selector (`'$.user.email'`), any other
   *   value as a containment needle (`{ role: 'admin' }`)
   *
   * Omit to infer from the column's configured indexes (priority:
   * `unique > match > ore > ste_vec`, matching the native client) —
   * unambiguous for single-index columns like `types.TextEq`, but be
   * explicit for multi-index domains like `types.TextSearch` (which
   * carries all three scalar indexes).
   */
  queryType?: QueryTypeName
}

/**
 * One term for {@link WasmEncryptionClient.encryptQueryBulk} — the
 * {@link WasmEncryptQueryOptions} plus the plaintext needle. A `null`
 * value yields `null` at the same position in the result (nothing to
 * search for).
 */
export type WasmQueryTerm = WasmEncryptQueryOptions & {
  value: WasmPlaintext
}

/**
 * One storage value in a {@link WasmEncryptionClient.bulkEncrypt} batch.
 *
 * Each entry carries its OWN table and column, rather than the batch taking a
 * single `EncryptOptions` the way {@link WasmEncryptionClient.encrypt} does.
 * That mirrors {@link WasmQueryTerm} — and it is what makes the round-trip
 * saving worth having: rendering a page of rows means encrypting several
 * columns across many rows, and a single-column batch would still cost one
 * ZeroKMS call per column. The FFI's `EncryptPayload` is per-item
 * (`{ plaintext, table, column }`), so mixing is free at the boundary.
 *
 * (The native entry's `bulkEncrypt` takes one column for the whole batch and
 * wraps values in `{ id, plaintext }` envelopes. This surface does neither —
 * see {@link WasmEncryptionClient.bulkEncrypt} for why.)
 */
export type WasmBulkPlaintext = {
  /**
   * The value to encrypt. `null`/`undefined` yields `null` at this index
   * without reaching ZeroKMS.
   *
   * `undefined` is admitted explicitly — unlike {@link WasmQueryTerm.value},
   * which is `WasmPlaintext` alone. Both are guarded identically at runtime,
   * but the shapes fed to them differ: a query needle is written by hand,
   * whereas a bulk batch is mapped straight off database rows, where an
   * absent column is `undefined`. Typing it out would force `?? null` at
   * every call site to satisfy a check the runtime does anyway.
   */
  plaintext: WasmPlaintext | undefined
  table: EncryptOptions['table']
  column: EncryptOptions['column']
}

/**
 * Map a thrown error into the repo-wide `{ type, message, code? }` failure
 * shape — the second half of `withResult`, shared by every method on this
 * client so the failure surface is identical across them.
 *
 * `AGENTS.md` makes this a contract, not a style choice: *"Operations return
 * `{ data }` or `{ failure }`. Preserve this shape and error `type` values in
 * `EncryptionErrorTypes`."* This entry did not follow it until #741 — see
 * {@link WasmEncryptionClient} for why that mattered and what changed.
 */
/**
 * The `{ data } | { failure }` envelope every fallible method here returns.
 *
 * Structurally identical to `@byteslice/result`'s `Result<T, EncryptionError>`
 * — which is what `withResult` actually produces — but declared LOCALLY on
 * purpose, for the same reason {@link WasmPlaintext} re-declares protect-ffi's
 * `JsPlaintext`: `@byteslice/result` is bundled into `dist/wasm-inline.js`
 * (tsup `noExternal`), so it is not a package an edge consumer can resolve.
 * Re-exporting its type put `import { Result } from '@byteslice/result'` at the
 * top of the emitted `.d.ts`, which a Deno consumer cannot resolve at all — the
 * e2e import map maps only the three `/wasm-inline` subpaths.
 *
 * Declaring it here keeps the published types self-contained.
 */
export type WasmResult<T> =
  | { data: T; failure?: never }
  | { data?: never; failure: EncryptionError }

/**
 * Read an FFI error code STRUCTURALLY.
 *
 * Deliberately not `@/encryption/helpers/error-code`: that narrows with
 * `instanceof` against the native `ProtectError`, which is a runtime VALUE
 * import of `@cipherstash/protect-ffi`. protect-ffi is not in tsup's
 * `noExternal`, so importing it here put a bare `@cipherstash/protect-ffi`
 * specifier into `dist/wasm-inline.js` — the native NAPI entry, in the one
 * bundle that exists to avoid it. On Workers / Edge the non-`node` condition
 * resolves that specifier to a module exporting no `ProtectError` at all.
 *
 * A structural read is also the only thing that could ever work here: the WASM
 * build ships no error class, so `instanceof` never matches on this path
 * regardless. A `code` string is all there is to find.
 */
function readErrorCode(error: unknown): EncryptionError['code'] {
  if (typeof error !== 'object' || error === null) return undefined
  const { code } = error as { code?: unknown }
  return typeof code === 'string'
    ? (code as EncryptionError['code'])
    : undefined
}

function toFailure(
  type: EncryptionError['type'],
): (error: unknown) => EncryptionError {
  return (error: unknown) => ({
    type,
    message: error instanceof Error ? error.message : String(error),
    code: readErrorCode(error),
  })
}

/**
 * Coerce a rejection into an `Error` WITHOUT losing what it said.
 *
 * `withResult`'s built-in `ensureError` replaces any non-`Error` throw with
 * `new Error('Something went wrong')`, discarding the original value entirely
 * (@byteslice/result@0.2.0, `dist/result.js:27`). It is only the fallback,
 * though — `withResult` prefers the `onException` hook:
 *
 * ```js
 * const error = hooks?.onException?.(ex) ?? ensureError(ex)
 * ```
 *
 * Supplying it matters more here than on the native entry. wasm-bindgen
 * rejects with the raw `JsValue` the Rust side produced (`throw
 * takeFromExternrefTable0(...)` in the generated glue), and the WASM build
 * exports no `ProtectError` class, so a genuine FFI failure can arrive as a
 * plain string or object rather than an `Error`. Without this hook its message
 * would be replaced by boilerplate — strictly worse than the throwing
 * behaviour this entry had before, which at least propagated the raw value.
 */
function toError(ex: unknown): Error {
  if (ex instanceof Error) return ex
  if (typeof ex === 'string') return new Error(ex)

  // Objects are the other shape wasm-bindgen hands back, so serialize rather
  // than settle for "[object Object]". `JSON.stringify` returns undefined for
  // a symbol/function and throws on a cycle.
  let message: string
  try {
    message = JSON.stringify(ex) ?? safeString(ex)
  } catch {
    message = safeString(ex)
  }

  // Carry a structural `code` onto the synthesized Error so `toFailure` can
  // still surface it. Without this the conversion loses it: `withResult` runs
  // `onException` FIRST, so the mapper only ever sees this fresh Error, and
  // `failure.code` could never be populated on this entry at all.
  const error = new Error(message) as Error & { code?: string }
  const code = readErrorCode(ex)
  if (code) error.code = code
  return error
}

/**
 * `String(value)` that cannot itself throw.
 *
 * A null-prototype object (`Object.create(null)`) has no `toString`, so
 * `String(ex)` raises `TypeError: Cannot convert object to primitive value`.
 * That matters here because `withResult` invokes `onException` bare inside its
 * catch — a throw from this function escapes the Result contract entirely and
 * REJECTS the call, so edge code written as `if (result.failure)` would crash
 * on an unhandled rejection. `Object.prototype.toString` works on anything.
 */
function safeString(value: unknown): string {
  try {
    return String(value)
  } catch {
    return Object.prototype.toString.call(value)
  }
}

/**
 * `withResult` bound to this entry's conventions: the repo-wide failure shape
 * ({@link toFailure}) plus the {@link toError} hook.
 *
 * One seam, so a method added later cannot silently omit either. Omitting them
 * would not fail a build — it would quietly degrade failure messages, which is
 * precisely the bug this helper exists to prevent.
 */
function wasmResult<T>(
  operation: () => Promise<T>,
  type: EncryptionError['type'],
): Promise<WasmResult<T>> {
  return withResult(operation, toFailure(type), { onException: toError })
}

/**
 * Guard the positional contract the bulk methods rely on.
 *
 * Both `bulkEncrypt` and `bulkDecrypt` match FFI results to inputs by INDEX —
 * the payloads carry no correlation id (protect-ffi's `EncryptPayload` /
 * `BulkDecryptPayload` have no `id` field). If the FFI ever returned a
 * different count, the surplus input slots would keep their initial `null`,
 * which a caller cannot distinguish from "this row genuinely had no value".
 * That is a silent-wrong-data failure, so it throws instead.
 */
/**
 * The positional-batch bookkeeping every bulk method here shares: compact the
 * live entries, remember where each came from, short-circuit an all-dead
 * batch, send one FFI call, assert the response length, and hand back each
 * result paired with the INPUT index it belongs to.
 *
 * Hand-rolled in three places before — the very code the length guard exists
 * because it is easy to get subtly wrong. (The model helpers do NOT route
 * through here: their batches are never sparse — nulls stay in the model —
 * and each entry carries `{ modelIndex, fieldKey }` structure instead of a
 * positional slot, so they pair results directly and call
 * {@link assertBatchLength} themselves.)
 *
 * `out` is built with `Array.from`, NOT `items.map(() => null)`: `map` SKIPS
 * holes in a sparse input, so `bulkDecrypt([a, , b])` would leave index 1 an
 * `undefined` hole rather than the documented `null`, while lengths still
 * matched. (`forEach` skipping holes is correct and wanted — a hole is a dead
 * slot.)
 */
async function runBatch<In, Res, Out = Res>(
  op: string,
  items: readonly In[],
  isLive: (item: In) => boolean,
  send: (live: In[]) => Promise<Res[]>,
): Promise<{
  out: Array<Out | null>
  placed: Array<{ result: Res; at: number }>
}> {
  const live: Array<{ item: In; at: number }> = []
  items.forEach((item, at) => {
    if (isLive(item)) live.push({ item, at })
  })

  const out: Array<Out | null> = Array.from(
    { length: items.length },
    () => null,
  )
  if (live.length === 0) return { out, placed: [] }

  const results = await send(live.map(({ item }) => item))
  assertBatchLength(op, results.length, live.length)

  // Lengths are equal past the assert, so every index pairs.
  const placed = results.map((result, i) => ({
    result,
    at: (live[i] as { at: number }).at,
  }))
  return { out, placed }
}

function assertBatchLength(op: string, received: number, sent: number): void {
  if (received !== sent) {
    throw new Error(
      `[encryption]: ${op} sent ${sent} payload(s) to ZeroKMS but received ${received} back. ` +
        'Results are matched to inputs by position, so a count mismatch would silently return null ' +
        'for the unmatched entries — refusing rather than returning data that looks complete.',
    )
  }
}

/**
 * One item of a `decryptBulkFallible` response: the decrypted plaintext, or
 * this item's own failure (the batch call itself still resolves). Shared by
 * {@link WasmEncryptionClient.bulkDecrypt} and the model decrypt engine.
 */
type FallibleDecryptItem =
  | { data: WasmPlaintext }
  | { error: string; code?: string }

/**
 * The JS property paths of `table`'s date-like columns (`cast_as: 'date' |
 * 'timestamp'`). The model decrypt path rebuilds these into `Date` values:
 * the FFI returns date plaintexts in their serialized form (this entry sends
 * them as ISO strings — see the model encrypt engine), and the native v3
 * client performs the same reconstruction (`rowReconstructor` in
 * `@/encryption/v3`), so a model round-trips `Date` → `Date` on both entries.
 */
function datePropertyPaths(table: AnyV3Table): Set<string> {
  const { columns } = table.build()
  const propToDb = table.buildColumnKeyMap()
  const paths = new Set<string>()
  for (const [property, dbName] of Object.entries(propToDb)) {
    const castAs = columns[dbName]?.cast_as
    if ((DATE_LIKE_CASTS as readonly string[]).includes(castAs as string)) {
      paths.add(property)
    }
  }
  return paths
}

/**
 * Internal token used to gate the {@link WasmEncryptionClient}
 * constructor. Symbols are unique by reference, so external code can't
 * forge one even if they recreate `WasmEncryptionClient` via type
 * inspection.
 */
const INTERNAL_CONSTRUCT = Symbol('cs-wasm-client')

/**
 * WASM encryption client. Returned by {@link Encryption}.
 *
 * Wraps an opaque `wasmNewClient` handle and exposes `encrypt`, `decrypt`,
 * `isEncrypted`, `encryptQuery` / `encryptQueryBulk` for minting v3 query
 * terms (#662, which made searchable encryption reachable on the edge),
 * `bulkEncrypt` / `bulkDecrypt` for single-round-trip list reads and writes
 * (#737), and the model helpers `encryptModel` / `decryptModel` /
 * `bulkEncryptModels` / `bulkDecryptModels` (#742).
 *
 * ## Every fallible method returns a Result
 *
 * `{ data } | { failure }`, with `failure.type` drawn from
 * `EncryptionErrorTypes` — the same contract the native entry honours, and
 * the one `AGENTS.md` states outright: *"Operations return `{ data }` or
 * `{ failure }`. Preserve this shape and error `type` values in
 * `EncryptionErrorTypes`."*
 *
 * This entry THREW until #741. That was drift, not a design decision: nothing
 * about WASM prevents it (`@byteslice/result` is already bundled into
 * `dist/wasm-inline.js` — see `tsup.config.ts` `noExternal`), and the
 * divergence just meant edge code had to be written in a different shape from
 * every other surface, with failures that were easy to miss. Aligned before
 * 1.0 so it never had to be a breaking change afterwards.
 *
 * `isEncrypted` is the one exception, and stays a plain `boolean`: it is a
 * pure predicate with nothing to fail at, exactly as on the native entry.
 *
 * The model helpers run the SAME traversal the native entry uses
 * (`@/encryption/helpers/model-traversal` — shared, not ported, so the two
 * entries cannot drift on which fields get encrypted), and each call is one
 * ZeroKMS round trip regardless of how many fields or models it covers. What
 * still differs from the native surface is deliberate and local: arguments
 * are plain models and a v3 table (no `{ id, … }` envelopes), failures come
 * back as this entry's `{ failure }` Results, and there is no
 * `.withLockContext()` — identity-bound encryption on the edge is configured
 * at client construction via `config.authStrategy` instead (#663 context).
 *
 * Construct via {@link Encryption} — the constructor is private to
 * prevent callers from wrapping arbitrary objects in this type.
 */
export class WasmEncryptionClient {
  /** @internal */
  private readonly client: unknown

  /**
   * @internal Gated by the module-scoped {@link INTERNAL_CONSTRUCT}
   * symbol: external callers can't obtain it, so {@link Encryption} is
   * effectively the only constructor. (A `private` constructor would
   * block {@link Encryption} too, since it lives outside the class.)
   */
  constructor(token: symbol, client: unknown) {
    if (token !== INTERNAL_CONSTRUCT) {
      throw new Error(
        '[encryption]: WasmEncryptionClient cannot be constructed directly — use the Encryption() factory.',
      )
    }
    this.client = client
  }

  async encrypt(
    plaintext: WasmPlaintext,
    opts: EncryptOptions,
  ): Promise<WasmResult<Encrypted>> {
    return wasmResult(async () => {
      const ffiOpts = {
        plaintext,
        table: opts.table.tableName,
        column: getColumnName(opts.column),
      }
      return (await wasmEncrypt(
        // biome-ignore lint/plugin: the FFI handle is an opaque wasm-bindgen pointer with no JS-side type
        this.client as never,
        // biome-ignore lint/plugin: the opts cross the serde boundary, whose shape protect-ffi types as `any`
        ffiOpts as never,
      )) as Encrypted
    }, EncryptionErrorTypes.EncryptionError)
  }

  async decrypt(encrypted: Encrypted): Promise<WasmResult<WasmPlaintext>> {
    return wasmResult(
      async () =>
        (await wasmDecrypt(
          // biome-ignore lint/plugin: the FFI handle is an opaque wasm-bindgen pointer with no JS-side type
          this.client as never,
          // biome-ignore lint/plugin: the opts cross the serde boundary, whose shape protect-ffi types as `any`
          { ciphertext: encrypted } as never,
        )) as WasmPlaintext,
      EncryptionErrorTypes.DecryptionError,
    )
  }

  isEncrypted(value: unknown): boolean {
    return wasmIsEncrypted(value as never)
  }

  /**
   * Encrypt a QUERY TERM (search needle) for a queryable v3 column —
   * equality, free-text match, ORE range, or JSON containment/selector.
   *
   * The returned term is **ciphertext-free**: it is matched against stored
   * envelopes, never decrypted, so it is safe to log-scrub less aggressively
   * than storage payloads (though it still derives from the plaintext).
   * Interpolate it as a parameter and cast to the column's
   * `eql_v3.query_<domain>` type to reach the indexed operators — the domain
   * suffix mirrors the storage domain (`eql_v3_text_eq` →
   * `eql_v3.query_text_eq`; irregular: `eql_v3_json_search` → `eql_v3.query_json`).
   *
   * @example Equality (unique index)
   * ```ts
   * const term = await client.encryptQuery("alice@example.com", {
   *   table: users, column: users.email, queryType: "equality",
   * })
   * if (term.failure) throw new Error(term.failure.message)
   * // postgres-js — bind the unwrapped term, not the Result:
   * sql`SELECT * FROM users
   *     WHERE email = ${term.data}::jsonb::eql_v3.query_text_eq`
   * ```
   *
   * @example Free-text match (bloom index — one-sided, fuzzy)
   * ```ts
   * const term = await client.encryptQuery("needle", {
   *   table: users, column: users.bio, queryType: "freeTextSearch",
   * })
   * if (term.failure) throw new Error(term.failure.message)
   * sql`SELECT * FROM users
   *     WHERE eql_v3.matches(bio, ${term.data}::jsonb::eql_v3.query_text_search)`
   * ```
   *
   * @example Range / ORDER BY (ORE index)
   * ```ts
   * const term = await client.encryptQuery(42, {
   *   table: users, column: users.age, queryType: "orderAndRange",
   * })
   * if (term.failure) throw new Error(term.failure.message)
   * sql`SELECT * FROM users
   *     WHERE eql_v3.gte(age, ${term.data}::jsonb::eql_v3.query_integer_ord)`
   * ```
   *
   * @example Encrypted JSON — containment and JSONPath selector
   * ```ts
   * // Object value → containment needle (a v3 envelope):
   * const contains = await client.encryptQuery({ role: "admin" }, {
   *   table: users, column: users.prefs, queryType: "searchableJson",
   * })
   * if (contains.failure) throw new Error(contains.failure.message)
   * sql`SELECT * FROM users
   *     WHERE prefs @> ${contains.data}::jsonb::eql_v3.query_json`
   *
   * // String value → JSONPath selector. NOTE: v3 has no encrypted-selector
   * // envelope — this returns the BARE selector-hash string, bound as the
   * // text argument of -> / ->>:
   * const selector = await client.encryptQuery("$.role", {
   *   table: users, column: users.prefs, queryType: "searchableJson",
   * })
   * if (selector.failure) throw new Error(selector.failure.message)
   * sql`SELECT prefs -> ${selector.data} FROM users`
   * ```
   *
   * @param plaintext - The search needle. `null`/`undefined` returns `null`
   *   without contacting ZeroKMS (nothing to search for), mirroring the
   *   native client.
   * @param opts - Table, column, and (optionally) which index to target —
   *   see {@link WasmEncryptQueryOptions.queryType} for the inference rules.
   * @returns `{ data }` with the v3 query term (or `null` for null
   *   plaintext), or `{ failure }` when the requested `queryType` isn't
   *   configured on the column, the column has no indexes at all, the value
   *   fails the same pre-flight validation the native client runs (NaN /
   *   Infinity / out-of-int64 bigint, or a numeric value against a
   *   `freeTextSearch` index), or encryption fails.
   */
  async encryptQuery(
    plaintext: WasmPlaintext,
    opts: WasmEncryptQueryOptions,
  ): Promise<WasmResult<EncryptedQuery | null>> {
    return wasmResult(async () => {
      if (plaintext === null || plaintext === undefined) return null
      return (await wasmEncryptQuery(
        // biome-ignore lint/plugin: the FFI handle is an opaque wasm-bindgen pointer with no JS-side type
        this.client as never,
        // biome-ignore lint/plugin: the term crosses the serde boundary, whose shape protect-ffi types as `any`
        toFfiQueryTerm(plaintext, opts) as never,
      )) as EncryptedQuery
    }, EncryptionErrorTypes.EncryptionError)
  }

  /**
   * Batch form of {@link encryptQuery} — one ZeroKMS round trip for many
   * terms, which is the shape query builders want (encrypt every needle in
   * a WHERE clause together).
   *
   * Position-stable: the result array is index-aligned with `terms`, and a
   * `null`/`undefined` value yields `null` at the same index (an all-null
   * batch short-circuits without calling ZeroKMS). Terms may mix query
   * types and columns freely.
   *
   * @example
   * ```ts
   * const terms = await client.encryptQueryBulk([
   *   { value: "alice@example.com", table: users, column: users.email,
   *     queryType: "equality" },
   *   { value: "needle", table: users, column: users.bio,
   *     queryType: "freeTextSearch" },
   * ])
   * if (terms.failure) throw new Error(terms.failure.message)
   * const [emailEq, bioMatch] = terms.data
   * ```
   *
   * @param terms - The needles to encrypt; see {@link WasmQueryTerm}.
   * @returns `{ data }` with an index-aligned array of v3 query terms (`null`
   *   per null value), or `{ failure }` — the first invalid term aborts the
   *   batch, as {@link encryptQuery}.
   */
  async encryptQueryBulk(
    terms: readonly WasmQueryTerm[],
  ): Promise<WasmResult<Array<EncryptedQuery | null>>> {
    return wasmResult(async () => {
      const { out, placed } = await runBatch<WasmQueryTerm, EncryptedQuery>(
        'encryptQueryBulk',
        terms,
        (term) => term.value !== null && term.value !== undefined,
        async (live) =>
          // The FFI's batch field is `queries` (matching the native
          // ffiEncryptQueryBulk call in packages/protect).
          (await wasmEncryptQueryBulk(
            // biome-ignore lint/plugin: the FFI handle is an opaque wasm-bindgen pointer with no JS-side type
            this.client as never,
            // biome-ignore lint/plugin: the batch crosses the serde boundary, whose shape protect-ffi types as `any`
            {
              queries: live.map((term) => toFfiQueryTerm(term.value, term)),
            } as never,
          )) as EncryptedQuery[],
      )
      for (const { result, at } of placed) out[at] = result
      return out
    }, EncryptionErrorTypes.EncryptionError)
  }

  /**
   * Encrypt many storage values in ONE ZeroKMS round trip.
   *
   * Without this, an edge function writing N rows pays N round trips — the
   * property `AGENTS.md` calls out ("prefer bulk operations to exercise
   * ZeroKMS bulk speed") was unreachable from the WASM entry entirely (#737).
   *
   * Position-stable: the result is index-aligned with `items`, and a
   * `null`/`undefined` plaintext yields `null` at the same index without
   * being sent to ZeroKMS (an all-null batch short-circuits entirely).
   * Entries may mix tables and columns freely — see {@link WasmBulkPlaintext}.
   *
   * ## How this differs from the native `bulkEncrypt`
   *
   * The failure shape is the SAME — `{ data } | { failure }`, per
   * `AGENTS.md` — but the batch shape differs: the Node entry takes one
   * column for the whole batch and wraps values in `{ id, plaintext }`
   * envelopes, where this takes per-item routing and plain values.
   *
   * That divergence is about capability, not convention. Per-item routing is
   * what makes the round-trip saving real (one call covers several columns
   * across many rows), and the `id` bookkeeping buys nothing once positions
   * are stable — the FFI's `EncryptPayload` has no `id` field, so the native
   * one is dropped at the boundary anyway.
   *
   * @example Encrypting a page of rows in one call
   * ```ts
   * const rows = [{ email: "a@b.com", bio: "hi" }, { email: "c@d.com", bio: "yo" }]
   * const encrypted = await client.bulkEncrypt(
   *   rows.flatMap((r) => [
   *     { plaintext: r.email, table: users, column: users.email },
   *     { plaintext: r.bio,   table: users, column: users.bio },
   *   ]),
   * )
   * if (encrypted.failure) throw new Error(encrypted.failure.message)
   * // encrypted.data[0] = email of row 0, [1] = bio of row 0, …
   * ```
   *
   * @param items - Values to encrypt, each with its own table and column.
   * @returns `{ data }` with an index-aligned array of storage payloads
   *   (`null` per null input), or `{ failure }`. The batch is all-or-nothing:
   *   ZeroKMS rejects the call as a whole, so there is no per-item error to
   *   report (unlike {@link bulkDecrypt}, whose FFI primitive IS fallible).
   */
  async bulkEncrypt(
    items: readonly WasmBulkPlaintext[],
  ): Promise<WasmResult<Array<Encrypted | null>>> {
    return wasmResult(async () => {
      const { out, placed } = await runBatch<WasmBulkPlaintext, Encrypted>(
        'bulkEncrypt',
        items,
        (item) => item.plaintext !== null && item.plaintext !== undefined,
        async (live) =>
          (await wasmEncryptBulk(
            // biome-ignore lint/plugin: the FFI handle is an opaque wasm-bindgen pointer with no JS-side type
            this.client as never,
            // biome-ignore lint/plugin: the batch crosses the serde boundary, whose shape protect-ffi types as `any`
            {
              plaintexts: live.map((item) => ({
                plaintext: item.plaintext,
                table: item.table.tableName,
                column: getColumnName(item.column),
              })),
            } as never,
          )) as Encrypted[],
      )
      for (const { result, at } of placed) out[at] = result
      return out
    }, EncryptionErrorTypes.EncryptionError)
  }

  /**
   * Decrypt many stored payloads in ONE ZeroKMS round trip.
   *
   * This is the half that matters most on the edge: rendering a list of N
   * encrypted rows cost N round trips before this existed, which is what made
   * list endpoints impractical on Deno / Workers (#737).
   *
   * Position-stable, same contract as {@link bulkEncrypt}: index-aligned with
   * `ciphertexts`, `null`/`undefined` passes through as `null` without
   * reaching ZeroKMS, and an all-null batch short-circuits.
   *
   * ## Partial failure
   *
   * The underlying primitive is `decryptBulkFallible`, which reports success
   * or failure PER ITEM — one undecryptable row does not fail the call at the
   * FFI level. Any failure still collapses the whole call into a single
   * `{ failure }`, but its message names EVERY failed index and reason rather
   * than surfacing the first and discarding the rest. So a caller debugging
   * one bad row in a page of 50 learns which row, and that the other 49 were
   * fine.
   *
   * (A per-item `Result[]` would preserve the partial success too, and is
   * worth considering if callers ask for it — but it is a different return
   * type from every other method here, so it is not the default.)
   *
   * @example
   * ```ts
   * const rows = await sql`SELECT email FROM users LIMIT 50`
   * const emails = await client.bulkDecrypt(rows.map((r) => r.email))
   * if (emails.failure) throw new Error(emails.failure.message)
   * // one ZeroKMS call, not 50
   * ```
   *
   * @param ciphertexts - Stored payloads; `null`/`undefined` entries allowed.
   * @returns `{ data }` with an index-aligned array of plaintexts (`null` per
   *   null input), or `{ failure }` naming each failing index and its reason.
   */
  async bulkDecrypt(
    ciphertexts: readonly (Encrypted | null | undefined)[],
  ): Promise<WasmResult<Array<WasmPlaintext | null>>> {
    return wasmResult(async () => {
      const { out, placed } = await runBatch<
        Encrypted,
        FallibleDecryptItem,
        WasmPlaintext
      >(
        'bulkDecrypt',
        ciphertexts as readonly Encrypted[],
        (ciphertext) => ciphertext !== null && ciphertext !== undefined,
        async (live) =>
          (await wasmDecryptBulkFallible(
            // biome-ignore lint/plugin: the FFI handle is an opaque wasm-bindgen pointer with no JS-side type
            this.client as never,
            // biome-ignore lint/plugin: the batch crosses the serde boundary, whose shape protect-ffi types as `any`
            {
              ciphertexts: live.map((ciphertext) => ({ ciphertext })),
            } as never,
          )) as FallibleDecryptItem[],
      )

      // Collect every failure before raising: the FFI already did the work for
      // the rows that succeeded, so reporting only the first would discard
      // information the caller paid for. The throw is caught by `withResult`
      // and surfaces as a single `{ failure }` naming every bad index.
      //
      // Each line carries the per-item `code` the FFI supplies. It cannot go
      // on `failure.code` — a batch has no single code, and inventing one from
      // the first failure would be wrong — but dropping it entirely would lose
      // the only machine-meaningful part of a row's error.
      const failures: string[] = []
      for (const { result, at } of placed) {
        if ('error' in result) {
          const code = result.code ? ` (${result.code})` : ''
          failures.push(`  [${at}]${code}: ${result.error}`)
          continue
        }
        out[at] = result.data
      }

      if (failures.length > 0) {
        throw new Error(
          `bulkDecrypt failed for ${failures.length} of ${placed.length} payload(s) (indices are into the input array):\n${failures.join('\n')}`,
        )
      }
      return out
    }, EncryptionErrorTypes.DecryptionError)
  }

  /**
   * Encrypt a model's schema-declared fields in ONE ZeroKMS round trip.
   *
   * Walks `model` against `table`'s columns — matched by JS property name,
   * nested fields via a column's dotted path (`'profile.ssn'`) — and encrypts
   * exactly the declared fields. Everything else passes through untouched,
   * and a `null`/`undefined` schema field is preserved as-is without
   * reaching ZeroKMS. The traversal is the native entry's own, shared from
   * `@/encryption/helpers/model-traversal` (#742): a column added to the
   * schema is picked up by construction, instead of by remembering to extend
   * a hand-written `bulkEncrypt` mapping — the failure mode of that mapping
   * is a field that silently persists in PLAINTEXT.
   *
   * `Date` plaintexts (date/timestamp domains) are sent as ISO-8601 strings —
   * {@link WasmPlaintext} carries no `Date` across the WASM serde boundary —
   * and {@link decryptModel} rebuilds them into `Date` values on the way out.
   *
   * @example
   * ```ts
   * const row = await client.encryptModel(
   *   { id: 1, email: "alice@example.com", verified: true },
   *   users,
   * )
   * if (row.failure) throw new Error(row.failure.message)
   * // row.data = { id: 1, email: <EQL envelope>, verified: true }
   * ```
   */
  async encryptModel<
    Table extends AnyV3Table,
    T extends Record<string, unknown>,
  >(
    model: V3ModelInput<Table, T>,
    table: Table,
  ): Promise<WasmResult<V3EncryptedModel<Table, T>>> {
    return wasmResult(async () => {
      const [encrypted] = await this.encryptModelsBatch(
        [model as Record<string, unknown>],
        table,
        'encryptModel',
      )
      return encrypted as V3EncryptedModel<Table, T>
    }, EncryptionErrorTypes.EncryptionError)
  }

  /**
   * Encrypt many models in ONE ZeroKMS round trip — {@link encryptModel}'s
   * traversal applied per model, with every collected field across every
   * model batched into a single FFI call. N models × M columns is still one
   * crossing, the same economics as {@link bulkEncrypt}.
   *
   * The result array is index-aligned with `models`. An empty input returns
   * `{ data: [] }` without contacting ZeroKMS.
   */
  async bulkEncryptModels<
    Table extends AnyV3Table,
    T extends Record<string, unknown>,
  >(
    models: Array<V3ModelInput<Table, T>>,
    table: Table,
  ): Promise<WasmResult<Array<V3EncryptedModel<Table, T>>>> {
    return wasmResult(
      async () =>
        (await this.encryptModelsBatch(
          models as Record<string, unknown>[],
          table,
          'bulkEncryptModels',
        )) as Array<V3EncryptedModel<Table, T>>,
      EncryptionErrorTypes.EncryptionError,
    )
  }

  /**
   * Decrypt every encrypted payload in a model, in ONE ZeroKMS round trip.
   *
   * Schema-blind on the way in — any value that IS an EQL envelope is
   * decrypted, wherever it nests; everything else (nulls included) passes
   * through untouched. Schema-aware on the way out: `table`'s date-like
   * columns (`date` / `timestamp` domains) are rebuilt into `Date` values
   * from their `cast_as`, matching the native v3 client's reconstruction, so
   * a model round-trips `Date` → `Date`.
   *
   * ## Partial failure
   *
   * Built on the same per-item-fallible primitive as {@link bulkDecrypt}:
   * one undecryptable field does not mask the rest. Any failure collapses to
   * a single `{ failure }` whose message names EVERY failed field by its
   * path in the model (e.g. `profile.ssn`), with its per-item code.
   */
  async decryptModel<
    Table extends AnyV3Table,
    T extends Record<string, unknown>,
  >(model: T, table: Table): Promise<WasmResult<V3DecryptedModel<Table, T>>> {
    return wasmResult(async () => {
      const [decrypted] = await this.decryptModelsBatch(
        [model as Record<string, unknown>],
        table,
        'decryptModel',
        (_modelIndex, fieldKey) => fieldKey,
      )
      return decrypted as V3DecryptedModel<Table, T>
    }, EncryptionErrorTypes.DecryptionError)
  }

  /**
   * Decrypt many models in ONE ZeroKMS round trip — {@link decryptModel}
   * across a list, which is the shape a page of database rows arrives in.
   * The result array is index-aligned with `models`; an empty input returns
   * `{ data: [] }` without contacting ZeroKMS. Failures are reported for
   * every bad field across the whole batch, labelled `[model <i>] <field>`.
   */
  async bulkDecryptModels<
    Table extends AnyV3Table,
    T extends Record<string, unknown>,
  >(
    models: T[],
    table: Table,
  ): Promise<WasmResult<Array<V3DecryptedModel<Table, T>>>> {
    return wasmResult(
      async () =>
        (await this.decryptModelsBatch(
          models as Record<string, unknown>[],
          table,
          'bulkDecryptModels',
          (modelIndex, fieldKey) => `[model ${modelIndex}] ${fieldKey}`,
        )) as Array<V3DecryptedModel<Table, T>>,
      EncryptionErrorTypes.DecryptionError,
    )
  }

  /**
   * The shared model-encrypt engine behind {@link encryptModel} and
   * {@link bulkEncryptModels}: run the shared traversal per model, send every
   * collected field in one `encryptBulk` crossing, and rebuild each model
   * with its encrypted fields set back in place (null fields verbatim,
   * passthrough fields untouched).
   *
   * Results pair with fields positionally — `fields` flattens the traversal's
   * per-model maps in the order the walk visited them — so the count is
   * guarded by {@link assertBatchLength} exactly as the value-level batches
   * guard theirs through {@link runBatch}.
   */
  private async encryptModelsBatch(
    models: Record<string, unknown>[],
    table: AnyV3Table,
    op: string,
  ): Promise<Record<string, unknown>[]> {
    const { otherFields, operationFields, nullFields } =
      prepareBulkModelsForOperation(models, table)
    const { toColumnName } = resolveEncryptColumnMap(table)

    const fields = operationFields.flatMap((modelFields, modelIndex) =>
      Object.entries(modelFields).map(([fieldKey, value]) => ({
        modelIndex,
        fieldKey,
        value,
      })),
    )

    let results: Encrypted[] = []
    if (fields.length > 0) {
      results = (await wasmEncryptBulk(
        // biome-ignore lint/plugin: the FFI handle is an opaque wasm-bindgen pointer with no JS-side type
        this.client as never,
        // biome-ignore lint/plugin: the batch crosses the serde boundary, whose shape protect-ffi types as `any`
        {
          plaintexts: fields.map(({ fieldKey, value }) => ({
            // Date → ISO-8601 here, NOT pass-through: a JS Date has no
            // enumerable properties, so the wasm serde would carry it as `{}`
            // — silent corruption of every date column. The model decrypt
            // engine rebuilds the Date on the way out.
            plaintext: value instanceof Date ? value.toISOString() : value,
            table: table.tableName,
            column: toColumnName(fieldKey),
          })),
        } as never,
      )) as Encrypted[]
      assertBatchLength(op, results.length, fields.length)
    }

    return models.map((_, modelIndex) => {
      const rebuilt: Record<string, unknown> = { ...otherFields[modelIndex] }
      for (const [key, value] of Object.entries(nullFields[modelIndex])) {
        setNestedValue(rebuilt, key.split('.'), value)
      }
      fields.forEach((field, i) => {
        if (field.modelIndex !== modelIndex) return
        setNestedValue(rebuilt, field.fieldKey.split('.'), results[i])
      })
      return rebuilt
    })
  }

  /**
   * The shared model-decrypt engine behind {@link decryptModel} and
   * {@link bulkDecryptModels}. The traversal runs WITHOUT a table (it
   * collects every value that is an encrypted payload — decryption needs no
   * schema to find its work); the table drives only the `Date`
   * reconstruction. `label` renders a failed field's coordinate for the
   * aggregate error, so the single-model caller reports `profile.ssn` while
   * the bulk caller reports `[model 2] profile.ssn`.
   */
  private async decryptModelsBatch(
    models: Record<string, unknown>[],
    table: AnyV3Table,
    op: string,
    label: (modelIndex: number, fieldKey: string) => string,
  ): Promise<Record<string, unknown>[]> {
    const { otherFields, operationFields, nullFields } =
      prepareBulkModelsForOperation(models)
    const dateFields = datePropertyPaths(table)

    const fields = operationFields.flatMap((modelFields, modelIndex) =>
      Object.entries(modelFields).map(([fieldKey, value]) => ({
        modelIndex,
        fieldKey,
        value,
      })),
    )

    let results: FallibleDecryptItem[] = []
    if (fields.length > 0) {
      results = (await wasmDecryptBulkFallible(
        // biome-ignore lint/plugin: the FFI handle is an opaque wasm-bindgen pointer with no JS-side type
        this.client as never,
        // biome-ignore lint/plugin: the batch crosses the serde boundary, whose shape protect-ffi types as `any`
        {
          ciphertexts: fields.map(({ value }) => ({ ciphertext: value })),
        } as never,
      )) as FallibleDecryptItem[]
      assertBatchLength(op, results.length, fields.length)
    }

    // Same all-failures-at-once contract as bulkDecrypt, labelled by model
    // field rather than input index — the caller handed us models, so "which
    // field of which model" is the coordinate they can act on.
    const failures: string[] = []
    results.forEach((result, i) => {
      if ('error' in result) {
        const code = result.code ? ` (${result.code})` : ''
        const field = fields[i]
        failures.push(
          `  ${label(field.modelIndex, field.fieldKey)}${code}: ${result.error}`,
        )
      }
    })
    if (failures.length > 0) {
      throw new Error(
        `${op} failed for ${failures.length} of ${fields.length} payload(s):\n${failures.join('\n')}`,
      )
    }

    return models.map((_, modelIndex) => {
      const rebuilt: Record<string, unknown> = { ...otherFields[modelIndex] }
      for (const [key, value] of Object.entries(nullFields[modelIndex])) {
        setNestedValue(rebuilt, key.split('.'), value)
      }
      fields.forEach((field, i) => {
        if (field.modelIndex !== modelIndex) return
        const item = results[i] as { data: WasmPlaintext }
        const plain =
          dateFields.has(field.fieldKey) && item.data != null
            ? new Date(item.data as string | number)
            : item.data
        setNestedValue(rebuilt, field.fieldKey.split('.'), plain)
      })
      return rebuilt
    })
  }
}

/**
 * Initialize a WASM-backed encryption client.
 *
 * Mirrors the Node entry's {@link import('./encryption').Encryption}
 * factory, but constructs the protect-ffi client via the WASM strategy
 * API. Use from Deno / Edge / Workers / Bun.
 */
export async function Encryption(
  config: WasmEncryptionConfig,
): Promise<WasmEncryptionClient> {
  const { schemas, config: clientConfig } = config

  if (!schemas.length) {
    throw new Error(
      '[encryption]: At least one encryptedTable must be provided to initialize the encryption client',
    )
  }

  // The WASM entry is EQL v3 only. The types enforce v3 tables, but a plain-JS
  // caller can bypass that — reject a non-v3 table (one lacking the v3
  // `buildColumnKeyMap` marker) with a clear message rather than pinning the
  // client to v3 wire against a v2 schema and failing opaquely inside the FFI.
  for (const table of schemas) {
    const isV3 = hasBuildColumnKeyMap(table)
    if (!isV3) {
      throw new Error(
        '[encryption]: `@cipherstash/stack/wasm-inline` is EQL v3 only — author schemas with `types` / `encryptedTable` from this entry. (EQL v2 is available on the native `@cipherstash/stack` entry.)',
      )
    }
  }

  const encryptConfig: EncryptConfig = encryptConfigSchema.parse(
    buildEncryptConfig(...schemas),
  )

  const strategy = resolveStrategy(clientConfig)

  // protect-ffi 0.25 takes a single options object with the strategy nested
  // under `strategy` (0.24 passed the strategy as a separate first argument).
  // `eqlVersion: 3` pins the EQL v3 wire format — this entry is v3 only, so
  // every encrypt/query emits v3 (a v2-mode client cannot resolve the concrete
  // `eql_v3_*` domains and would fail every encrypt).
  const client = await wasmNewClient({
    strategy,
    encryptConfig: normalizeCastAs(encryptConfig),
    clientId: clientConfig.clientId,
    clientKey: clientConfig.clientKey,
    eqlVersion: 3,
  } as never)

  // `INTERNAL_CONSTRUCT` is module-scoped, so this factory is the only
  // code that can build a `WasmEncryptionClient` — external callers hit
  // the constructor guard.
  return new WasmEncryptionClient(INTERNAL_CONSTRUCT, client)
}

/**
 * Convert SDK-facing `cast_as` values (`'string'`, `'number'`, …) to the
 * EQL-native variants (`'text'`, `'double'`, …) that the WASM
 * `newClient` accepts.
 *
 * The Node entry of protect-ffi performs this normalization internally
 * via `normalizeEncryptConfig.js`; the WASM bindings do not. Without
 * this, the WASM client rejects an `encryptedColumn('email')` (which
 * defaults to `cast_as: 'string'`) with
 * `unknown variant `string`, expected one of `big_int`, …`.
 *
 * `toEqlCastAs` is exhaustive over the current `CastAs` union; if a new
 * SDK-facing variant is added without updating that switch, this
 * function throws synchronously at startup with a clear message rather
 * than handing `undefined` to the WASM serde (which surfaces as an
 * opaque `unknown variant 'null'` error).
 *
 * @internal exported for unit-test coverage of the drift-guard branch.
 */
export function normalizeCastAs(config: EncryptConfig): unknown {
  const tables: Record<string, Record<string, unknown>> = {}
  for (const [tableName, columns] of Object.entries(config.tables)) {
    const normalised: Record<string, unknown> = {}
    for (const [colName, col] of Object.entries(columns)) {
      if (col.cast_as) {
        const eqlCastAs = toEqlCastAs(col.cast_as as CastAs)
        if (eqlCastAs === undefined) {
          throw new Error(
            `[encryption]: unrecognised cast_as value "${col.cast_as}" on ${tableName}.${colName} — update toEqlCastAs() to map it to an EQL variant.`,
          )
        }
        normalised[colName] = { ...col, cast_as: eqlCastAs }
      } else {
        normalised[colName] = col
      }
    }
    tables[tableName] = normalised
  }
  return { ...config, tables }
}

/**
 * Resolve a column's name structurally. Accepts any column builder exposing
 * `getName()` — v2 `EncryptedColumn` / `EncryptedField` AND v3 column builders
 * (e.g. `EncryptedTextSearchColumn`) alike — matching the structural
 * `BuildableColumn` contract that `EncryptOptions.column` was widened to.
 *
 * An `instanceof EncryptedColumn || EncryptedField` gate would type-check after
 * the widening but throw at runtime for a v3 column, breaking the type promise;
 * resolving the name structurally keeps the wasm-inline encrypt entry honest.
 * The `typeof` check still fails loudly for plain JS callers passing a value
 * that is not a column builder.
 *
 * @internal exported for unit-test coverage.
 */
export function getColumnName(col: EncryptOptions['column']): string {
  if (typeof col?.getName === 'function') {
    return col.getName()
  }
  throw new Error(
    '[encryption]: opts.column must be a column builder exposing getName()',
  )
}

/**
 * Build the FFI term for one query needle — the ONE place the single and
 * bulk paths share, so the subtle parts can't drift between them.
 *
 * Runs the same pre-FFI guards as the native client's query operations
 * (`assertValidNumericValue`, `assertValueIndexCompatibility`): NaN /
 * Infinity / out-of-int64 bigint and numeric-on-match-index fail with the
 * same named errors the Node entry raises, instead of an opaque serde
 * failure — or a silently no-match term — from inside the WASM boundary.
 *
 * Index resolution is the SAME resolver the native client uses
 * (`@/encryption/helpers` is type-only on protect-ffi, so it's
 * WASM-bundle-safe): explicit queryType validated against the column's
 * indexes; v3 ord domains' `ope` swapped in for `orderAndRange`; equality
 * answered via the ordering index on order-capable columns without
 * `unique`; inference priority unique > match > ore/ope > ste_vec.
 *
 * serde on the WASM side rejects explicitly-undefined fields ("invalid
 * type: unit value, expected a string") — OMIT `queryOp` when absent (the
 * native NAPI layer tolerates undefined; the WASM one does not).
 *
 * WasmPlaintext widens Plaintext with `bigint` (carried natively over the
 * WASM boundary); the resolver only `typeof`-inspects the value for
 * ste_vec op inference, so the assertion is safe.
 */
function toFfiQueryTerm(value: WasmPlaintext, opts: WasmEncryptQueryOptions) {
  assertValidNumericValue(value)
  const { indexType, queryOp } = resolveIndexType(
    opts.column,
    opts.queryType,
    value as Plaintext,
  )
  assertValueIndexCompatibility(value, indexType, getColumnName(opts.column))
  return {
    plaintext: value,
    table: opts.table.tableName,
    column: getColumnName(opts.column),
    indexType,
    ...(queryOp ? { queryOp } : {}),
  }
}

// Emit the `config.strategy` → `config.authStrategy` rename warning at most
// once per process so repeated `Encryption()` calls don't spam the console.
// Mirrors the identical latch on the Node entry (`@/encryption`); the two are
// kept separate so the wasm bundle never imports the Node-only module.
let warnedStrategyDeprecated = false
function warnStrategyDeprecated(): void {
  if (warnedStrategyDeprecated) return
  warnedStrategyDeprecated = true
  console.warn(
    '[encryption]: `config.strategy` is deprecated and will be removed in a future release — use `config.authStrategy` instead.',
  )
}

/**
 * Reset the once-per-process deprecation-warning latch. Test-only hook so
 * suites can assert the warning fires deterministically, independent of test
 * ordering.
 * @internal
 */
export function __resetStrategyDeprecationWarningForTests(): void {
  warnedStrategyDeprecated = false
}

/**
 * Resolve the auth strategy for the WASM client from its config: an explicit
 * `config.authStrategy` (or the deprecated `config.strategy` alias), or — for
 * the access-key path — an `AccessKeyStrategy` built from the workspace CRN
 * (region derived from it inside `@cipherstash/auth`). An auth strategy and
 * `accessKey` are mutually exclusive.
 *
 * @internal exported for offline unit coverage of the strategy wiring; the
 * gated Deno e2e (`e2e/wasm/roundtrip.test.ts`) is the only other exercise of
 * this path and it skips without real `CS_*` secrets.
 */
export function resolveStrategy(cfg: WasmClientConfig): WasmAuthStrategy {
  // Honour the deprecated `strategy` alias; `authStrategy` wins when both are
  // set. Warn whenever the deprecated field is present at all so the leftover
  // field gets cleaned up (mirrors the Node entry).
  if (cfg.strategy) {
    warnStrategyDeprecated()
  }
  const authStrategy = cfg.authStrategy ?? cfg.strategy
  // The discriminated union rejects an auth strategy + `accessKey` together at
  // compile time, but JS callers (Deno / plain JS) bypass that — guard at
  // runtime so a conflicting config fails loudly instead of silently
  // preferring one.
  if (authStrategy && cfg.accessKey) {
    // Name the field the caller actually set — `strategy` when only the
    // deprecated alias was used — so the message isn't misleading.
    const field = cfg.authStrategy ? 'authStrategy' : 'strategy'
    throw new Error(
      `[encryption]: \`config.${field}\` and \`config.accessKey\` are mutually exclusive — pass exactly one.`,
    )
  }
  if (authStrategy) return authStrategy
  // No auth strategy → the access-key arm, where `workspaceCrn` and `accessKey`
  // are both required (and so present at runtime); the union widens their
  // static types to `string | undefined`, hence the casts. Guard at runtime
  // so plain JS / Deno callers that bypass the compile-time union fail loudly
  // instead of forwarding `undefined` into `AccessKeyStrategy.create`.
  if (!cfg.workspaceCrn || !cfg.accessKey) {
    throw new Error(
      '[encryption]: `config.workspaceCrn` and `config.accessKey` are required when no auth strategy is provided.',
    )
  }
  // `AccessKeyStrategy.create` takes the full workspace CRN — the region is
  // derived from it inside `@cipherstash/auth`, so the CRN stays the single
  // source of truth with no manual region split. As of `@cipherstash/auth`
  // `0.41` `create` returns a `Result<AccessKeyStrategy, AuthFailure>` rather
  // than throwing — unwrap it and surface a construction failure loudly.
  const result = AccessKeyStrategy.create(cfg.workspaceCrn, cfg.accessKey)
  if (result.failure) {
    throw new Error(
      `[encryption]: failed to construct \`AccessKeyStrategy\` from \`config.workspaceCrn\` / \`config.accessKey\` (${result.failure.type}): ${result.failure.error.message}`,
    )
  }
  return result.data
}
