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
 * const enc = await client.encrypt("alice@example.com", {
 *   column: users.email,
 *   table: users,
 * })
 * const dec = await client.decrypt(enc)
 *
 * // Searchable encryption: mint a ciphertext-free QUERY TERM and cast it
 * // to the column's `eql_v3.query_<domain>` type in SQL to hit the index.
 * const term = await client.encryptQuery("alice@example.com", {
 *   column: users.email,
 *   table: users,
 *   queryType: "freeTextSearch",
 * })
 * // e.g. postgres-js:
 * //   sql`SELECT * FROM users
 * //       WHERE eql_v3.matches(email, ${term}::jsonb::eql_v3.query_text_search)`
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

import { type Result, withResult } from '@byteslice/result'
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
import { getErrorCode } from '@/encryption/helpers/error-code'
import { resolveIndexType } from '@/encryption/helpers/infer-index-type'
import {
  assertValidNumericValue,
  assertValueIndexCompatibility,
} from '@/encryption/helpers/validation'
import { type AnyV3Table, buildEncryptConfig } from '@/eql/v3'
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
function toFailure(
  type: EncryptionError['type'],
): (error: unknown) => EncryptionError {
  return (error: unknown) => ({
    type,
    message: error instanceof Error ? error.message : String(error),
    code: getErrorCode(error),
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
  try {
    // Objects are the other shape wasm-bindgen hands back, so serialize rather
    // than settle for "[object Object]". `JSON.stringify` returns undefined for
    // a symbol/function and throws on a cycle — `String` covers both.
    return new Error(JSON.stringify(ex) ?? String(ex))
  } catch {
    return new Error(String(ex))
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
): Promise<Result<T, EncryptionError>> {
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
 * terms (#662, which made searchable encryption reachable on the edge), and
 * `bulkEncrypt` / `bulkDecrypt` for single-round-trip list reads and writes
 * (#737).
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
 * Still Node-only: the MODEL helpers (`encryptModel` / `decryptModel` and
 * their bulk forms). Those are a separate port — this entry has no
 * single-model operation to build a bulk one on top of, so adding
 * `bulkEncryptModels` alone would be incoherent. Port lazily as Deno / edge
 * consumers demand it; the value-level bulk primitives above are what the
 * round-trip cost actually hangs on.
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
  ): Promise<Result<Encrypted, EncryptionError>> {
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

  async decrypt(
    encrypted: Encrypted,
  ): Promise<Result<WasmPlaintext, EncryptionError>> {
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
   * // postgres-js:
   * sql`SELECT * FROM users
   *     WHERE email = ${term}::jsonb::eql_v3.query_text_eq`
   * ```
   *
   * @example Free-text match (bloom index — one-sided, fuzzy)
   * ```ts
   * const term = await client.encryptQuery("needle", {
   *   table: users, column: users.bio, queryType: "freeTextSearch",
   * })
   * sql`SELECT * FROM users
   *     WHERE eql_v3.matches(bio, ${term}::jsonb::eql_v3.query_text_search)`
   * ```
   *
   * @example Range / ORDER BY (ORE index)
   * ```ts
   * const term = await client.encryptQuery(42, {
   *   table: users, column: users.age, queryType: "orderAndRange",
   * })
   * sql`SELECT * FROM users
   *     WHERE eql_v3.gte(age, ${term}::jsonb::eql_v3.query_integer_ord)`
   * ```
   *
   * @example Encrypted JSON — containment and JSONPath selector
   * ```ts
   * // Object value → containment needle (a v3 envelope):
   * const contains = await client.encryptQuery({ role: "admin" }, {
   *   table: users, column: users.prefs, queryType: "searchableJson",
   * })
   * sql`SELECT * FROM users
   *     WHERE prefs @> ${contains}::jsonb::eql_v3.query_json`
   *
   * // String value → JSONPath selector. NOTE: v3 has no encrypted-selector
   * // envelope — this returns the BARE selector-hash string, bound as the
   * // text argument of -> / ->>:
   * const selector = await client.encryptQuery("$.role", {
   *   table: users, column: users.prefs, queryType: "searchableJson",
   * })
   * sql`SELECT prefs -> ${selector} FROM users`
   * ```
   *
   * @param plaintext - The search needle. `null`/`undefined` returns `null`
   *   without contacting ZeroKMS (nothing to search for), mirroring the
   *   native client.
   * @param opts - Table, column, and (optionally) which index to target —
   *   see {@link WasmEncryptQueryOptions.queryType} for the inference rules.
   * @returns The v3 query term, or `null` for null plaintext.
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
  ): Promise<Result<EncryptedQuery | null, EncryptionError>> {
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
  ): Promise<Result<Array<EncryptedQuery | null>, EncryptionError>> {
    return wasmResult(async () => {
      const live: Array<{ term: WasmQueryTerm; at: number }> = []
      terms.forEach((term, at) => {
        if (term.value !== null && term.value !== undefined)
          live.push({ term, at })
      })
      const out: Array<EncryptedQuery | null> = terms.map(() => null)
      if (live.length === 0) return out

      const ffiTerms = live.map(({ term }) => toFfiQueryTerm(term.value, term))
      // The FFI's batch field is `queries` (matching the native
      // ffiEncryptQueryBulk call in packages/protect).
      const encrypted = (await wasmEncryptQueryBulk(
        // biome-ignore lint/plugin: the FFI handle is an opaque wasm-bindgen pointer with no JS-side type
        this.client as never,
        // biome-ignore lint/plugin: the batch crosses the serde boundary, whose shape protect-ffi types as `any`
        {
          queries: ffiTerms,
        } as never,
      )) as EncryptedQuery[]

      assertBatchLength('encryptQueryBulk', encrypted.length, live.length)

      encrypted.forEach((value, i) => {
        const slot = live[i]
        if (slot) out[slot.at] = value
      })
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
  ): Promise<Result<Array<Encrypted | null>, EncryptionError>> {
    return wasmResult(async () => {
      const live: Array<{ item: WasmBulkPlaintext; at: number }> = []
      items.forEach((item, at) => {
        if (item.plaintext !== null && item.plaintext !== undefined)
          live.push({ item, at })
      })
      const out: Array<Encrypted | null> = items.map(() => null)
      if (live.length === 0) return out

      const encrypted = (await wasmEncryptBulk(
        // biome-ignore lint/plugin: the FFI handle is an opaque wasm-bindgen pointer with no JS-side type
        this.client as never,
        // biome-ignore lint/plugin: the batch crosses the serde boundary, whose shape protect-ffi types as `any`
        {
          plaintexts: live.map(({ item }) => ({
            plaintext: item.plaintext,
            table: item.table.tableName,
            column: getColumnName(item.column),
          })),
        } as never,
      )) as Encrypted[]

      // Results are matched to inputs BY POSITION (the FFI payload carries no
      // correlation id). A length mismatch would silently leave trailing slots
      // null — indistinguishable from "this row had no value" — so treat it as
      // the contract violation it is rather than returning plausible-looking
      // data.
      assertBatchLength('bulkEncrypt', encrypted.length, live.length)

      encrypted.forEach((value, i) => {
        const slot = live[i]
        if (slot) out[slot.at] = value
      })
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
  ): Promise<Result<Array<WasmPlaintext | null>, EncryptionError>> {
    return wasmResult(async () => {
      const live: Array<{ ciphertext: Encrypted; at: number }> = []
      ciphertexts.forEach((ciphertext, at) => {
        if (ciphertext !== null && ciphertext !== undefined)
          live.push({ ciphertext, at })
      })
      const out: Array<WasmPlaintext | null> = ciphertexts.map(() => null)
      if (live.length === 0) return out

      const results = (await wasmDecryptBulkFallible(
        // biome-ignore lint/plugin: the FFI handle is an opaque wasm-bindgen pointer with no JS-side type
        this.client as never,
        // biome-ignore lint/plugin: the batch crosses the serde boundary, whose shape protect-ffi types as `any`
        {
          ciphertexts: live.map(({ ciphertext }) => ({ ciphertext })),
        } as never,
      )) as Array<{ data: WasmPlaintext } | { error: string; code?: string }>

      // Positional matching, same contract as `bulkEncrypt` — see there.
      assertBatchLength('bulkDecrypt', results.length, live.length)

      // Collect every failure before raising: the FFI already did the work for
      // the rows that succeeded, so reporting only the first would discard
      // information the caller paid for. The throw is caught by `withResult`
      // and surfaces as a single `{ failure }` naming every bad index.
      const failures: string[] = []
      results.forEach((result, i) => {
        const slot = live[i]
        if (!slot) return
        if ('error' in result) {
          failures.push(`  [${slot.at}]: ${result.error}`)
          return
        }
        out[slot.at] = result.data
      })

      if (failures.length > 0) {
        throw new Error(
          `bulkDecrypt failed for ${failures.length} of ${live.length} payload(s) (indices are into the input array):\n${failures.join('\n')}`,
        )
      }
      return out
    }, EncryptionErrorTypes.DecryptionError)
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
    const isV3 =
      typeof (table as { buildColumnKeyMap?: unknown }).buildColumnKeyMap ===
      'function'
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
