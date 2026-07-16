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
 * //       WHERE eql_v3.contains(email, ${term}::jsonb::eql_v3.query_text_search)`
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

import {
  AccessKeyStrategy,
  type OidcFederationStrategy,
} from '@cipherstash/auth/wasm-inline'
import {
  decrypt as wasmDecrypt,
  encrypt as wasmEncrypt,
  encryptQuery as wasmEncryptQuery,
  encryptQueryBulk as wasmEncryptQueryBulk,
  isEncrypted as wasmIsEncrypted,
  newClient as wasmNewClient,
} from '@cipherstash/protect-ffi/wasm-inline'
import { type AnyV3Table, buildEncryptConfig } from '@/eql/v3'
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
  QueryTypeName,
} from '@/types'
import { queryTypeToFfi, queryTypeToQueryOp } from '@/types'

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
 * Resolve the FFI `{ indexType, queryOp }` for a query term. A local port of
 * the native client's `resolveIndexType` (packages/protect
 * `ffi/helpers/infer-index-type.ts`) — this module deliberately never
 * imports `@cipherstash/protect` (it would drag the Node-only native FFI
 * into the WASM bundle), so the ~40 lines live here. Keep the two in
 * behavioural lockstep.
 */
function resolveQueryIndex(
  column: BuildableV3QueryableColumn,
  queryType: QueryTypeName | undefined,
  plaintext: WasmPlaintext | null,
): { indexType: string; queryOp?: string } {
  const indexes = column.build().indexes ?? {}
  const has = (k: string) =>
    (indexes as Record<string, unknown>)[k] !== undefined

  const stevecOp = () =>
    typeof plaintext === 'string' ? 'ste_vec_selector' : 'ste_vec_term'

  if (queryType) {
    const indexType = queryTypeToFfi[queryType]
    if (!has(indexType)) {
      throw new Error(
        `[encryption]: index type "${indexType}" is not configured on column "${column.getName()}"`,
      )
    }
    if (queryType === 'searchableJson') {
      return plaintext === null || plaintext === undefined
        ? { indexType }
        : { indexType, queryOp: stevecOp() }
    }
    const mappedOp = queryTypeToQueryOp[queryType]
    return mappedOp ? { indexType, queryOp: mappedOp } : { indexType }
  }

  // Inference priority mirrors the native client: unique > match > ore > ste_vec.
  const inferred = (['unique', 'match', 'ore', 'ste_vec'] as const).find(has)
  if (!inferred) {
    throw new Error(
      `[encryption]: column "${column.getName()}" has no indexes configured — nothing to query`,
    )
  }
  if (inferred === 'ste_vec' && plaintext !== null && plaintext !== undefined) {
    return { indexType: inferred, queryOp: stevecOp() }
  }
  return { indexType: inferred }
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
 * `isEncrypted`, and — since #662 made searchable encryption reachable on
 * the edge — `encryptQuery` / `encryptQueryBulk` for minting v3 query
 * terms. Remaining surface (bulk encrypt/decrypt, model helpers) lives on
 * the Node entry — port lazily as Deno / edge consumers demand it.
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
  ): Promise<Encrypted> {
    const ffiOpts = {
      plaintext,
      table: opts.table.tableName,
      column: getColumnName(opts.column),
    }
    return (await wasmEncrypt(
      this.client as never,
      ffiOpts as never,
    )) as Encrypted
  }

  async decrypt(encrypted: Encrypted): Promise<WasmPlaintext> {
    return (await wasmDecrypt(
      this.client as never,
      {
        ciphertext: encrypted,
      } as never,
    )) as WasmPlaintext
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
   * `eql_v3.query_text_eq`; irregular: `eql_v3_json` → `eql_v3.query_jsonb`).
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
   *     WHERE eql_v3.contains(bio, ${term}::jsonb::eql_v3.query_text_search)`
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
   * // Object value → containment needle:
   * const contains = await client.encryptQuery({ role: "admin" }, {
   *   table: users, column: users.prefs, queryType: "searchableJson",
   * })
   * // String value → JSONPath selector:
   * const selector = await client.encryptQuery("$.role", {
   *   table: users, column: users.prefs, queryType: "searchableJson",
   * })
   * ```
   *
   * @param plaintext - The search needle. `null`/`undefined` returns `null`
   *   without contacting ZeroKMS (nothing to search for), mirroring the
   *   native client.
   * @param opts - Table, column, and (optionally) which index to target —
   *   see {@link WasmEncryptQueryOptions.queryType} for the inference rules.
   * @returns The v3 query term, or `null` for null plaintext.
   * @throws When the requested `queryType` isn't configured on the column,
   *   the column has no indexes at all, or encryption fails. Errors THROW,
   *   consistent with this surface's `encrypt`/`decrypt` (the native
   *   entry's `{ data } | { failure }` envelope lives on the Node client
   *   only).
   */
  async encryptQuery(
    plaintext: WasmPlaintext | null,
    opts: WasmEncryptQueryOptions,
  ): Promise<EncryptedQuery | null> {
    if (plaintext === null || plaintext === undefined) return null
    const { indexType, queryOp } = resolveQueryIndex(
      opts.column,
      opts.queryType,
      plaintext,
    )
    // serde on the WASM side rejects explicitly-undefined fields ("invalid
    // type: unit value, expected a string") — OMIT queryOp when absent
    // (the native NAPI layer tolerates undefined; the WASM one does not).
    return (await wasmEncryptQuery(
      this.client as never,
      {
        plaintext,
        table: opts.table.tableName,
        column: getColumnName(opts.column),
        indexType,
        ...(queryOp ? { queryOp } : {}),
      } as never,
    )) as EncryptedQuery
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
   * const [emailEq, bioMatch] = await client.encryptQueryBulk([
   *   { value: "alice@example.com", table: users, column: users.email,
   *     queryType: "equality" },
   *   { value: "needle", table: users, column: users.bio,
   *     queryType: "freeTextSearch" },
   * ])
   * ```
   *
   * @param terms - The needles to encrypt; see {@link WasmQueryTerm}.
   * @returns Index-aligned array of v3 query terms (or `null` per null value).
   * @throws As {@link encryptQuery} — the first invalid term aborts the batch.
   */
  async encryptQueryBulk(
    terms: readonly WasmQueryTerm[],
  ): Promise<Array<EncryptedQuery | null>> {
    const live: Array<{ term: WasmQueryTerm; at: number }> = []
    terms.forEach((term, at) => {
      if (term.value !== null && term.value !== undefined)
        live.push({ term, at })
    })
    const out: Array<EncryptedQuery | null> = terms.map(() => null)
    if (live.length === 0) return out

    const ffiTerms = live.map(({ term }) => {
      const { indexType, queryOp } = resolveQueryIndex(
        term.column,
        term.queryType,
        term.value,
      )
      return {
        plaintext: term.value,
        table: term.table.tableName,
        column: getColumnName(term.column),
        indexType,
        // See the single-term path: WASM serde rejects undefined fields.
        ...(queryOp ? { queryOp } : {}),
      }
    })
    // The FFI's batch field is `queries` (matching the native
    // ffiEncryptQueryBulk call in packages/protect).
    const encrypted = (await wasmEncryptQueryBulk(
      this.client as never,
      {
        queries: ffiTerms,
      } as never,
    )) as EncryptedQuery[]
    encrypted.forEach((value, i) => {
      const slot = live[i]
      if (slot) out[slot.at] = value
    })
    return out
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
