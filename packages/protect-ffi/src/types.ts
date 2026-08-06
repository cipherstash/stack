/**
 * Wire-shape types for the CipherStash client boundary.
 *
 * These describe what the Rust core accepts and returns. They are NOT specific
 * to a binding: `crates/protect-ffi/src/wasm.rs` deserializes each `opts` into
 * exactly the same Rust struct the Neon entry does (`EncryptOptions`,
 * `DecryptBulkOptions`, …) and calls the same `do_*` helper, so the accepted
 * shape is identical by construction.
 *
 * They live in their own module, rather than in `index.cts`, so that BOTH
 * entries can name them. `index.cts` re-exports every one of them, so the
 * Node-API surface is unchanged; the wasm `.d.ts` imports them by relative
 * path from the `typescript_custom_section` in
 * `crates/protect-ffi/src/wasm.rs`, which wasm-bindgen emits verbatim into
 * `dist/wasm/protect_ffi.d.ts`. Before that split they existed only in the
 * Node-API declarations, which meant the wasm build typed every `opts` as
 * `any` — no checking on that path at all — and any consumer wanting the real
 * shapes had to import from the entry that loads a native binary.
 * See #142.
 *
 * Nothing here may import a module with a runtime side effect. Types are
 * erased, but the wasm `.d.ts` resolves this file, so a value import would
 * put the Neon loader into the type graph of the build that exists to avoid
 * it.
 */

import type { CredentialOpts } from './credentials.js'
import type { EncryptedV3 } from './eql-v3.js'
import type { ProtectErrorCode } from './errors.js'

export type DecryptResult =
  | { data: JsPlaintext }
  | { error: string; code?: ProtectErrorCode }

export type EncryptPayload = {
  plaintext: JsPlaintext
  column: string
  table: string
  lockContext?: Context
}

export type BulkDecryptPayload = {
  ciphertext: EncryptedPayload
  lockContext?: Context
}

export type Context = {
  identityClaim: string[]
}

/**
 * EQL v2.3 **storage** payload — the shape persisted in an `eql_v2_encrypted`
 * column. Returned by {@link encrypt} / {@link encryptBulk}; the only shape
 * {@link decrypt} accepts.
 *
 * Discriminated on `k`. A storage payload always carries the ciphertext — `c`
 * on the scalar variant, or `sv[0].c` on the STE-vector variant. Query payloads
 * carry no ciphertext and are a separate type — see {@link EncryptedQuery}.
 *
 * ```ts
 * if (payload.k === 'sv') {
 *   payload.sv.forEach(...)
 * }
 * ```
 */
export type Encrypted = EncryptedScalar | EncryptedSteVec

/**
 * A stored payload in EITHER wire format: EQL v2.3 ({@link Encrypted}) or
 * EQL v3 ({@link EncryptedV3}). {@link encrypt} / {@link encryptBulk} return
 * the format selected by the client's `eqlVersion`; {@link decrypt} accepts
 * both regardless of `eqlVersion` (data-migration scenarios).
 */
export type EncryptedPayload = Encrypted | EncryptedV3

/** Scalar EQL v2.3 storage payload (`k: "ct"`). */
export type EncryptedScalar = {
  k: 'ct'
  /** EQL schema version */
  v: number
  /** Table and column identifier */
  i: { t: string; c: string }
  /** Encrypted ciphertext (mp_base85). Always present on a storage payload. */
  c: string
  /** HMAC-SHA256 term — present when a `unique` index is configured. */
  hm?: string
  /** Bloom filter (set bit positions) — present when a `match` index is configured. */
  bf?: number[]
  /** Block ORE u64_8_256 term — present when an `ore` index is configured. */
  ob?: string[]
}

/**
 * STE-vector EQL v2.3 storage payload (`k: "sv"`). Carries the per-selector
 * entries in `sv`; the root document ciphertext lives at `sv[0].c`.
 */
export type EncryptedSteVec = {
  k: 'sv'
  v: number
  i: { t: string; c: string }
  /** EQL v3 document key header. Absent on legacy v2 SteVec payloads. */
  h?: string
  /** Per-selector entries; root document ciphertext lives at `sv[0].c`. */
  sv: [SteVecEntry, ...SteVecEntry[]]
  s?: never
}

/**
 * EQL v2.3 **query** payload — an encrypted search term. Returned, alongside
 * {@link Encrypted}, by {@link encryptQuery} / {@link encryptQueryBulk}.
 *
 * Unlike a storage payload, a query payload carries no ciphertext (`c`): it is
 * matched against stored values, never decrypted. It must not be passed to
 * {@link decrypt}.
 *
 * This covers scalar terms, path selectors, exact-value selector needles, and
 * JSON ordering terms. New SteVec storage is v3-only; the v2 forms remain in
 * the public input union so legacy ciphertexts can still be decrypted.
 */
export type EncryptedQuery =
  | EncryptedScalarQuery
  | EncryptedSteVecSelector
  | EncryptedSteVecQuery

export type EncryptedSteVecQuery = {
  k: 'sv'
  v: number
  i: { t: string; c: string }
  c?: never
} & ({ op: string } | { oc: string } | { q: unknown })

/**
 * Scalar query term (`k: "ct"`, no ciphertext) — a `unique` / `match` / `ore`
 * lookup term carrying exactly one of `hm`, `bf`, or `ob`.
 */
export type EncryptedScalarQuery = {
  k: 'ct'
  /** EQL schema version */
  v: number
  /** Table and column identifier */
  i: { t: string; c: string }
  /** Query payloads carry no ciphertext — discriminates against {@link EncryptedScalar}. */
  c?: never
} & ({ hm: string } | { bf: number[] } | { ob: string[] })

/**
 * STE-vector selector query payload (`ste_vec_selector`) — a tokenized JSON
 * path selector, no ciphertext.
 */
export type EncryptedSteVecSelector = {
  k: 'sv'
  v: number
  i: { t: string; c: string }
  /** Tokenized selector for path queries. */
  s: string
  sv?: never
}

/**
 * One entry inside a SteVec payload (`k: "sv"`).
 *
 * Every element carries `s` (selector) and `c` (entry ciphertext). String and
 * number path entries may additionally carry `op` (v3 Compat mode) or `oc`
 * (legacy v2 Standard mode). Exact equality is encoded in value-inclusive
 * selectors, so newly emitted entries do not carry `hm`.
 */
export type SteVecEntry = {
  /** Hex-encoded tokenized selector — deterministic per (path, key) */
  s: string
  /** Entry ciphertext: a legacy record in v2, raw AEAD output in v3. */
  c: string
  /** Array marker — true when the selector points at a JSON array context */
  a?: boolean
  /** Legacy v2 HMAC term; client 0.42 no longer emits this field. */
  hm?: string
  /** Per-entry CLLW OPE term for orderable leaves (strings, numbers) — Compat mode, the default */
  op?: string
  /** Per-entry CLLW ORE term for orderable leaves (strings, numbers) — Standard mode, EQL v2 only */
  oc?: string
}

/** @deprecated Use SteVecEntry instead */
export type EqlCiphertextBody = SteVecEntry

export type EncryptConfig = {
  v: number
  tables: Record<string, Record<string, Column>>
}

export type Column = {
  cast_as?: CastAs
  indexes?: Indexes
}

export type CastAs =
  | 'bigint'
  | 'boolean'
  | 'date'
  | 'decimal'
  | 'int'
  | 'number'
  | 'small_int'
  | 'string' // deprecated, use text instead but keep for backwards compatibility
  | 'text'
  | 'timestamp'
  | 'json'

/**
 * The `cast_as` vocabulary the Rust core actually accepts
 * (cipherstash-config's `CanonicalEncryptionConfig`).
 *
 * Three members of the public {@link CastAs} union are JS-only spellings with
 * no canonical equivalent — `string`, `number`, and `bigint` map to `text`,
 * `float`, and `big_int`. Both bindings translate them inside the Rust, at the
 * deserialization boundary (`crates/protect-ffi/src/encrypt_config.rs`), so
 * callers pass the public vocabulary and never have to spell this one.
 */
export type CanonicalCastAs =
  | 'text'
  | 'float'
  | 'big_int'
  | 'boolean'
  | 'date'
  | 'decimal'
  | 'int'
  | 'json'
  | 'small_int'
  | 'timestamp'

/** A {@link Column} whose `cast_as` is in the canonical vocabulary. */
export type CanonicalColumn = Omit<Column, 'cast_as'> & {
  cast_as?: CanonicalCastAs
}

/**
 * An encrypt config in the vocabulary the Rust core expects.
 *
 * Nothing asks you to build one. Both entries take the public
 * {@link EncryptConfig} and normalize into this shape at the Rust
 * deserialization boundary, so `newClient` declares {@link EncryptConfig} on
 * either binding.
 *
 * It stays exported because it names what the core ends up holding — for
 * tooling that models that vocabulary, and for a caller who would rather
 * pre-canonicalize than rely on the translation.
 */
export type CanonicalEncryptConfig = Omit<EncryptConfig, 'tables'> & {
  tables: Record<string, Record<string, CanonicalColumn>>
}

// Extract the tables from a specific config
type TablesOf<C extends EncryptConfig> = C['tables']

// Compute valid { table, column } pairs
export type Identifier<C extends EncryptConfig> = {
  [T in keyof TablesOf<C>]: {
    [CName in keyof TablesOf<C>[T]]: { table: T; column: CName }
  }[keyof TablesOf<C>[T]]
}[keyof TablesOf<C>]

export type Indexes = {
  ore?: OreIndexOpts
  ope?: OpeIndexOpts
  unique?: UniqueIndexOpts
  match?: MatchIndexOpts
  ste_vec?: SteVecIndexOpts
}

export type OreIndexOpts = Record<string, never>

export type OpeIndexOpts = Record<string, never>

export type UniqueIndexOpts = {
  token_filters?: TokenFilter[]
}

export type MatchIndexOpts = {
  tokenizer?: Tokenizer
  token_filters?: TokenFilter[]
  k?: number
  m?: number
  /**
   * Storage-only option: adds the whole (filtered, untokenized) value as an
   * extra bloom term so the stored filter can also answer whole-value
   * equality. It never shapes query terms — `encryptQuery` /
   * `encryptQueryBulk` always emit token-only blooms, otherwise a substring
   * query's bloom could never be a subset of a row's bits.
   */
  include_original?: boolean
}

export type ArrayIndexMode =
  | 'all'
  | 'none'
  | { item?: boolean; wildcard?: boolean; position?: boolean }

/**
 * Encoding mode for SteVec indexes.
 *
 * - `compat`: CLLW-OPE ordering, emits `op` per entry. The default since
 *   cipherstash-config 0.40.0, and the only mode EQL v3 accepts.
 * - `standard`: CLLW-ORE ordering, emits `oc` per entry. The pre-0.40.0
 *   default; EQL v2 only.
 *
 * The two orderings are not cross-comparable, so a column cannot change mode
 * without re-encrypting. Client 0.42 emits SteVec only through EQL v3, so new
 * configurations must use `compat`.
 */
export type SteVecMode = 'compat' | 'standard'

export type SteVecIndexOpts = {
  prefix: string
  term_filters?: TokenFilter[]
  array_index_mode?: ArrayIndexMode
  mode?: SteVecMode
}

export type Tokenizer =
  | { kind: 'standard' }
  | { kind: 'ngram'; token_length: number }

export type TokenFilter = { kind: 'downcase' }

export type NewClientOptions = {
  encryptConfig: EncryptConfig
  clientOpts?: ClientOpts
  /**
   * Caller-supplied auth strategy. When provided, `getToken()` is invoked on
   * every ZeroKMS request and `clientOpts.creds` is ignored for auth (the
   * client key is still required). Without this, the native side builds an
   * AutoStrategy from env / profile / `clientOpts.creds`.
   *
   * Named to match `@cipherstash/stack`'s `config.authStrategy`, so one
   * concept has one name across the stack.
   */
  authStrategy?: AuthStrategy
  /**
   * @deprecated Renamed to {@link NewClientOptions.authStrategy}. Still
   * honoured — `authStrategy` wins when both are set — but it will be removed.
   */
  strategy?: AuthStrategy
  /**
   * EQL wire version this client emits. Defaults to `2` (the
   * `eql_v2_encrypted` payload format).
   *
   * With `3`, {@link encrypt} / {@link encryptBulk} return {@link
   * EncryptedV3} payloads for the `eql_v3` per-capability column domains
   * (`public.eql_v3_text_eq`, `public.eql_v3_integer_ord_ore`,
   * `public.eql_v3_json_search`, …), derived
   * from each column's `cast_as` + indexes, and {@link encryptQuery} /
   * {@link encryptQueryBulk} return {@link EncryptedV3Query} operands:
   * term-only scalar operands for the `eql_v3.query_<name>` twins, the
   * `eql_v3.query_json` containment needle, and bare selector-hash strings
   * for path queries. {@link decrypt} accepts BOTH formats regardless of
   * this setting.
   */
  eqlVersion?: 2 | 3
}

/** The token payload the native side ultimately reads. */
export type TokenResult = { token: string }

/**
 * A `@byteslice/result` `Result` envelope, as returned by
 * `@cipherstash/auth` >= 0.41's `getToken()`.
 */
export type TokenResultEnvelope =
  | { data: TokenResult; failure?: undefined }
  | { failure: { type?: string; error?: Error }; data?: undefined }

/**
 * Auth strategy shape compatible with `@cipherstash/auth` strategies (e.g.
 * `AccessKeyStrategy`, `OidcFederationStrategy`). Only `getToken` is required.
 *
 * `getToken` may resolve either shape — the native and WASM clients accept both
 * (see `crates/protect-ffi/src/lib.rs` and `crates/protect-ffi/src/wasm.rs`):
 *
 * - `{ token }` — the bare payload, used by `@cipherstash/auth` <= 0.40 and by
 *   custom strategies.
 * - `{ data: { token } }` / `{ failure }` — the `Result` envelope, used by
 *   `@cipherstash/auth` >= 0.41. A `failure` is reconstructed into the
 *   corresponding `AuthError`.
 *
 * Both have been accepted at runtime since 0.28.0; this type previously
 * declared only the bare payload, so a real `@cipherstash/auth` >= 0.41
 * strategy could not be assigned to it.
 */
export type AuthStrategy = {
  getToken: () => Promise<TokenResult | TokenResultEnvelope>
}

export type ClientOpts = CredentialOpts & {
  keyset?: KeysetIdentifier
}

export type KeysetIdentifier = { Uuid: string } | { Name: string }

export type EnsureKeysetOpts = CredentialOpts & {
  name: string
}

export type EnsureKeysetResult = {
  id: string
  name: string
}

/**
 * A plaintext value accepted by {@link encrypt} / {@link encryptBulk} /
 * {@link encryptQuery} and returned by {@link decrypt} / {@link decryptBulk} /
 * {@link decryptBulkFallible} (in the `data` arm of each result).
 *
 * `bigint` support (encrypted `cast_as: 'bigint'` columns store signed
 * 64-bit integers):
 *
 * - **Input**: a top-level `bigint` plaintext is accepted alongside
 *   `number`. Values outside the i64 range (-2^63 to 2^63 - 1) throw a
 *   `RangeError` at the boundary — this covers index-term generation too,
 *   since terms derive from the same value. `number` inputs keep the
 *   existing exact-integer guard (fractional, non-finite, or beyond-2^53
 *   inexact values are rejected). `bigint` values nested inside JSON
 *   objects/arrays are NOT supported (JSON has no bigint) and throw a
 *   `TypeError` on both Neon and wasm — plaintexts follow
 *   `JSON.stringify` semantics on both platforms.
 * - **Output** (BREAKING since the introduction of bigint support):
 *   decrypting a `cast_as: 'bigint'` column ALWAYS returns a `bigint`,
 *   even for values that fit in a JS number. Previous releases returned a
 *   `number`, silently losing precision beyond `Number.MAX_SAFE_INTEGER`.
 */
export type JsPlaintext =
  | string
  | number
  | boolean
  | bigint
  | Record<string, unknown>
  | JsPlaintext[]

export type EncryptOptions = {
  plaintext: JsPlaintext
  column: string
  table: string
  lockContext?: Context
  unverifiedContext?: Record<string, unknown>
}

export type EncryptBulkOptions = {
  plaintexts: EncryptPayload[]
  unverifiedContext?: Record<string, unknown>
}

export type DecryptOptions = {
  /** A stored payload in either wire format (EQL v2.3 or EQL v3). */
  ciphertext: EncryptedPayload
  lockContext?: Context
  unverifiedContext?: Record<string, unknown>
}

export type DecryptBulkOptions = {
  ciphertexts: BulkDecryptPayload[]
  unverifiedContext?: Record<string, unknown>
}

// Query encryption types
export type IndexTypeName = 'ste_vec' | 'match' | 'ore' | 'ope' | 'unique'

export type QueryOpName =
  | 'default'
  | 'ste_vec_selector'
  | 'ste_vec_value_selector'
  | 'ste_vec_term'

export type EncryptQueryOptions = {
  plaintext: JsPlaintext
  column: string
  table: string
  indexType: IndexTypeName
  queryOp?: QueryOpName
  lockContext?: Context
  unverifiedContext?: Record<string, unknown>
}

export type QueryPayload = {
  plaintext: JsPlaintext
  column: string
  table: string
  indexType: IndexTypeName
  queryOp?: QueryOpName
  lockContext?: Context
}

export type EncryptQueryBulkOptions = {
  queries: QueryPayload[]
  unverifiedContext?: Record<string, unknown>
}
