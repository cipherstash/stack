/* tslint:disable */
/* eslint-disable */
/**
 * The `ReadableStreamType` enum.
 *
 * *This API requires the following crate features to be activated: `ReadableStreamType`*
 */

type ReadableStreamType = "bytes";

import type {
    DecryptBulkOptions,
    DecryptOptions,
    DecryptResult,
    Encrypted,
    EncryptedPayload,
    EncryptedQuery,
    EncryptBulkOptions,
    EncryptOptions,
    EncryptQueryBulkOptions,
    EncryptQueryOptions,
    JsPlaintext,
    NewClientOptions,
} from "../../lib/types.js";
import type { EncryptedV3Query } from "../../lib/eql-v3.js";

// Enumerated rather than `export type *`, for two reasons. It keeps the entry
// honest: `EnsureKeysetOpts` / `EnsureKeysetResult` name an operation this
// build does not export — a gap rather than a boundary, see the module header.
// And `export type *` is TypeScript 5.0+, which this package has no reason to
// require of a consumer; the explicit form works from 3.8.
//
// `DecryptResult` is exported now. It was held back while `code` was a field
// only the Neon JS wrapper synthesised, which this build has no equivalent of;
// both entries emit the code from Rust, so there is one shape to name (#146).
export type {
    ArrayIndexMode,
    AuthStrategy,
    BulkDecryptPayload,
    CanonicalCastAs,
    CanonicalColumn,
    CanonicalEncryptConfig,
    CastAs,
    ClientOpts,
    Column,
    Context,
    DecryptBulkOptions,
    DecryptOptions,
    DecryptResult,
    Encrypted,
    EncryptedPayload,
    EncryptedQuery,
    EncryptedScalar,
    EncryptedScalarQuery,
    EncryptedSteVec,
    EncryptedSteVecQuery,
    EncryptedSteVecSelector,
    EncryptBulkOptions,
    EncryptConfig,
    EncryptOptions,
    EncryptPayload,
    EncryptQueryBulkOptions,
    EncryptQueryOptions,
    EqlCiphertextBody,
    Identifier,
    Indexes,
    IndexTypeName,
    JsPlaintext,
    KeysetIdentifier,
    MatchIndexOpts,
    NewClientOptions,
    OpeIndexOpts,
    OreIndexOpts,
    QueryOpName,
    QueryPayload,
    SteVecEntry,
    SteVecIndexOpts,
    SteVecMode,
    TokenFilter,
    Tokenizer,
    TokenResult,
    TokenResultEnvelope,
    UniqueIndexOpts,
} from "../../lib/types.js";
export type { EncryptedV3, EncryptedV3Query } from "../../lib/eql-v3.js";
export {
    PROTECT_ERROR_CODES,
    isProtectErrorCode,
    type ProtectErrorCode,
} from "./errors.js";



export class IntoUnderlyingByteSource {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    cancel(): void;
    pull(controller: ReadableByteStreamController): Promise<any>;
    start(controller: ReadableByteStreamController): void;
    readonly autoAllocateChunkSize: number;
    readonly type: ReadableStreamType;
}

export class IntoUnderlyingSink {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    abort(reason: any): Promise<any>;
    close(): Promise<any>;
    write(chunk: any): Promise<any>;
}

export class IntoUnderlyingSource {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    cancel(): void;
    pull(controller: ReadableStreamDefaultController): Promise<any>;
}

/**
 * Wasm-side client handle. Wraps the same `ScopedCipher` +
 * `ZeroKMSWithClientKey` pair the Neon side does, parameterised by
 * [`WasmAuthStrategy`] — whose two arms are the wasm counterpart of the Neon
 * side's `NodeAuthStrategy`.
 */
export class WasmClient {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
}

export function decrypt(client: WasmClient, opts: DecryptOptions): Promise<JsPlaintext>;

export function decryptBulk(client: WasmClient, opts: DecryptBulkOptions): Promise<JsPlaintext[]>;

export function decryptBulkFallible(client: WasmClient, opts: DecryptBulkOptions): Promise<DecryptResult[]>;

export function encrypt(client: WasmClient, opts: EncryptOptions): Promise<EncryptedPayload>;

export function encryptBulk(client: WasmClient, opts: EncryptBulkOptions): Promise<EncryptedPayload[]>;

export function encryptQuery(client: WasmClient, opts: EncryptQueryOptions): Promise<Encrypted | EncryptedQuery | EncryptedV3Query>;

export function encryptQueryBulk(client: WasmClient, opts: EncryptQueryBulkOptions): Promise<(Encrypted | EncryptedQuery | EncryptedV3Query)[]>;

/**
 * Install [`console_error_panic_hook`] so Rust panics surface as a JS
 * `Error` in the browser / Node console instead of a bare
 * `RuntimeError: unreachable executed` from the wasm trap. Idempotent —
 * safe to call from any number of entry points.
 *
 * Wired via `#[wasm_bindgen(start)]` so it runs once at module
 * instantiation, before any `newClient` / `encrypt` / `decrypt` call.
 */
export function init(): void;

export function isEncrypted(raw: unknown): boolean;

/**
 * Construct a [`WasmClient`].
 *
 * `opts.authStrategy` must be an `@cipherstash/auth`-shaped object — anything
 * with a `getToken()` method returning a `Promise` works. A non-`Promise`
 * return is rejected with `strategy.getToken() did not return a Promise`.
 *
 * The promise may resolve either the bare `{ token: string, ... }` payload
 * (`@cipherstash/auth` <= 0.40 and custom strategies) or a `@byteslice/result`
 * envelope — `{ data: { token, ... } }` on success, `{ failure }` on error
 * (`@cipherstash/auth` >= 0.41). Both are accepted.
 *
 * `opts.strategy` is the former name, still accepted while it is deprecated;
 * `authStrategy` wins when both are present. The new name matches
 * `@cipherstash/stack`'s `config.authStrategy`.
 *
 * Omitting it is fine: `clientOpts.accessKey` + `clientOpts.workspaceCrn`
 * then resolve an `AccessKeyStrategy` through the same
 * `CredentialOpts::build_strategy()` the Neon entry uses.
 *
 * Takes the SAME [`NewClientOptions`] as the Neon `newClient`, and the body
 * below is deliberately the same sequence. Everything that genuinely differs
 * between the targets is confined to `CredentialOpts::build_key_provider`
 * (no profile store here) and `AutoStrategy`'s own wasm arm (no filesystem
 * fallback). Nothing about the options shape differs, so callers write one
 * config for both entries.
 */
export function newClient(opts: NewClientOptions): Promise<WasmClient>;
