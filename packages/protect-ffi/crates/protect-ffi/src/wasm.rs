//! Wasm-bindgen bindings for protect-ffi.
//!
//! Mirrors the Neon exports in `lib.rs` for the `wasm32-unknown-unknown`
//! target. Uses `serde-wasm-bindgen` for JS↔Rust marshalling and wraps a
//! JS `getToken` callable (matching `@cipherstash/auth`'s
//! `AccessKeyStrategy.getToken()` shape) into a [`stack_auth::AuthStrategy`]
//! via a small adapter struct.
//!
//! What differs from the Neon path is not the options shape — both entries
//! deserialize the same [`crate::NewClientOptions`] — but what the host can
//! supply. There is no filesystem and no readable environment here, so the
//! client key is always passed as an explicit option: no
//! `~/.cipherstash/secretkey.json` to fall back to.
//!
//! Authentication has two arms, [`WasmAuthStrategy`]: a JS-supplied
//! `authStrategy`, or — when none is given — `AutoStrategy`'s wasm arm,
//! which resolves an `AccessKeyStrategy` from `clientOpts.accessKey` +
//! `clientOpts.workspaceCrn`.
//!
//! # Auth caching
//!
//! On the JS-backed arm, [`JsAuthStrategy::get_token`] is invoked on every
//! ZeroKMS request — there is no Rust-side equivalent of
//! [`stack_auth::AutoRefresh`] in the wasm path. Caching is the JS strategy's
//! responsibility (cookies, `localStorage`, or whatever the embedding runtime
//! provides). The adapter is intentionally a thin shim so the host environment
//! owns the refresh / persistence policy.
//!
//! # Surface omissions
//!
//! `ensureKeyset` is exported on the Neon entry only. Read that as a gap, not
//! a boundary: this doc used to call it deliberate — provisioning belongs on
//! your server, not in browser code — but wasm ships to servers too, and
//! nothing about the operation makes it unsuited to this target.
//!
//! It went unnoticed for a structural reason worth naming, because it will
//! hide the next one too. `ensureKeyset`'s only caller in this repo is
//! `integration-tests/tests/keyset.test.ts`, and the wasm suite has no
//! equivalent: one of the eighteen files under `integration-tests/tests`
//! loads this build, covering round-trips and `newClient` validation and
//! nothing else — `encryptQuery` and `encryptQueryBulk` have no wasm test at
//! all, nor do `eqlVersion`, `keyset`, or lock contexts. A missing export is
//! invisible when no test on that target would have called it, so the
//! omission is the symptom and the coverage is the cause. Tracked in #149.
//!
//! The `mod wasm;` declaration in `lib.rs` carries the
//! `#[cfg(target_arch = "wasm32")]`. Repeating it here as an inner attribute is
//! what `clippy::duplicated_attributes` flags, so this module has no cfg of its
//! own.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::sync::Arc;

use cipherstash_client::encryption::{Plaintext, ScopedCipher, TypeParseError};
use cipherstash_client::eql::{
    encrypt_eql, encrypt_eql_v3, EqlEncryptOpts, EqlOperation, Identifier as EqlIdentifier,
    PreparedPlaintext,
};
use cipherstash_client::schema::{ColumnConfig, Identifier};
use cipherstash_client::zerokms::{self, WithContext, ZeroKMSBuilder, ZeroKMSWithClientKey};
use serde::Serialize;
use stack_auth::{AuthError, AuthStrategy, SecretToken, ServerError, ServiceToken};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::js_plaintext::{JsPlaintext, BIGINT_WIRE_KEY};
use crate::{
    auth_failure_message, encrypted_record_from_value, into_store_ciphertext,
    into_store_ciphertext_v3, is_encrypted_value, prepare_query_plaintext, query_config_map,
    query_output, query_output_v3, resolve_eql_version, storage_output, storage_output_v3,
    DecryptBulkOptions, DecryptOptions, DecryptResult, EncryptBulkOptions, EncryptOptions,
    EncryptQueryBulkOptions, EncryptQueryOptions, EncryptedOutput, EqlVersion, Error,
    NewClientOptions, QueryOutput,
};
use cipherstash_client::AutoStrategy;

// ---------------------------------------------------------------------------
// TypeScript declarations
// ---------------------------------------------------------------------------

/// TypeScript emitted verbatim into `dist/wasm/protect_ffi.d.ts`.
///
/// wasm-bindgen appends `typescript_custom_section` content to the generated
/// `.d.ts`, and `typescript_type` below names these types in the signatures.
/// Together that means the declarations are produced by the build rather than
/// patched on afterwards, so they cannot drift from the Rust and there is no
/// post-processing step to keep in sync with wasm-bindgen's output format.
///
/// `../../lib/` is a relative path inside the package, so it resolves for every
/// consumer without naming the Neon entry — which matters, because this is the
/// bundle whose whole purpose is to avoid loading a native binary (#142).
#[wasm_bindgen(typescript_custom_section)]
const TYPESCRIPT_DECLARATIONS: &'static str = r#"
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
"#;

/// Newtypes over `JsValue` that carry a TypeScript type into the generated
/// signatures.
///
/// Without these every export is `(client: WasmClient, opts: any) =>
/// Promise<any>`, because wasm-bindgen only sees `JsValue`. The names on the
/// right are resolved against the declarations above.
///
/// They are safe to assert because `wasm.rs` deserializes each `opts` into the
/// SAME Rust struct the Neon entry does and calls the same `do_*` helper — the
/// accepted shape is identical by construction, not by convention.
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "NewClientOptions")]
    pub type NewClientOptionsJs;
    #[wasm_bindgen(typescript_type = "EncryptOptions")]
    pub type EncryptOptionsJs;
    #[wasm_bindgen(typescript_type = "EncryptBulkOptions")]
    pub type EncryptBulkOptionsJs;
    #[wasm_bindgen(typescript_type = "DecryptOptions")]
    pub type DecryptOptionsJs;
    #[wasm_bindgen(typescript_type = "DecryptBulkOptions")]
    pub type DecryptBulkOptionsJs;
    #[wasm_bindgen(typescript_type = "EncryptQueryOptions")]
    pub type EncryptQueryOptionsJs;
    #[wasm_bindgen(typescript_type = "EncryptQueryBulkOptions")]
    pub type EncryptQueryBulkOptionsJs;
    #[wasm_bindgen(typescript_type = "EncryptedPayload")]
    pub type EncryptedPayloadJs;
    #[wasm_bindgen(typescript_type = "EncryptedPayload[]")]
    pub type EncryptedPayloadArrayJs;
    #[wasm_bindgen(typescript_type = "JsPlaintext")]
    pub type JsPlaintextJs;
    #[wasm_bindgen(typescript_type = "JsPlaintext[]")]
    pub type JsPlaintextArrayJs;
    // The Neon entry's `DecryptResult`, not a wasm-specific narrowing of it.
    // It used to be one: `code` is set by Rust as of #146, where before it was
    // synthesised in JS by the Neon wrapper and so could not reach this build.
    #[wasm_bindgen(typescript_type = "DecryptResult[]")]
    pub type DecryptResultArrayJs;
    #[wasm_bindgen(typescript_type = "Encrypted | EncryptedQuery | EncryptedV3Query")]
    pub type QueryTermJs;
    #[wasm_bindgen(typescript_type = "(Encrypted | EncryptedQuery | EncryptedV3Query)[]")]
    pub type QueryTermArrayJs;
    #[wasm_bindgen(typescript_type = "unknown")]
    pub type UnknownJs;
}

// ---------------------------------------------------------------------------
// Module init
// ---------------------------------------------------------------------------

/// Install [`console_error_panic_hook`] so Rust panics surface as a JS
/// `Error` in the browser / Node console instead of a bare
/// `RuntimeError: unreachable executed` from the wasm trap. Idempotent —
/// safe to call from any number of entry points.
///
/// Wired via `#[wasm_bindgen(start)]` so it runs once at module
/// instantiation, before any `newClient` / `encrypt` / `decrypt` call.
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

// ---------------------------------------------------------------------------
// Auth strategy adapter
// ---------------------------------------------------------------------------

/// JS-backed [`AuthStrategy`].
///
/// Holds a JS callable `getToken(): Promise<TokenResult>` (the shape
/// `@cipherstash/auth`'s strategies expose) and calls it whenever
/// cipherstash-client asks for a fresh service token. Inline rather than
/// going through `stack_auth::AuthStrategyFn` because the JS callable type
/// is hard to express as a Rust closure in a stored struct.
pub(crate) struct JsAuthStrategy {
    /// The original JS strategy object — kept so `getToken()` is invoked with the
    /// correct `this` receiver. Class-based strategies read instance state via
    /// `this`; calling with `JsValue::NULL` breaks them.
    strategy: JsValue,
    get_token: js_sys::Function,
}

impl JsAuthStrategy {
    fn new(strategy: JsValue, get_token: js_sys::Function) -> Self {
        Self {
            strategy,
            get_token,
        }
    }
}

// Safety: wasm32-unknown-unknown is single-threaded, and `JsValue` /
// `js_sys::Function` handles cannot cross threads even in principle. The
// `Send + Sync` bound only exists because `cipherstash_client::ScopedCipher`
// and `ZeroKMSWithClientKey` carry a blanket `C: Send + Sync + 'static`
// bound on their methods (inherited from the native build). Dropping this
// unsafe impl requires an upstream change in cipherstash-client to relax
// those bounds on `target_arch = "wasm32"` (similar to the existing
// `AuthStrategy` split in `stack-auth`).
unsafe impl Send for JsAuthStrategy {}
unsafe impl Sync for JsAuthStrategy {}

impl AuthStrategy for &JsAuthStrategy {
    fn get_token(self) -> impl Future<Output = Result<ServiceToken, AuthError>> {
        let promise = self.get_token.call0(&self.strategy);
        async move {
            let promise = promise.map_err(|e| {
                AuthError::Server(ServerError(format!("strategy.getToken() threw: {e:?}")))
            })?;
            let promise: js_sys::Promise = promise.dyn_into().map_err(|_| {
                AuthError::Server(ServerError(
                    "strategy.getToken() did not return a Promise".to_string(),
                ))
            })?;
            let result = JsFuture::from(promise).await.map_err(|e| {
                AuthError::Server(ServerError(format!("strategy.getToken() rejected: {e:?}")))
            })?;
            // `Reflect::get` throws on a non-object receiver, so validate up
            // front: a non-object resolution (e.g. a bare string) is a distinct,
            // clearer failure than the "missing token field" it would otherwise
            // surface as. Mirrors the Node seam's `downcast::<JsObject>` guard.
            if !result.is_object() {
                return Err(AuthError::Server(ServerError(
                    "strategy.getToken() did not return an object".to_string(),
                )));
            }
            // Accept both `@cipherstash/auth` shapes:
            //   >= 0.41: a `@byteslice/result` `Result` — `{ data: TokenResult }`
            //            on success, `{ failure: AuthFailure }` on error.
            //   <= 0.40 / custom strategies: the bare `TokenResult`, with `token`
            //            at the top level (the documented
            //            `getToken(): Promise<{ token }>` contract).
            // `result` is an object, so `Reflect::get` only throws on a getter
            // that itself throws (e.g. a Proxy trap) — propagate that rather than
            // silently treating the field as absent.
            let failure =
                js_sys::Reflect::get(&result, &JsValue::from_str("failure")).map_err(|e| {
                    AuthError::Server(ServerError(format!("reading failure field: {e:?}")))
                })?;
            if !failure.is_undefined() && !failure.is_null() {
                return Err(js_failure_to_auth_error(failure));
            }
            // Unwrap the `data` envelope when present (0.41+); otherwise read the
            // bare result object directly (<= 0.40).
            let data = js_sys::Reflect::get(&result, &JsValue::from_str("data")).map_err(|e| {
                AuthError::Server(ServerError(format!("reading data field: {e:?}")))
            })?;
            let source = if data.is_object() { data } else { result };
            let token =
                js_sys::Reflect::get(&source, &JsValue::from_str("token")).map_err(|e| {
                    AuthError::Server(ServerError(format!("missing token field: {e:?}")))
                })?;
            let token = token.as_string().ok_or_else(|| {
                AuthError::Server(ServerError("token field is not a string".to_string()))
            })?;
            Ok(ServiceToken::new(SecretToken::new(token)))
        }
    }
}

/// Reconstruct a [`stack_auth::AuthError`] from an `@cipherstash/auth`
/// `AuthFailure` (`{ ...payload, type, error: Error, help?, url? }`) via
/// [`AuthError::from_error_code`], so a strategy failure crosses back into Rust
/// as the real typed error — preserving its code and any structured payload
/// (e.g. `WORKSPACE_MISMATCH`'s `expected`/`actual`) — rather than a flattened
/// `Server`. Unknown / foreign codes fall through to `AuthError::Custom`.
fn js_failure_to_auth_error(failure: JsValue) -> AuthError {
    // A non-object failure (a bare string/number) carries no `type`/`error`, so
    // reconstruction would produce a blank `Custom("")`. Treat it as a malformed
    // strategy result with a clear message instead — mirroring the Neon seam's
    // `downcast::<JsObject>` guard.
    if !failure.is_object() {
        return AuthError::Server(ServerError("strategy.getToken failed".to_string()));
    }
    let code = js_sys::Reflect::get(&failure, &JsValue::from_str("type"))
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_default();
    let message = js_sys::Reflect::get(&failure, &JsValue::from_str("error"))
        .ok()
        .and_then(|err| js_sys::Reflect::get(&err, &JsValue::from_str("message")).ok())
        .and_then(|m| m.as_string())
        .unwrap_or_default();
    // The structured payload is every own field except the reserved
    // `type`/`error`/`help`/`url`. `error` is a live JS `Error`; the rest are
    // plain values, so deserialization is lossless for what `from_error_code`
    // reads (and degrades to an empty map, i.e. `Custom`, if it ever isn't).
    let mut payload: serde_json::Map<String, serde_json::Value> =
        serde_wasm_bindgen::from_value(failure).unwrap_or_default();
    for key in ["type", "error", "help", "url"] {
        payload.remove(key);
    }
    AuthError::from_error_code(&code, auth_failure_message(&code, message), &payload)
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// The two ways this build can authenticate.
///
/// Mirrors the Neon side's `NodeAuthStrategy` so `new_client` has the same
/// shape on both targets: a caller-supplied JS strategy, or — when none is
/// given — whatever `CredentialOpts::build_strategy()` resolves.
///
/// On wasm that resolution is `AutoStrategy`'s `target_arch = "wasm32"` arm,
/// which is access-key-only: `stack-auth` compiles out the profile-store
/// fallback because there is no filesystem to read. So "auto" here means
/// exactly "build an `AccessKeyStrategy` from the supplied workspace CRN and
/// access key", which is the wasm equivalent of the Neon default.
///
/// Note that `AutoStrategy`'s own environment lookup never fires here:
/// `std::env::var` on `wasm32-unknown-unknown` always returns `Err`, since std
/// falls back to its `unsupported` env backend. That costs nothing, because
/// the builder consults explicit values first and the JS layer already reads
/// env and passes credentials through as explicit fields — the same
/// arrangement the Neon path uses for Bun.
enum WasmAuthStrategy {
    Auto(Box<AutoStrategy>),
    JsBacked(JsAuthStrategy),
}

impl AuthStrategy for &WasmAuthStrategy {
    async fn get_token(self) -> Result<ServiceToken, AuthError> {
        match self {
            WasmAuthStrategy::Auto(s) => (&**s).get_token().await,
            WasmAuthStrategy::JsBacked(s) => s.get_token().await,
        }
    }
}

/// Wasm-side client handle. Wraps the same `ScopedCipher` +
/// `ZeroKMSWithClientKey` pair the Neon side does, parameterised by
/// [`WasmAuthStrategy`] — whose two arms are the wasm counterpart of the Neon
/// side's `NodeAuthStrategy`.
#[wasm_bindgen]
pub struct WasmClient {
    cipher: Arc<ScopedCipher<WasmAuthStrategy>>,
    zerokms: Arc<ZeroKMSWithClientKey<WasmAuthStrategy>>,
    encrypt_config: Arc<HashMap<Identifier, ColumnConfig>>,
    /// `encrypt_config` with `include_original` forced off on every match
    /// index — what the encrypt-query entry points use, so query blooms stay
    /// token-only. See [`query_config_map`].
    query_config: Arc<HashMap<Identifier, ColumnConfig>>,
    /// EQL wire version this client emits. Decryption accepts both formats
    /// regardless of this setting.
    eql_version: EqlVersion,
}

/// Construct a [`WasmClient`].
///
/// `opts.authStrategy` must be an `@cipherstash/auth`-shaped object — anything
/// with a `getToken()` method returning a `Promise` works. A non-`Promise`
/// return is rejected with `strategy.getToken() did not return a Promise`.
///
/// The promise may resolve either the bare `{ token: string, ... }` payload
/// (`@cipherstash/auth` <= 0.40 and custom strategies) or a `@byteslice/result`
/// envelope — `{ data: { token, ... } }` on success, `{ failure }` on error
/// (`@cipherstash/auth` >= 0.41). Both are accepted.
///
/// `opts.strategy` is the former name, still accepted while it is deprecated;
/// `authStrategy` wins when both are present. The new name matches
/// `@cipherstash/stack`'s `config.authStrategy`.
///
/// Omitting it is fine: `clientOpts.accessKey` + `clientOpts.workspaceCrn`
/// then resolve an `AccessKeyStrategy` through the same
/// `CredentialOpts::build_strategy()` the Neon entry uses.
///
/// Takes the SAME [`NewClientOptions`] as the Neon `newClient`, and the body
/// below is deliberately the same sequence. Everything that genuinely differs
/// between the targets is confined to `CredentialOpts::build_key_provider`
/// (no profile store here) and `AutoStrategy`'s own wasm arm (no filesystem
/// fallback). Nothing about the options shape differs, so callers write one
/// config for both entries.
#[wasm_bindgen(js_name = newClient)]
pub async fn new_client(opts: NewClientOptionsJs) -> Result<WasmClient, JsValue> {
    let opts: JsValue = opts.into();
    // Extract the strategy before serde — the JS function on it can't survive
    // serde_wasm_bindgen, and the rest of the opts has no JS-callable fields.
    // (The Neon entry gets it as a separate argument for the same reason: its
    // `Json` extractor is JSON.stringify-based, which would drop a function.)
    //
    // `authStrategy` first, then the deprecated `strategy`. Read both rather
    // than either/or so a caller mid-migration, or one passing an object that
    // still carries the old key, keeps working.
    //
    // `key` is the name the caller actually used, and every error below quotes
    // it: someone still on `strategy` should not be told to look at a property
    // they did not write.
    let new_name = js_sys::Reflect::get(&opts, &JsValue::from_str("authStrategy"))
        .map_err(|e| js_error(&format!("opts.authStrategy lookup failed: {e:?}")))?;
    let (key, strategy) = if new_name.is_undefined() || new_name.is_null() {
        let old_name = js_sys::Reflect::get(&opts, &JsValue::from_str("strategy"))
            .map_err(|e| js_error(&format!("opts.strategy lookup failed: {e:?}")))?;
        ("strategy", old_name)
    } else {
        ("authStrategy", new_name)
    };
    let js_strategy = if strategy.is_undefined() || strategy.is_null() {
        None
    } else {
        // `Reflect::get` throws on a non-object receiver, so a bare string here
        // would surface as "opts.authStrategy.getToken not found: TypeError:
        // Reflect.get called on non-object" plus a stack trace — blaming
        // `getToken` for a problem one level up. Mirrors the guards in
        // `JsAuthStrategy::get_token` and `js_failure_to_auth_error`.
        if !strategy.is_object() {
            return Err(js_error(&format!(
                "opts.{key} must be an object with a getToken() method"
            )));
        }
        let get_token = js_sys::Reflect::get(&strategy, &JsValue::from_str("getToken"))
            .map_err(|e| js_error(&format!("opts.{key}.getToken not found: {e:?}")))?;
        let get_token: js_sys::Function = get_token
            .dyn_into()
            .map_err(|_| js_error(&format!("opts.{key}.getToken is not a function")))?;
        Some(JsAuthStrategy::new(strategy.clone(), get_token))
    };

    // Both auth keys are handled above, so neither is a field of
    // `NewClientOptions` — and that struct denies unknown fields. Strip them
    // before serde sees the object.
    //
    // Onto a shallow copy, never the caller's object: a config reused across
    // calls would silently lose its strategy on the second one.
    //
    // The copy goes through [`shallow_clone`], which reports a throwing getter
    // instead of letting it unwind out of wasm.
    //
    // The deletes cannot report failure on a property `Object::assign` copied.
    // It writes through [[Set]] onto a fresh object, which produces plain
    // configurable data properties — so a source property that was frozen or
    // non-configurable arrives here deletable, and a non-enumerable one was
    // never copied at all (the `Reflect::get` above still saw it on the
    // original, so such a strategy is used, not lost). Keep that in mind if
    // this ever stops going through `Object::assign`.
    //
    // [[Set]] cuts the other way too: a setter for a copied key on
    // `Object.prototype` swallows the value, and the key does not arrive. That
    // is a silent drop inside the function that exists to stop silent drops,
    // but it needs a poisoned `Object.prototype` to reach, which breaks far
    // more than this.
    //
    // The `dyn_ref` guard costs nothing but rarely decides anything: a caller
    // passing a primitive has already been rejected by the `Reflect::get`
    // above with "called on non-object". Arrays and functions do reach it, and
    // `Object::assign` flattens them into an object serde then rejects for the
    // fields it is missing.
    let opts = match opts.dyn_ref::<js_sys::Object>() {
        Some(obj) => {
            let clone = shallow_clone(obj, "opts")?;
            for key in ["authStrategy", "strategy"] {
                js_sys::Reflect::delete_property(&clone, &JsValue::from_str(key))
                    .map_err(|e| js_error(&format!("opts.{key} could not be removed: {e:?}")))?;
            }
            clone.into()
        }
        None => opts,
    };

    let opts: NewClientOptions = from_js_value(opts)?;

    // From here down this mirrors the Neon `new_client` line for line.
    //
    // Anything that IS an `Error`, or can become one, goes through
    // `error_to_js` so the code survives; `js_error` is only for failures with
    // no `Error` variant behind them, like the serde rejection above. These
    // three used to take the `js_error` path — invisible until #146, because a
    // code was not being carried anywhere. `into_config_map` is the one that
    // mattered: its three coded config failures arrived bare on this entry.
    let encrypt_config = opts
        .encrypt_config
        .0
        .into_config_map()
        .map_err(|e| error_to_js(e.into()))?;
    let eql_version =
        resolve_eql_version(opts.eql_version, &encrypt_config).map_err(error_to_js)?;
    let client_opts = opts.client_opts.unwrap_or_default();

    let auth = match js_strategy {
        Some(s) => WasmAuthStrategy::JsBacked(s),
        None => WasmAuthStrategy::Auto(Box::new(
            client_opts.creds.build_strategy().map_err(error_to_js)?,
        )),
    };
    let zerokms = ZeroKMSBuilder::new(auth)
        .with_key_provider(
            client_opts
                .creds
                .build_key_provider()
                .map_err(error_to_js)?,
        )
        .build()
        .await
        .map_err(|e| error_to_js(e.into()))?;

    let zerokms = Arc::new(zerokms);
    let cipher = ScopedCipher::init(zerokms.clone(), client_opts.keyset)
        .await
        .map_err(|e| error_to_js(e.into()))?;

    let query_config = query_config_map(encrypt_config.clone());
    let encrypt_config = Arc::new(encrypt_config);
    Ok(WasmClient {
        cipher: Arc::new(cipher),
        zerokms,
        encrypt_config,
        query_config,
        eql_version,
    })
}

// ---------------------------------------------------------------------------
// Encrypt / decrypt JS surface
// ---------------------------------------------------------------------------

// Top-level wasm-bindgen exports mirror the flat function shape of
// `@cipherstash/protect-ffi`'s Neon API (`encrypt(client, opts)`,
// `decrypt(client, opts)`, etc.) so the conditional `exports` map can
// resolve to the wasm output without consumers having to rewrite call
// sites between native and Edge runtimes.

#[wasm_bindgen]
pub async fn encrypt(
    client: &WasmClient,
    opts: EncryptOptionsJs,
) -> Result<EncryptedPayloadJs, JsValue> {
    let opts = encode_plaintext(&opts.into())?;
    let opts: EncryptOptions = from_js_value(opts)?;
    let out = do_encrypt(client, opts).await.map_err(error_to_js)?;
    to_js(&out).map(JsCast::unchecked_into)
}

#[wasm_bindgen(js_name = encryptBulk)]
pub async fn encrypt_bulk(
    client: &WasmClient,
    opts: EncryptBulkOptionsJs,
) -> Result<EncryptedPayloadArrayJs, JsValue> {
    let opts = encode_plaintext_list(&opts.into(), "plaintexts")?;
    let opts: EncryptBulkOptions = from_js_value(opts)?;
    let out = do_encrypt_bulk(client, opts).await.map_err(error_to_js)?;
    to_js(&out).map(JsCast::unchecked_into)
}

#[wasm_bindgen(js_name = encryptQuery)]
pub async fn encrypt_query(
    client: &WasmClient,
    opts: EncryptQueryOptionsJs,
) -> Result<QueryTermJs, JsValue> {
    let opts = encode_plaintext(&opts.into())?;
    let opts: EncryptQueryOptions = from_js_value(opts)?;
    let out = do_encrypt_query(client, opts).await.map_err(error_to_js)?;
    to_js(&out).map(JsCast::unchecked_into)
}

#[wasm_bindgen(js_name = encryptQueryBulk)]
pub async fn encrypt_query_bulk(
    client: &WasmClient,
    opts: EncryptQueryBulkOptionsJs,
) -> Result<QueryTermArrayJs, JsValue> {
    let opts = encode_plaintext_list(&opts.into(), "queries")?;
    let opts: EncryptQueryBulkOptions = from_js_value(opts)?;
    let out = do_encrypt_query_bulk(client, opts)
        .await
        .map_err(error_to_js)?;
    to_js(&out).map(JsCast::unchecked_into)
}

#[wasm_bindgen]
pub async fn decrypt(
    client: &WasmClient,
    opts: DecryptOptionsJs,
) -> Result<JsPlaintextJs, JsValue> {
    let opts: DecryptOptions = from_js_value(opts.into())?;
    let out = do_decrypt(client, opts).await.map_err(error_to_js)?;
    plaintext_to_js(&out).map(JsCast::unchecked_into)
}

#[wasm_bindgen(js_name = decryptBulk)]
pub async fn decrypt_bulk(
    client: &WasmClient,
    opts: DecryptBulkOptionsJs,
) -> Result<JsPlaintextArrayJs, JsValue> {
    let opts: DecryptBulkOptions = from_js_value(opts.into())?;
    let out = do_decrypt_bulk(client, opts).await.map_err(error_to_js)?;
    let arr = js_sys::Array::new();
    for plaintext in &out {
        arr.push(&plaintext_to_js(plaintext)?);
    }
    Ok(arr.unchecked_into())
}

#[wasm_bindgen(js_name = decryptBulkFallible)]
pub async fn decrypt_bulk_fallible(
    client: &WasmClient,
    opts: DecryptBulkOptionsJs,
) -> Result<DecryptResultArrayJs, JsValue> {
    let opts: DecryptBulkOptions = from_js_value(opts.into())?;
    let out = do_decrypt_bulk_fallible(client, opts)
        .await
        .map_err(error_to_js)?;
    let arr = js_sys::Array::new();
    for result in &out {
        let obj = js_sys::Object::new();
        match result {
            DecryptResult::Success { data } => {
                set_prop(&obj, "data", &plaintext_to_js(data)?)?;
            }
            DecryptResult::Error { error, code } => {
                set_prop(&obj, "error", &JsValue::from_str(error))?;
                // Left unset rather than set to null when absent, so the item
                // matches the declared `code?: ProtectErrorCode`.
                if let Some(code) = code {
                    set_prop(&obj, "code", &JsValue::from_str(code))?;
                }
            }
        }
        arr.push(&obj);
    }
    Ok(arr.unchecked_into())
}

#[wasm_bindgen(js_name = isEncrypted)]
pub fn is_encrypted(raw: UnknownJs) -> bool {
    let Ok(v) = serde_wasm_bindgen::from_value::<serde_json::Value>(raw.into()) else {
        return false;
    };
    is_encrypted_value(&v)
}

// ---------------------------------------------------------------------------
// Logic helpers — mirror the Neon `#[neon::export]` fn bodies in lib.rs.
// ---------------------------------------------------------------------------

async fn do_encrypt(client: &WasmClient, opts: EncryptOptions) -> Result<EncryptedOutput, Error> {
    let ident = Identifier::new(opts.table.clone(), opts.column.clone());
    let column_config = client
        .encrypt_config
        .get(&ident)
        .ok_or_else(|| Error::UnknownColumn(ident.clone()))?;
    let plaintext = opts
        .plaintext
        .to_plaintext_with_type(column_config.cast_type)?;
    let eql_ident = EqlIdentifier::new(&opts.table, &opts.column);
    let prepared = PreparedPlaintext::new(
        Cow::Borrowed(column_config),
        eql_ident,
        plaintext,
        EqlOperation::Store,
    );
    let eql_opts = EqlEncryptOpts {
        keyset_id: None,
        lock_context: Cow::Owned(opts.lock_context.map(Into::into).unwrap_or_default()),
        unverified_context: opts.unverified_context.map(Cow::Owned),
        index_types: None,
        decryption_policy: None,
    };
    // v3 clients emit natively via encrypt_eql_v3 (no from_v2); v2 keeps the
    // historical encrypt_eql + storage_output path.
    if client.eql_version == EqlVersion::V3 {
        let mut encrypted =
            encrypt_eql_v3(client.cipher.clone(), vec![prepared], &eql_opts).await?;
        storage_output_v3(
            into_store_ciphertext_v3(encrypted.remove(0))?,
            column_config,
        )
    } else {
        let mut encrypted = encrypt_eql(client.cipher.clone(), vec![prepared], &eql_opts).await?;
        storage_output(
            into_store_ciphertext(encrypted.remove(0))?,
            client.eql_version,
            column_config,
        )
    }
}

async fn do_encrypt_bulk(
    client: &WasmClient,
    opts: EncryptBulkOptions,
) -> Result<Vec<EncryptedOutput>, Error> {
    // Group payloads by lock_context identity_claim — same shape as native.
    // We move the LockContext (no Clone) and extract its identity_claim
    // (Vec<String>, which IS Clone) as the group key.
    let mut groups: BTreeMap<Vec<String>, Vec<(usize, crate::PlaintextPayload)>> = BTreeMap::new();
    for (idx, payload) in opts.plaintexts.into_iter().enumerate() {
        let key = payload
            .lock_context
            .as_ref()
            .map(|lc| lc.identity_claim.clone())
            .unwrap_or_default();
        groups.entry(key).or_default().push((idx, payload));
    }

    let total: usize = groups.values().map(|v| v.len()).sum();
    let mut results: Vec<Option<EncryptedOutput>> = (0..total).map(|_| None).collect();

    for (identity_claim, payloads) in groups {
        let lock_context: Vec<zerokms::Context> = identity_claim
            .into_iter()
            .map(zerokms::Context::IdentityClaim)
            .collect();

        let mut prepared_plaintexts = Vec::with_capacity(payloads.len());
        let mut payload_data: Vec<(usize, Identifier)> = Vec::with_capacity(payloads.len());

        for (original_idx, payload) in payloads {
            let ident = Identifier::new(payload.table.clone(), payload.column.clone());
            let column_config = client
                .encrypt_config
                .get(&ident)
                .ok_or_else(|| Error::UnknownColumn(ident.clone()))?;
            let plaintext = payload
                .plaintext
                .to_plaintext_with_type(column_config.cast_type)?;
            let eql_ident = EqlIdentifier::new(&payload.table, &payload.column);
            let prepared = PreparedPlaintext::new(
                Cow::Borrowed(column_config),
                eql_ident,
                plaintext,
                EqlOperation::Store,
            );
            prepared_plaintexts.push(prepared);
            payload_data.push((original_idx, ident));
        }

        let eql_opts = EqlEncryptOpts {
            keyset_id: None,
            lock_context: Cow::Owned(lock_context),
            unverified_context: opts.unverified_context.as_ref().map(Cow::Borrowed),
            index_types: None,
            decryption_policy: None,
        };

        // v3 clients emit natively via encrypt_eql_v3 (no from_v2); v2 keeps the
        // historical path. Only one branch runs, so both may consume the moved
        // `prepared_plaintexts` / `payload_data`.
        if client.eql_version == EqlVersion::V3 {
            let encrypted =
                encrypt_eql_v3(client.cipher.clone(), prepared_plaintexts, &eql_opts).await?;
            for (eql_output, (original_idx, ident)) in encrypted.into_iter().zip(payload_data) {
                let column_config = client
                    .encrypt_config
                    .get(&ident)
                    .ok_or_else(|| Error::UnknownColumn(ident.clone()))?;
                results[original_idx] = Some(storage_output_v3(
                    into_store_ciphertext_v3(eql_output)?,
                    column_config,
                )?);
            }
        } else {
            let encrypted =
                encrypt_eql(client.cipher.clone(), prepared_plaintexts, &eql_opts).await?;
            for (eql_output, (original_idx, ident)) in encrypted.into_iter().zip(payload_data) {
                let column_config = client
                    .encrypt_config
                    .get(&ident)
                    .ok_or_else(|| Error::UnknownColumn(ident.clone()))?;
                results[original_idx] = Some(storage_output(
                    into_store_ciphertext(eql_output)?,
                    client.eql_version,
                    column_config,
                )?);
            }
        }
    }

    results
        .into_iter()
        .enumerate()
        .map(|(i, opt)| {
            opt.ok_or_else(|| Error::InvariantViolation(format!("missing bulk result {i}")))
        })
        .collect()
}

async fn do_encrypt_query(
    client: &WasmClient,
    opts: EncryptQueryOptions,
) -> Result<QueryOutput, Error> {
    let (prepared, column_config) = prepare_query_plaintext(
        &client.query_config,
        &opts.table,
        &opts.column,
        &opts.plaintext,
        &opts.index_type,
        opts.query_op,
        client.eql_version,
    )?;
    let eql_opts = EqlEncryptOpts {
        keyset_id: None,
        lock_context: Cow::Owned(opts.lock_context.map(Into::into).unwrap_or_default()),
        unverified_context: opts.unverified_context.map(Cow::Owned),
        index_types: None,
        decryption_policy: None,
    };
    // v3 clients emit query operands natively via encrypt_eql_v3 (no from_v2);
    // v2 keeps the historical encrypt_eql + query_output path.
    if client.eql_version == EqlVersion::V3 {
        let mut encrypted =
            encrypt_eql_v3(client.cipher.clone(), vec![prepared], &eql_opts).await?;
        query_output_v3(encrypted.remove(0), column_config)
    } else {
        let mut encrypted = encrypt_eql(client.cipher.clone(), vec![prepared], &eql_opts).await?;
        query_output(encrypted.remove(0), client.eql_version, column_config)
    }
}

async fn do_encrypt_query_bulk(
    client: &WasmClient,
    opts: EncryptQueryBulkOptions,
) -> Result<Vec<QueryOutput>, Error> {
    let mut groups: BTreeMap<Vec<String>, Vec<(usize, crate::QueryPayload)>> = BTreeMap::new();
    for (idx, payload) in opts.queries.into_iter().enumerate() {
        let key = payload
            .lock_context
            .as_ref()
            .map(|lc| lc.identity_claim.clone())
            .unwrap_or_default();
        groups.entry(key).or_default().push((idx, payload));
    }

    let total: usize = groups.values().map(|v| v.len()).sum();
    let mut results: Vec<Option<QueryOutput>> = (0..total).map(|_| None).collect();

    for (identity_claim, payloads) in groups {
        let lock_context: Vec<zerokms::Context> = identity_claim
            .into_iter()
            .map(zerokms::Context::IdentityClaim)
            .collect();

        let mut prepared_plaintexts = Vec::with_capacity(payloads.len());
        let mut payload_data: Vec<(usize, &ColumnConfig)> = Vec::with_capacity(payloads.len());

        for (original_idx, payload) in &payloads {
            let (prepared, column_config) = prepare_query_plaintext(
                &client.query_config,
                &payload.table,
                &payload.column,
                &payload.plaintext,
                &payload.index_type,
                payload.query_op,
                client.eql_version,
            )?;
            prepared_plaintexts.push(prepared);
            payload_data.push((*original_idx, column_config));
        }

        let eql_opts = EqlEncryptOpts {
            keyset_id: None,
            lock_context: Cow::Owned(lock_context),
            unverified_context: opts.unverified_context.as_ref().map(Cow::Borrowed),
            index_types: None,
            decryption_policy: None,
        };

        // v3 clients emit query operands natively via encrypt_eql_v3 (no
        // from_v2); v2 keeps the historical path.
        if client.eql_version == EqlVersion::V3 {
            let encrypted =
                encrypt_eql_v3(client.cipher.clone(), prepared_plaintexts, &eql_opts).await?;
            for (eql_output, (original_idx, column_config)) in
                encrypted.into_iter().zip(payload_data)
            {
                results[original_idx] = Some(query_output_v3(eql_output, column_config)?);
            }
        } else {
            let encrypted =
                encrypt_eql(client.cipher.clone(), prepared_plaintexts, &eql_opts).await?;
            for (eql_output, (original_idx, column_config)) in
                encrypted.into_iter().zip(payload_data)
            {
                results[original_idx] =
                    Some(query_output(eql_output, client.eql_version, column_config)?);
            }
        }
    }

    results
        .into_iter()
        .enumerate()
        .map(|(i, opt)| {
            opt.ok_or_else(|| Error::InvariantViolation(format!("missing query result {i}")))
        })
        .collect()
}

async fn do_decrypt(client: &WasmClient, opts: DecryptOptions) -> Result<JsPlaintext, Error> {
    let lock_context = opts.lock_context.map(Into::into).unwrap_or_default();
    let encrypted_record = encrypted_record_from_value(opts.ciphertext, lock_context)?;

    let bytes = client
        .zerokms
        .decrypt_single(encrypted_record, None, opts.unverified_context.as_ref())
        .await
        .map_err(Error::from)?;
    let plaintext = Plaintext::from_slice(bytes.as_slice()).map_err(Error::from)?;
    Ok(JsPlaintext::try_from(plaintext)?)
}

async fn do_decrypt_bulk(
    client: &WasmClient,
    opts: DecryptBulkOptions,
) -> Result<Vec<JsPlaintext>, Error> {
    let encrypted_records: Vec<WithContext<'static, crate::eql_v3::DecryptableRecord>> = opts
        .ciphertexts
        .into_iter()
        .map(|payload| {
            let lock_context: Vec<zerokms::Context> =
                payload.lock_context.map(Into::into).unwrap_or_default();
            encrypted_record_from_value(payload.ciphertext, lock_context)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let decrypted = client
        .zerokms
        .decrypt(encrypted_records, None, opts.unverified_context.as_ref())
        .await?;

    decrypted
        .into_iter()
        .map(|bytes| Plaintext::from_slice(&bytes).and_then(JsPlaintext::try_from))
        .collect::<Result<Vec<_>, TypeParseError>>()
        .map_err(Error::from)
}

async fn do_decrypt_bulk_fallible(
    client: &WasmClient,
    opts: DecryptBulkOptions,
) -> Result<Vec<DecryptResult>, Error> {
    // Decode each ciphertext independently so a single invalid payload turns
    // into a per-item `DecryptResult::Error` rather than aborting the whole
    // batch — matches the `*Fallible` contract.
    let parsed: Vec<Result<WithContext<'static, crate::eql_v3::DecryptableRecord>, Error>> = opts
        .ciphertexts
        .into_iter()
        .map(|payload| {
            let lock_context: Vec<zerokms::Context> =
                payload.lock_context.map(Into::into).unwrap_or_default();
            encrypted_record_from_value(payload.ciphertext, lock_context)
        })
        .collect();

    let mut results: Vec<Option<DecryptResult>> = (0..parsed.len()).map(|_| None).collect();
    let mut valid_records: Vec<WithContext<'static, crate::eql_v3::DecryptableRecord>> =
        Vec::with_capacity(parsed.len());
    let mut valid_indices: Vec<usize> = Vec::with_capacity(parsed.len());

    for (idx, item) in parsed.into_iter().enumerate() {
        match item {
            Ok(record) => {
                valid_records.push(record);
                valid_indices.push(idx);
            }
            Err(e) => {
                results[idx] = Some(DecryptResult::from_error(&e));
            }
        }
    }

    let decrypted = client
        .zerokms
        .decrypt_fallible(valid_records, opts.unverified_context.map(Cow::Owned))
        .await?;

    for (item, idx) in decrypted.into_iter().zip(valid_indices) {
        results[idx] = Some(match item {
            Ok(bytes) => match Plaintext::from_slice(&bytes)
                .map_err(Error::from)
                .and_then(|p| JsPlaintext::try_from(p).map_err(Error::from))
            {
                Ok(data) => DecryptResult::Success { data },
                Err(e) => DecryptResult::from_error(&e),
            },
            Err(e) => DecryptResult::from_error(&Error::from(e)),
        });
    }

    results
        .into_iter()
        .enumerate()
        .map(|(i, opt)| {
            opt.ok_or_else(|| {
                Error::InvariantViolation(format!("missing decrypt_fallible result at index {i}"))
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Error / value helpers
// ---------------------------------------------------------------------------

/// A JS `Error` with no `ProtectErrorCode`.
///
/// Used for failures raised at the wasm boundary itself — a malformed options
/// object, a value serde could not convert — which have no [`Error`] variant
/// and so no code to carry. The JS side reads those as `UNKNOWN`, matching what
/// the Neon entry does with the same failures.
fn js_error(msg: &str) -> JsValue {
    js_sys::Error::new(msg).into()
}

/// A JS `Error` carrying this error's `ProtectErrorCode` as `err.code`.
///
/// The code comes off the Rust variant (see [`Error`]'s `code` contract) rather
/// than being recovered from the message on the JS side, which is what
/// `src/errors.ts` used to do — and could only do for the Neon entry, since
/// this build's thrown errors never reached that wrapper (#146).
fn error_to_js(e: Error) -> JsValue {
    let (message, code) = e.diagnostic_parts();
    let err = js_sys::Error::new(&message);
    if let Some(code) = code {
        // Infallible in practice: `err` is a fresh, extensible JS object. A
        // failure here still yields a correct error, just without the code,
        // which beats masking the original failure with a `Reflect` one.
        let _ = js_sys::Reflect::set(&err, &JsValue::from_str("code"), &JsValue::from_str(&code));
    }
    err.into()
}

/// `serde_wasm_bindgen::from_value`, with an unknown `queryOp` routed through
/// [`Error`] so it arrives carrying `UNKNOWN_QUERY_OP`.
///
/// Every options struct on this entry deserializes through here. Anything else
/// stays a bare JS error, exactly as before: `serde_wasm_bindgen::Error` has no
/// `Error` variant to land in, and inventing a code for "the options object was
/// the wrong shape" is not this change's business.
fn from_js_value<T: serde::de::DeserializeOwned>(value: JsValue) -> Result<T, JsValue> {
    serde_wasm_bindgen::from_value(value).map_err(|e| {
        let message = e.to_string();
        Error::unknown_query_op(&message).map_or_else(|| js_error(&message), error_to_js)
    })
}

/// `Object.assign({}, source)` that reports a throwing getter rather than
/// unwinding through the wasm frames.
///
/// Every clone in this module copies an object the *caller* built, and a copy
/// reads each own enumerable property — so any of them can meet a getter that
/// throws. js-sys declares `Object::assign` without `catch`, which would let
/// that throw travel straight out of wasm, past the destructors of the
/// zeroizing values these paths carry. `try_assign` is the same
/// `Object.assign` with a `Result`, matching the `Reflect::*` calls around it.
///
/// `what` names the thing being copied, since the failure is the caller's
/// object misbehaving and they have to be able to find it.
fn shallow_clone(source: &js_sys::Object, what: &str) -> Result<js_sys::Object, JsValue> {
    js_sys::Object::try_assign(&js_sys::Object::new(), source)
        .map_err(|e| js_error(&format!("{what} could not be copied: {e:?}")))
}

fn to_js<T: serde::Serialize>(value: &T) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(value).map_err(|e| js_error(&e.to_string()))
}

fn set_prop(obj: &js_sys::Object, key: &str, value: &JsValue) -> Result<(), JsValue> {
    js_sys::Reflect::set(obj, &JsValue::from_str(key), value)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Plaintext boundary encoding
// ---------------------------------------------------------------------------
//
// Every `plaintext` value is rewritten BEFORE serde_wasm_bindgen runs, for
// two reasons:
//
// 1. BigInt tagging. A JS `bigint` cannot pass through
//    `serde_wasm_bindgen::from_value` into the untagged `JsPlaintext` enum:
//    `deserialize_any` visits BOTH a BigInt and a safe-integer Number as
//    `visit_i64`, so after untagged buffering the two are indistinguishable
//    and a bigint would silently land in the `Number(f64)` arm (losing
//    precision beyond 2^53). Instead, `bigint` plaintexts are detected with
//    `JsValue::is_bigint`, bounds-checked against i64, and swapped for the
//    tagged wire map (`{BIGINT_WIRE_KEY: "<decimal>"}`). This mirrors what
//    `src/index.cts` does for the Neon boundary.
//
// 2. JSON canonicalization. The Neon boundary extracts every options object
//    with `neon::types::extract::Json`, i.e. `JSON.stringify` on the JS
//    side — so Neon plaintexts get JSON.stringify semantics: `toJSON` is
//    honored (a `Date` becomes its ISO string), `undefined` properties are
//    dropped, non-finite numbers become `null`, and anything JSON cannot
//    represent (a bigint nested inside a json-column document, a circular
//    reference) throws a `TypeError`. serde_wasm_bindgen walks the live
//    object instead, so without this step the platforms diverge — most
//    sharply for a nested bigint, which Neon rejects but serde folds into
//    the document as an i64 that later decrypts through f64 (silently
//    rounding above 2^53). Round-tripping every non-bigint plaintext
//    through `JSON.stringify` → `JSON.parse` makes the wasm boundary
//    match Neon exactly, including the thrown `TypeError`.
//
// Rewrites land on a shallow-cloned options object — the caller's object
// is never mutated.

/// Bounds error for a JS `bigint` outside `i64::MIN..=i64::MAX`. Names the
/// bounds and the offending direction; deliberately does not echo the
/// value (it is plaintext being encrypted). A `RangeError` — the class the
/// README and the `JsPlaintext` JSDoc promise, and the class the Neon
/// boundary (`src/bigintWire.ts`) throws.
fn bigint_bounds_error(value: &JsValue) -> JsValue {
    let negative = js_sys::BigInt::new(value)
        .ok()
        .and_then(|b| b.to_string(10).ok())
        .map(|s| String::from(s).starts_with('-'))
        .unwrap_or(false);
    let (direction, bound) = if negative {
        ("below", "minimum")
    } else {
        ("above", "maximum")
    };
    js_sys::RangeError::new(&format!(
        "BigInt plaintext is {direction} the {bound} supported value: \
         encrypted bigint values must fit in a signed 64-bit integer \
         (-9223372036854775808 to 9223372036854775807)"
    ))
    .into()
}

/// Convert a JS `bigint` into the tagged wire map `JsPlaintext`
/// deserializes into `JsPlaintext::BigInt`, erroring (with the i64 bounds
/// and direction) when the value does not fit an i64.
fn tagged_bigint_wire(value: &JsValue) -> Result<JsValue, JsValue> {
    debug_assert!(value.is_bigint());
    let v = i64::try_from(value.clone()).map_err(|_| bigint_bounds_error(value))?;
    let obj = js_sys::Object::new();
    set_prop(&obj, BIGINT_WIRE_KEY, &JsValue::from_str(&v.to_string()))?;
    Ok(obj.into())
}

/// Round-trip a value through `JSON.stringify` → `JSON.parse`, matching
/// the Neon boundary's `neon::types::extract::Json` semantics. Returns
/// `None` when the value has no JSON form (`undefined`, a function, a
/// symbol — `JSON.stringify` returns `undefined` for these): the caller
/// passes the value through untouched so serde reports its usual error,
/// mirroring Neon, where `JSON.stringify` drops the property and serde
/// reports the plaintext as missing. Propagates `JSON.stringify`'s
/// `TypeError` (nested bigint, circular reference) unchanged.
fn json_canonical(value: &JsValue) -> Result<Option<JsValue>, JsValue> {
    let json: JsValue = js_sys::JSON::stringify(value)?.into();
    // `js_sys::JSON::stringify` types its success as `JsString`, but for
    // undefined/function/symbol inputs the underlying JS value is
    // `undefined` — `as_string()` is the honest check.
    let Some(json) = json.as_string() else {
        return Ok(None);
    };
    js_sys::JSON::parse(&json).map(Some)
}

/// The canonical boundary form of one `plaintext` value: a `bigint` becomes
/// the tagged wire map (bounds-checked), everything else is JSON
/// canonicalized. `None` means "leave the value untouched" (no JSON form).
fn boundary_plaintext(value: &JsValue) -> Result<Option<JsValue>, JsValue> {
    if value.is_bigint() {
        return tagged_bigint_wire(value).map(Some);
    }
    json_canonical(value)
}

/// Shallow-clone `opts` with its top-level `plaintext` replaced by the
/// canonical boundary form ([`boundary_plaintext`]). Plaintexts with no
/// canonical form (and non-object `opts`) pass through untouched, so serde
/// reports its usual errors for malformed input.
fn encode_plaintext(opts: &JsValue) -> Result<JsValue, JsValue> {
    let Some(obj) = opts.dyn_ref::<js_sys::Object>() else {
        return Ok(opts.clone());
    };
    let plaintext =
        js_sys::Reflect::get(opts, &JsValue::from_str("plaintext")).unwrap_or(JsValue::UNDEFINED);
    let Some(encoded) = boundary_plaintext(&plaintext)? else {
        return Ok(opts.clone());
    };
    let clone = shallow_clone(obj, "opts")?;
    set_prop(&clone, "plaintext", &encoded)?;
    Ok(clone.into())
}

/// Bulk variant of [`encode_plaintext`]: shallow-clones `opts`, the payload
/// array at `key`, and each payload whose `plaintext` has a canonical
/// boundary form. Returns `opts` untouched when nothing needed rewriting.
fn encode_plaintext_list(opts: &JsValue, key: &str) -> Result<JsValue, JsValue> {
    let Some(obj) = opts.dyn_ref::<js_sys::Object>() else {
        return Ok(opts.clone());
    };
    let list = js_sys::Reflect::get(opts, &JsValue::from_str(key)).unwrap_or(JsValue::UNDEFINED);
    let Some(arr) = list.dyn_ref::<js_sys::Array>() else {
        return Ok(opts.clone());
    };
    let item_plaintext = |item: &JsValue| {
        js_sys::Reflect::get(item, &JsValue::from_str("plaintext")).unwrap_or(JsValue::UNDEFINED)
    };
    let encoded = js_sys::Array::new();
    let mut changed = false;
    for item in arr.iter() {
        let plaintext = item_plaintext(&item);
        match (
            boundary_plaintext(&plaintext)?,
            item.dyn_ref::<js_sys::Object>(),
        ) {
            (Some(canonical), Some(item_obj)) => {
                let item_clone = shallow_clone(item_obj, "a payload item")?;
                set_prop(&item_clone, "plaintext", &canonical)?;
                encoded.push(&item_clone);
                changed = true;
            }
            _ => {
                encoded.push(&item);
            }
        }
    }
    if !changed {
        return Ok(opts.clone());
    }
    let clone = shallow_clone(obj, "opts")?;
    set_prop(&clone, key, &encoded)?;
    Ok(clone.into())
}

/// Convert a decrypted [`JsPlaintext`] into a JS value. The serde route
/// cannot produce a JS `bigint` (`JsPlaintext::BigInt` serializes as the
/// tagged wire map), so BigInt is constructed directly. Every other
/// variant goes through serde-wasm-bindgen's JSON-compatible serializer:
/// the default serializer emits Rust maps as JS `Map`s and nulls as
/// `undefined`, so a decrypted `JsonB` document would come back as
/// `Map { "score" => undefined }` on wasm while the Neon boundary returns
/// the plain object `{ score: null }` it round-trips through JSON.
fn plaintext_to_js(plaintext: &JsPlaintext) -> Result<JsValue, JsValue> {
    match plaintext {
        JsPlaintext::BigInt(v) => Ok(js_sys::BigInt::from(*v).into()),
        other => other
            .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
            .map_err(|e| js_error(&e.to_string())),
    }
}
