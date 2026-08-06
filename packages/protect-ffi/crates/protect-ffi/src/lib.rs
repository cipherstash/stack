mod client_options;
mod encrypt_config;
mod eql_v3;
mod js_plaintext;
mod query_op;
#[cfg(target_arch = "wasm32")]
mod wasm;

use client_options::NewClientOptions;
#[cfg(not(target_arch = "wasm32"))]
use client_options::{EnsureKeysetOpts, EnsureKeysetResult};
use query_op::{QueryOpName, SteVecQueryOpKind};

use cipherstash_client::{
    encryption::{EncryptionError, IndexerInit, MatchIndexer, Plaintext, QueryOp, TypeParseError},
    eql::{
        EqlCiphertext, EqlCiphertextV3, EqlError, EqlOperation, EqlOutput, EqlOutputV3,
        Identifier as EqlIdentifier, PreparedPlaintext,
    },
    schema::{
        column::{Index, IndexType},
        errors::ConfigError,
        ColumnConfig, Identifier,
    },
    zerokms::{self, RecordDecryptError, WithContext, ZeroKMSBuilderError},
    AuthError, UnverifiedContext,
};
// Everything below this line belongs to the Neon exports: the encryption
// pipeline, the ZeroKMS client, and the key providers behind it. `wasm.rs`
// imports its own copies straight from `cipherstash_client`, so gating these
// costs the wasm build nothing and is what lets clippy run clean against
// `wasm32-unknown-unknown` (#145).
#[cfg(not(target_arch = "wasm32"))]
use cipherstash_client::{
    encryption::ScopedCipher,
    eql::{encrypt_eql, encrypt_eql_v3, EqlEncryptOpts},
    zerokms::{KeyProvider, ZeroKMSBuilder, ZeroKMSWithClientKey},
    AutoStrategy,
};
// Shared by the Neon exports below and the wasm module (which imports these
// via `crate::`), so both targets resolve them through this one re-export.
pub(crate) use eql_v3::{
    encrypted_record_from_value, is_encrypted_value, query_output, query_output_v3, storage_output,
    storage_output_v3, validate_eql_version, EncryptedOutput, EqlVersion, QueryOutput,
};
use js_plaintext::JsPlaintext;
#[cfg(not(target_arch = "wasm32"))]
use neon::{
    prelude::*,
    types::{
        extract::{self, Boxed, Json, TryFromJs, TryIntoJs},
        JsBigInt, JsFuture,
    },
};
// Holds the Tokio runtime the Neon exports block on; nothing on wasm uses it.
#[cfg(not(target_arch = "wasm32"))]
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
#[cfg(not(target_arch = "wasm32"))]
use stack_auth::{AuthStrategy, SecretToken, ServerError};
#[cfg(not(target_arch = "wasm32"))]
use std::collections::BTreeMap;
use std::{borrow::Cow, collections::HashMap, sync::Arc};
#[cfg(not(target_arch = "wasm32"))]
use tokio::runtime::Runtime;

#[cfg(test)]
extern crate quickcheck;
#[cfg(test)]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone)]
struct Client {
    cipher: Arc<ScopedZeroKMS>,
    zerokms: Arc<ZeroKMSWithClientKey<NodeAuthStrategy>>,
    encrypt_config: Arc<HashMap<Identifier, ColumnConfig>>,
    /// `encrypt_config` with `include_original` forced off on every match
    /// index — what the encrypt-query entry points use, so query blooms stay
    /// token-only. See [`query_config_map`].
    query_config: Arc<HashMap<Identifier, ColumnConfig>>,
    /// EQL wire version this client emits. Decryption accepts both formats
    /// regardless of this setting.
    eql_version: EqlVersion,
}

#[cfg(not(target_arch = "wasm32"))]
impl Finalize for Client {}

/// Re-export EqlCiphertext as Encrypted for backward compatibility.
///
/// `EqlCiphertext` is the EQL v2.3 storage payload — a discriminated enum that is either
/// a scalar `Encrypted` payload (`k = "ct"`) or a structured `SteVec` payload (`k = "sv"`).
/// The MessagePack-Base85 ciphertext lives at `c` on the scalar variant, or at `sv[0].c`
/// for the SteVec variant.
pub type Encrypted = EqlCiphertext;

/// What type of value was received in a query
#[derive(Debug, Clone)]
pub enum ReceivedKind {
    String(String),
    Number(f64),
    Boolean(bool),
    BigInt(i64),
    JsonObject,
    JsonArray,
    JsonScalar(String),
    Date,
}

impl std::fmt::Display for ReceivedKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::String(s) => write!(f, "String \"{}\"", truncate_for_error(s, 30)),
            Self::Number(n) => write!(f, "Number {}", n),
            Self::Boolean(b) => write!(f, "Boolean {}", b),
            Self::BigInt(v) => write!(f, "BigInt {}n", v),
            Self::JsonObject => write!(f, "JSON object"),
            Self::JsonArray => write!(f, "JSON array"),
            Self::JsonScalar(s) => write!(f, "JSON scalar {}", s),
            Self::Date => write!(f, "Date"),
        }
    }
}

impl ReceivedKind {
    /// Introspect JSON values so object/array are distinguished.
    pub fn from_json(value: &serde_json::Value) -> Self {
        match value {
            serde_json::Value::Object(_) => Self::JsonObject,
            serde_json::Value::Array(_) => Self::JsonArray,
            serde_json::Value::String(s) => Self::JsonScalar(format!("\"{}\"", s)),
            serde_json::Value::Number(n) => Self::JsonScalar(n.to_string()),
            serde_json::Value::Bool(b) => Self::JsonScalar(b.to_string()),
            serde_json::Value::Null => Self::JsonScalar("null".to_string()),
        }
    }
}

/// What type of value was expected
#[derive(Debug, Clone, Copy)]
pub enum ExpectedKind {
    JsonObjectOrArray,
    StringPathOrJsonObjectOrArray,
    StringOrNumber,
    ValueSelectorObject,
}

impl std::fmt::Display for ExpectedKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JsonObjectOrArray => write!(f, "JSON object or array"),
            Self::StringPathOrJsonObjectOrArray => {
                write!(f, "String (JSON path) or JSON object/array")
            }
            Self::StringOrNumber => write!(f, "String or Number"),
            Self::ValueSelectorObject => write!(
                f,
                "JSON object {{\"path\": <JSON path string>, \"value\": <scalar JSON value>}}"
            ),
        }
    }
}

/// Wrapper for bounded display of potentially large strings
#[derive(Debug, Clone)]
pub struct Truncated<'a> {
    value: std::borrow::Cow<'a, str>,
    max_len: usize,
}

impl<'a> Truncated<'a> {
    pub fn new(value: impl Into<std::borrow::Cow<'a, str>>, max_len: usize) -> Self {
        Self {
            value: value.into(),
            max_len,
        }
    }

    pub fn path(value: impl Into<std::borrow::Cow<'a, str>>) -> Self {
        Self::new(value, 50)
    }
}

impl std::fmt::Display for Truncated<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.value.chars().count() <= self.max_len {
            write!(f, "{}", self.value)
        } else {
            let truncated: String = self.value.chars().take(self.max_len).collect();
            write!(f, "{}...", truncated)
        }
    }
}

/// Hints for InvalidQueryInput errors
#[derive(Debug, Clone, Copy)]
pub enum QueryInputHint {
    UseSelectorForPath,
    WrapInObject,
    WrapNumberInObject,
    WrapBooleanInObject,
    UsePathOrObject,
    BigIntNotJson,
    UseOrderingScalar,
    UseValueSelectorObject,
}

impl std::fmt::Display for QueryInputHint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UseSelectorForPath => write!(f, "For path queries like '$.field', use queryOp: 'ste_vec_selector'. For containment queries, wrap the value in an object: {{\"field\": \"value\"}}."),
            Self::WrapInObject => write!(f, "Wrap the value in a JSON object: {{\"field\": value}}."),
            Self::WrapNumberInObject => write!(f, "Wrap the number in a JSON object to query by value: {{\"field\": <number>}}."),
            Self::WrapBooleanInObject => write!(f, "Wrap the boolean in a JSON object to query by value: {{\"field\": <boolean>}}."),
            Self::UsePathOrObject => write!(f, "Use a JSON path string like '$.field' for path queries, or a JSON object like {{\"field\": value}} for containment queries."),
            Self::BigIntNotJson => write!(f, "BigInt values cannot appear in JSON documents; wrap a Number within the safe integer range in a JSON object instead: {{\"field\": <number>}}."),
            Self::UseOrderingScalar => write!(f, "Use a String or Number for ordering comparisons. For exact equality at a path, use queryOp: 'ste_vec_value_selector'."),
            Self::UseValueSelectorObject => write!(f, "Use exactly {{\"path\": \"$.field\", \"value\": <string, number, boolean, or null>}}. Objects and arrays require a containment query."),
        }
    }
}

/// Reasons for JSON path errors
#[derive(Debug, Clone, Copy)]
pub enum JsonPathReason {
    Empty,
    MissingDollar,
}

impl std::fmt::Display for JsonPathReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "path cannot be empty"),
            Self::MissingDollar => write!(f, "path must start with '$'"),
        }
    }
}

/// Hints for JSON path errors
#[derive(Debug, Clone)]
pub enum JsonPathHint {
    TryPrefix(String),
}

impl std::fmt::Display for JsonPathHint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TryPrefix(path) => write!(f, "Try: '$.{}' or '$[\"{}\"]'.", path, path),
        }
    }
}

/// Every error this crate returns to JavaScript.
///
/// # The `code` contract
///
/// A variant's `#[diagnostic(code(..))]` IS the `ProtectErrorCode` a caller
/// reads off the thrown JS error — the string is carried across both bindings
/// verbatim, not re-derived on the other side. A variant with no code reaches
/// JS as `UNKNOWN`, which is the honest answer for the `#[error(transparent)]`
/// wrappers whose text belongs to cipherstash-client.
///
/// It used to work the other way around: `Display` was the only thing that
/// crossed, and `src/errors.ts` recovered the code by matching that prose
/// against a table of fourteen prefixes and substrings. Three of those
/// patterns — `'requires plaintext_type: json'`, `'requires plaintext_type:
/// text'` and `'unsupported config version'` — were matching wording owned by
/// **cipherstash-config**, so an unrelated reword upstream would silently
/// downgrade a caller's error to `UNKNOWN` with nothing in this repo failing
/// (#146).
///
/// Three of fourteen is the whole problem, not a small part of it, because
/// nothing distinguished them: `' index configured'` reads like an upstream
/// phrase and is this crate's own [`Self::MissingIndex`]. Which patterns were
/// safe could only be established by going and looking.
///
/// Two rules keep that from coming back:
///
/// - The codes live here and nowhere else. `src/errors.ts` declares the same
///   set as a TypeScript union, and `src/errorCodes.test.ts` reads this file
///   to prove the two agree.
/// - Nothing may be routed by message text. Where a code depends on which
///   *upstream* variant was raised, match the variant — see the
///   `From<ConfigError>` impl below, which is where those same three codes are
///   decided now, and where a rename upstream is a compile error.
#[derive(thiserror::Error, Debug, miette::Diagnostic)]
pub enum Error {
    #[error("Credential error: {0}")]
    Credentials(String),
    #[error(transparent)]
    ZeroKMSBuilder(#[from] ZeroKMSBuilderError),
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    ZeroKMS(#[from] zerokms::Error),
    #[error(transparent)]
    TypeParse(#[from] TypeParseError),
    #[error(transparent)]
    Encryption(#[from] EncryptionError),
    #[error(transparent)]
    Eql(#[from] EqlError),
    #[error("protect-ffi invariant violation: {0}. This is a bug in protect-ffi. Please file an issue at https://github.com/cipherstash/protectjs-ffi/issues.")]
    #[diagnostic(code("INVARIANT_VIOLATION"))]
    InvariantViolation(String),
    /// An unknown `queryOp` wire value, raised from [`query_op::QueryOpName`]'s
    /// `Deserialize`. Carries serde's fully-formed message — which already
    /// names the value and lists the accepted set — so `#[error("{0}")]`
    /// rather than a format of its own.
    ///
    /// Not reached by `?` on a serde error directly: the deserializer hands
    /// back an opaque `Error::custom`, so the routing happens in the
    /// `From` impls below, keyed on [`query_op::UNKNOWN_QUERY_OP_PREFIX`].
    #[error("{0}")]
    #[diagnostic(code("UNKNOWN_QUERY_OP"))]
    UnknownQueryOp(String),
    #[error(transparent)]
    Parse(serde_json::Error),
    #[error("column {}.{} not found in Encrypt config", _0.table, _0.column)]
    #[diagnostic(code("UNKNOWN_COLUMN"))]
    UnknownColumn(Identifier),
    #[error(transparent)]
    RecordDecryptError(#[from] RecordDecryptError),
    #[error("Column '{column}' does not have a '{index_type}' index configured. {hint}")]
    #[diagnostic(code("MISSING_INDEX"))]
    MissingIndex {
        column: String,
        index_type: String,
        hint: String,
    },
    #[error(
        "Invalid query input for '{query_op}': received {received}, expected {expected}. {hint}"
    )]
    #[diagnostic(code("INVALID_QUERY_INPUT"))]
    InvalidQueryInput {
        query_op: SteVecQueryOpKind,
        received: ReceivedKind,
        expected: ExpectedKind,
        hint: QueryInputHint,
    },
    #[error("Invalid match query on column '{column}': {source}. Use a longer search term.")]
    #[diagnostic(code("SHORT_MATCH_NEEDLE"))]
    ShortMatchNeedle {
        column: String,
        source: EncryptionError,
    },
    #[error("Invalid JSON path '{path}': {reason}. {hint}")]
    #[diagnostic(code("INVALID_JSON_PATH"))]
    InvalidJsonPath {
        path: Truncated<'static>,
        reason: JsonPathReason,
        hint: JsonPathHint,
    },
    /// A [`ConfigError`] with no code of its own. The three that DO carry one
    /// are the variants below; [`From<ConfigError>`] decides which.
    #[error(transparent)]
    Config(ConfigError),
    #[error(transparent)]
    #[diagnostic(code("STE_VEC_REQUIRES_JSON_CAST_AS"))]
    SteVecRequiresJsonCastAs(ConfigError),
    #[error(transparent)]
    #[diagnostic(code("MATCH_REQUIRES_TEXT"))]
    MatchRequiresText(ConfigError),
    #[error(transparent)]
    #[diagnostic(code("UNSUPPORTED_CONFIG_VERSION"))]
    UnsupportedConfigVersion(ConfigError),
    #[error("Invalid eqlVersion {0}: expected 2 or 3")]
    #[diagnostic(code("INVALID_EQL_VERSION"))]
    InvalidEqlVersion(u8),
    #[error(
        "eqlVersion 2 cannot emit ste_vec ciphertexts with cipherstash-client 0.42; use eqlVersion 3"
    )]
    SteVecRequiresV3,
    #[error("Column '{column}' cannot be represented in EQL v3: {reason}. {hint}")]
    #[diagnostic(code("EQL_V3_UNSUPPORTED_COLUMN"))]
    NoV3Domain {
        column: String,
        reason: String,
        hint: String,
    },
    #[error("EQL v3 conversion failed: {0}")]
    #[diagnostic(code("EQL_V3_CONVERSION_FAILED"))]
    FromV2(#[from] eql_bindings::from_v2::FromV2Error),
    /// A natively-emitted v3 payload failed the target domain's strict parse.
    /// Carries the same code as [`Self::FromV2`] — a caller branching on
    /// `EQL_V3_CONVERSION_FAILED` cares that the v3 payload was refused, not
    /// which of the two paths refused it.
    #[error("EQL v3 conversion failed: native payload did not parse as {domain}: {source}")]
    #[diagnostic(code("EQL_V3_CONVERSION_FAILED"))]
    V3NativeParse {
        domain: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("Invalid EQL ciphertext: {0}")]
    #[diagnostic(code("INVALID_CIPHERTEXT"))]
    InvalidCiphertext(#[from] zerokms::DecryptError),
    #[error("Invalid EQL ciphertext: v3 SteVec selector must be 16 bytes of hexadecimal")]
    #[diagnostic(code("INVALID_CIPHERTEXT"))]
    InvalidSteVecSelector,
}

impl Error {
    /// `Some` when a deserialization failure is an unknown `queryOp`.
    ///
    /// The prefix match is the part of this change that did not get to be
    /// structural. `QueryOpName`'s `Deserialize` rejects an unknown wire value
    /// from inside serde — which is what makes the failure name the `queryOp`
    /// field rather than surfacing later from query preparation (see the
    /// `query_op` module docs) — and serde's `de::Error::custom` takes a
    /// `Display`, not a payload. Nothing typed survives to the far side.
    ///
    /// It is still worth doing here rather than in `src/errors.ts`, where it
    /// used to live. This sits beside [`query_op::UNKNOWN_QUERY_OP_PREFIX`],
    /// the constant that defines the message, in the same crate and the same
    /// review diff, and `query_op`'s tests pin that constant — so a change
    /// that would break the mapping fails `cargo test`, rather than silently
    /// degrading a caller's `code` to `UNKNOWN` at runtime.
    ///
    /// Both boundaries route through this: the Neon query entries via
    /// `decode_coded_json`, the wasm entry via `wasm::from_js_value`.
    pub(crate) fn unknown_query_op(message: &str) -> Option<Self> {
        message
            .starts_with(query_op::UNKNOWN_QUERY_OP_PREFIX)
            .then(|| Error::UnknownQueryOp(message.to_string()))
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::unknown_query_op(&err.to_string()).unwrap_or(Error::Parse(err))
    }
}

/// Routes a [`ConfigError`] to the [`Error`] variant carrying the right code.
///
/// Three config failures are worth naming to a caller: a `ste_vec` index on a
/// non-JSON column, a `match` index on a non-text column, and a config `v` this
/// build does not support. All three arrive as one upstream type, so the code
/// has to be decided from the variant — which is the point. These are exactly
/// the three codes `src/errors.ts` used to decide from the message, and the
/// only three whose patterns matched wording this repo did not own.
///
/// A rename or removal upstream now fails this match at compile time. A NEW
/// upstream variant still falls to [`Error::Config`] and reaches JS as
/// `UNKNOWN` — the same as today, but visible here rather than buried in a
/// substring table.
impl From<ConfigError> for Error {
    fn from(err: ConfigError) -> Self {
        match err {
            e @ ConfigError::SteVecRequiresJson { .. } => Self::SteVecRequiresJsonCastAs(e),
            e @ ConfigError::MatchRequiresText { .. } => Self::MatchRequiresText(e),
            e @ ConfigError::UnsupportedVersion { .. } => Self::UnsupportedConfigVersion(e),
            other => Self::Config(other),
        }
    }
}

impl Error {
    /// The human-readable diagnostic message and stable machine-readable code
    /// carried across either JavaScript boundary.
    ///
    /// `miette::Diagnostic` uses this error's [`Display`](std::fmt::Display)
    /// implementation as its primary message; the code comes from the
    /// variant's `#[diagnostic(code(..))]`. Keeping the extraction together
    /// makes the Neon, wasm, and fallible-bulk representations agree.
    pub(crate) fn diagnostic_parts(&self) -> (String, Option<String>) {
        (self.to_string(), self.error_code())
    }

    /// The `ProtectErrorCode` this error crosses the boundary with, if it has
    /// one. `None` becomes `UNKNOWN` on the JS side.
    ///
    /// Spelled `error_code` rather than `code` so it cannot be confused with
    /// (or accidentally recurse into) [`miette::Diagnostic::code`], which is
    /// where the value actually comes from.
    pub(crate) fn error_code(&self) -> Option<String> {
        miette::Diagnostic::code(self).map(|code| code.to_string())
    }
}

/// JS-backed [`AuthStrategy`] for the Neon build.
///
/// Holds the strategy object and its `getToken` callable as Neon [`Root`]s,
/// plus a [`Channel`] for invoking them from tokio tasks. Mirrors
/// `wasm::JsAuthStrategy` but uses Neon's cross-thread invocation model
/// instead of wasm's single-threaded one.
///
/// `getToken()` is called on every ZeroKMS request — caching is the JS
/// strategy's responsibility, matching the wasm path.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) struct NeonJsAuthStrategy {
    strategy: Arc<Root<JsObject>>,
    get_token: Arc<Root<JsFunction>>,
    channel: Channel,
}

#[cfg(not(target_arch = "wasm32"))]
impl NeonJsAuthStrategy {
    /// Build from a JS strategy object plus the [`Channel`] for the isolate
    /// that produced it. The channel must come from the calling JS context
    /// (the `#[neon::export]` macro injects one for any async fn whose first
    /// argument is `Channel`) — sharing a process-wide channel would route
    /// callbacks to the wrong isolate when the addon is loaded from multiple
    /// Node Worker threads, panicking inside `Root::to_inner`.
    ///
    /// The stored channel is unref'd so a `Client` holding a JS-backed
    /// strategy doesn't pin libuv's event loop. The per-call promise
    /// settlement channel that `#[neon::export]` async wraps each encrypt
    /// / decrypt with is still referenced for the duration of that call,
    /// so awaited operations complete normally; only the persistent auth
    /// channel stops blocking process exit when idle.
    async fn from_root(strategy: Root<JsObject>, channel: Channel) -> Result<Self, Error> {
        let strategy = Arc::new(strategy);
        let strategy_for_lookup = Arc::clone(&strategy);
        // Use a clone for the lookup `send` so we can move the original
        // into the JS-thread closure, unref it there (which requires a
        // `Cx`), and return it back to be stored on `self`.
        let sender = channel.clone();
        // Retrieve the property as a raw JsValue and do an explicit
        // `is_a` + `downcast` check, so a missing or non-callable
        // `getToken` becomes a clean `Result::Err` rather than a `Throw`
        // bubbling through the channel callback (which surfaces as an
        // unhandled rejection on the JS side even when the Rust caller
        // catches the resulting JoinError).
        let lookup: Result<(Root<JsFunction>, Channel), String> = sender
            .send(move |mut cx| {
                let mut channel = channel;
                let obj = strategy_for_lookup.to_inner(&mut cx);
                let raw: Handle<JsValue> = obj.prop(&mut cx, "getToken").get()?;
                if raw.is_a::<JsUndefined, _>(&mut cx) || raw.is_a::<JsNull, _>(&mut cx) {
                    channel.unref(&mut cx);
                    return Ok(Err("opts.strategy.getToken is missing".to_string()));
                }
                let func = match raw.downcast::<JsFunction, _>(&mut cx) {
                    Ok(f) => f,
                    Err(_) => {
                        channel.unref(&mut cx);
                        return Ok(Err("opts.strategy.getToken is not a function".to_string()));
                    }
                };
                channel.unref(&mut cx);
                Ok(Ok((func.root(&mut cx), channel)))
            })
            .await
            .map_err(|e| Error::Credentials(format!("strategy.getToken lookup failed: {e}")))?;
        let (get_token, channel) = lookup.map_err(Error::Credentials)?;
        Ok(Self {
            strategy,
            get_token: Arc::new(get_token),
            channel,
        })
    }
}

/// Best-effort conversion of a thrown JS value into a Rust string. Wrapped
/// in `try_catch` because `to_string` itself can throw (e.g. a Proxy with
/// a throwing trap, an object whose `toString` throws). Any failure falls
/// back to a generic message — and crucially clears the pending N-API
/// exception so the channel callback returns cleanly.
#[cfg(not(target_arch = "wasm32"))]
fn thrown_to_string<'cx, 'h, C: Context<'cx>>(thrown: Handle<'h, JsValue>, cx: &mut C) -> String {
    cx.try_catch(|cx| Ok(thrown.to_string(cx)?.value(cx)))
        .unwrap_or_else(|_| "<non-stringifiable error>".to_string())
}

/// Build an attributable message for a reconstructed auth failure. Falls back
/// to the failure `code` (or a generic phrase when that's absent too) if the
/// strategy supplied no `error.message`, so a reconstructed error is never
/// blank. Codes that map to a fixed [`AuthError`] variant ignore this message;
/// it only surfaces for the `Custom` fallthrough. Shared by the Neon and wasm
/// seams so both reconstruct the same message.
pub(crate) fn auth_failure_message(code: &str, message: String) -> String {
    if !message.is_empty() {
        message
    } else if !code.is_empty() {
        format!("auth failure: {code}")
    } else {
        "strategy.getToken failed with an unspecified auth failure".to_string()
    }
}

/// Read `obj[key]` as a `String`, or `None` if it's absent or not a JS string.
///
/// The `get()` runs through `cx.try_catch` because this is called at
/// promise-settle time on a user-controlled object: a throwing getter must have
/// its pending N-API exception cleared (not merely discarded via `.ok()`), or
/// it dangles on the env — the same invariant the settle closure's top-level
/// reads uphold.
#[cfg(not(target_arch = "wasm32"))]
fn prop_string<'cx>(cx: &mut Cx<'cx>, obj: Handle<JsObject>, key: &str) -> Option<String> {
    let value: Handle<JsValue> = cx.try_catch(|cx| obj.prop(cx, key).get()).ok()?;
    value.downcast::<JsString, _>(cx).ok().map(|s| s.value(cx))
}

/// Read `obj[key]` as an object handle, or `None` if it's absent or not a JS
/// object. Guarded with `try_catch` for the same reason as [`prop_string`].
#[cfg(not(target_arch = "wasm32"))]
fn prop_object<'cx>(
    cx: &mut Cx<'cx>,
    obj: Handle<JsObject>,
    key: &str,
) -> Option<Handle<'cx, JsObject>> {
    let value: Handle<JsValue> = cx.try_catch(|cx| obj.prop(cx, key).get()).ok()?;
    value.downcast::<JsObject, _>(cx).ok()
}

/// A protect-ffi-internal error for a strategy that returned a malformed shape
/// (not an auth-domain outcome). Kept as `Server` — the shape it took before
/// this reconstruction existed.
#[cfg(not(target_arch = "wasm32"))]
fn strategy_protocol_error(msg: impl Into<String>) -> AuthError {
    AuthError::Server(ServerError(msg.into()))
}

/// Reconstruct a [`stack_auth::AuthError`] from an `@cipherstash/auth`
/// `AuthFailure` (`{ ...payload, type, error, help?, url? }`) via
/// [`AuthError::from_error_code`], so a strategy failure crosses back into Rust
/// as the real typed error — preserving its code and any structured payload
/// (e.g. `WORKSPACE_MISMATCH`'s `expected`/`actual`) — rather than a flattened
/// `Server`. Unknown / foreign codes fall through to `AuthError::Custom`.
///
/// Mirrors the wasm seam: the structured payload is threaded by JSON-serialising
/// the whole failure object and dropping the reserved `type`/`error`/`help`/`url`
/// keys, so both runtimes reconstruct the same variant. Every property read
/// runs through a `try_catch` (directly, via `prop_*`, or via `Json`) so a
/// throwing getter on the user-controlled failure object clears its pending
/// N-API exception instead of leaving it dangling.
#[cfg(not(target_arch = "wasm32"))]
fn neon_failure_to_auth_error<'cx>(cx: &mut Cx<'cx>, failure: Handle<'cx, JsValue>) -> AuthError {
    let obj = match failure.downcast::<JsObject, _>(cx) {
        Ok(o) => o,
        Err(_) => return strategy_protocol_error("strategy.getToken failed"),
    };
    let code = prop_string(cx, obj, "type").unwrap_or_default();
    // The message lives on the nested `error` (a live JS `Error`).
    let message = match prop_object(cx, obj, "error") {
        Some(err_obj) => prop_string(cx, err_obj, "message").unwrap_or_default(),
        None => String::new(),
    };
    // Thread the structured payload the same way the wasm seam does: serialise
    // the whole failure object, then drop the reserved keys. `Json::try_from_js`
    // goes through `JSON.stringify`, which invokes getters, so guard it with
    // `try_catch`; a throw (or a non-serialisable field) degrades to an empty
    // payload (i.e. `Custom`).
    let mut payload = cx
        .try_catch(|cx| {
            Json::<serde_json::Map<String, serde_json::Value>>::try_from_js(cx, failure)
        })
        .ok()
        .and_then(|result| result.ok())
        .map(|Json(map)| map)
        .unwrap_or_default();
    for key in ["type", "error", "help", "url"] {
        payload.remove(key);
    }
    AuthError::from_error_code(&code, auth_failure_message(&code, message), &payload)
}

#[cfg(not(target_arch = "wasm32"))]
impl AuthStrategy for &NeonJsAuthStrategy {
    async fn get_token(self) -> Result<stack_auth::ServiceToken, AuthError> {
        let strategy = Arc::clone(&self.strategy);
        let get_token = Arc::clone(&self.get_token);
        let channel = self.channel.clone();

        // The channel-callback body is wrapped in `cx.try_catch` so that
        // *any* synchronous throw (a `getToken` that throws, a `.then`
        // getter that throws, a downcast that needs to consult a Proxy
        // trap, etc.) is caught and converted to a plain `Err(String)`.
        // Without `try_catch`, a `Throw` propagated out of the closure
        // leaves a pending N-API exception on the env that surfaces as an
        // unhandled JS rejection even when the Rust caller maps the
        // resulting `JoinError` into a clean error.
        //
        // The inner `Result<JsFuture<...>, String>` is the structural
        // outcome (a future to await vs. a synthesised error message);
        // the outer `try_catch` only fires on a real throw.
        let outer: Result<JsFuture<Result<String, AuthError>>, AuthError> = channel
            .send(move |mut cx| {
                let outcome: Result<JsFuture<Result<String, AuthError>>, AuthError> = match cx
                    .try_catch(
                        |cx| -> NeonResult<Result<JsFuture<Result<String, AuthError>>, AuthError>> {
                            let strategy_h = strategy.to_inner(cx);
                            let func_h = get_token.to_inner(cx);
                            let args: [Handle<JsValue>; 0] = [];
                            let result = func_h.call(cx, strategy_h, args)?;
                            let promise = match result.downcast::<JsPromise, _>(cx) {
                                Ok(p) => p,
                                Err(_) => {
                                    return Ok(Err(strategy_protocol_error(
                                        "strategy.getToken did not return a Promise",
                                    )))
                                }
                            };
                            // Inner `to_future` closure: structural mismatches
                            // (wrong type for resolved value, missing/non-string
                            // `token`) are returned as `Ok(Err(...))`. The
                            // property reads on the resolved object (`failure`,
                            // `data`, `token`) are user-reachable getters that
                            // can throw, and they run at promise-settle time —
                            // outside the outer try_catch's dynamic extent — so
                            // each gets its own try_catch: returning `Ok(Err(..))`
                            // on a bare `Err` would leave a pending N-API
                            // exception in the callback context.
                            let fut = promise.to_future(cx, |mut cx, settled| {
                                match settled {
                                    Ok(v) => {
                                        let obj =
                                            match v.downcast::<JsObject, _>(&mut cx) {
                                                Ok(o) => o,
                                                Err(_) => return Ok(Err(strategy_protocol_error(
                                                    "strategy.getToken did not return an object",
                                                ))),
                                            };
                                        // Accept both `@cipherstash/auth` shapes:
                                        //   >= 0.41: a `@byteslice/result` `Result` —
                                        //            `{ data: TokenResult }` on success,
                                        //            `{ failure: AuthFailure }` on error.
                                        //   <= 0.40 / custom strategies: the bare
                                        //            `TokenResult`, with `token` at the top
                                        //            level (the documented
                                        //            `getToken(): Promise<{ token }>` contract).
                                        let failure: Handle<JsValue> = match cx
                                            .try_catch(|cx| obj.prop(cx, "failure").get())
                                        {
                                            Ok(v) => v,
                                            Err(thrown) => {
                                                return Ok(Err(strategy_protocol_error(format!(
                                                    "reading 'failure' field threw: {}",
                                                    thrown_to_string(thrown, &mut cx),
                                                ))))
                                            }
                                        };
                                        if !failure.is_a::<JsUndefined, _>(&mut cx)
                                            && !failure.is_a::<JsNull, _>(&mut cx)
                                        {
                                            return Ok(Err(neon_failure_to_auth_error(
                                                &mut cx, failure,
                                            )));
                                        }
                                        // Unwrap the `data` envelope when present (0.41+);
                                        // otherwise read `token` from the bare result (<= 0.40).
                                        let data_val: Handle<JsValue> = match cx
                                            .try_catch(|cx| obj.prop(cx, "data").get())
                                        {
                                            Ok(v) => v,
                                            Err(thrown) => {
                                                return Ok(Err(strategy_protocol_error(format!(
                                                    "reading 'data' field threw: {}",
                                                    thrown_to_string(thrown, &mut cx),
                                                ))))
                                            }
                                        };
                                        let source = match data_val.downcast::<JsObject, _>(&mut cx)
                                        {
                                            Ok(d) => d,
                                            Err(_) => obj,
                                        };
                                        let raw: Handle<JsValue> = match cx
                                            .try_catch(|cx| source.prop(cx, "token").get())
                                        {
                                            Ok(v) => v,
                                            Err(thrown) => {
                                                return Ok(Err(strategy_protocol_error(format!(
                                                    "reading 'token' field threw: {}",
                                                    thrown_to_string(thrown, &mut cx),
                                                ))))
                                            }
                                        };
                                        if raw.is_a::<JsUndefined, _>(&mut cx)
                                            || raw.is_a::<JsNull, _>(&mut cx)
                                        {
                                            return Ok(Err(strategy_protocol_error(
                                                "missing 'token' field",
                                            )));
                                        }
                                        let token = match raw.downcast::<JsString, _>(&mut cx) {
                                            Ok(s) => s,
                                            Err(_) => {
                                                return Ok(Err(strategy_protocol_error(
                                                    "'token' field is not a string",
                                                )))
                                            }
                                        };
                                        Ok(Ok(token.value(&mut cx)))
                                    }
                                    Err(err) => Ok(Err(strategy_protocol_error(format!(
                                        "strategy.getToken rejected: {}",
                                        thrown_to_string(err, &mut cx),
                                    )))),
                                }
                            })?;
                            Ok(Ok(fut))
                        },
                    ) {
                    Ok(inner) => inner,
                    Err(thrown) => Err(strategy_protocol_error(format!(
                        "strategy.getToken threw synchronously: {}",
                        thrown_to_string(thrown, &mut cx),
                    ))),
                };
                Ok(outcome)
            })
            .await
            .map_err(|e| {
                AuthError::Server(ServerError(format!("strategy callback failed: {e}")))
            })?;

        let js_future = outer?;
        let token_result = js_future.await.map_err(|e| {
            AuthError::Server(ServerError(format!("strategy promise await failed: {e}")))
        })?;
        token_result.map(|s| stack_auth::ServiceToken::new(SecretToken::new(s)))
    }
}

/// Auth strategy held by the Neon-side [`Client`]. Either the
/// filesystem/env-backed [`AutoStrategy`] (built from credentials in opts
/// or the profile store) or a [`NeonJsAuthStrategy`] supplied by the
/// caller via `opts.strategy`.
///
/// `AutoStrategy` is boxed because it's substantially larger than the
/// JS-backed variant — without indirection clippy flags the size
/// imbalance as `large_enum_variant`.
#[cfg(not(target_arch = "wasm32"))]
enum NodeAuthStrategy {
    Auto(Box<AutoStrategy>),
    JsBacked(NeonJsAuthStrategy),
}

#[cfg(not(target_arch = "wasm32"))]
impl AuthStrategy for &NodeAuthStrategy {
    async fn get_token(self) -> Result<stack_auth::ServiceToken, AuthError> {
        match self {
            NodeAuthStrategy::Auto(s) => (&**s).get_token().await,
            NodeAuthStrategy::JsBacked(s) => s.get_token().await,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
type ScopedZeroKMS = ScopedCipher<NodeAuthStrategy>;

/// Makes `#[serde(deny_unknown_fields)]` fire on the wasm boundary as well as
/// the Neon one. Carried by every options struct that doesn't already flatten
/// something; deserializes nothing and exists only for where it is placed.
///
/// A struct with a `#[serde(flatten)]` field reads itself through
/// `Deserializer::deserialize_map` instead of `deserialize_struct`, and on wasm
/// that is the whole difference. `serde_wasm_bindgen`'s `deserialize_struct`
/// never enumerates the JS object: it looks up each *expected* field by name
/// with `ObjectExt::get_with_ref_key` — a wasm-bindgen `indexing_getter`, i.e.
/// plain `obj[key]`. A key the struct doesn't declare is invisible, so
/// `deny_unknown_fields` has nothing to reject and the attribute is a silent
/// no-op. `deserialize_map` enumerates, so every key reaches serde and the
/// leftover check works. The Neon boundary is `JSON.stringify` → `serde_json`,
/// which has always enumerated; it needs no help.
///
/// Structs that already flatten — [`ClientOpts`](client_options::ClientOpts),
/// [`EnsureKeysetOpts`] — are on the map path and don't carry this.
///
/// # What the map path costs
///
/// `deserialize_map` tries `js_sys::try_iter` FIRST and only falls back to
/// `Object::entries` (serde-wasm-bindgen `de.rs`, `deserialize_map`) — unlike
/// `deserialize_any`, which guards the iterator arm on `Map`. So:
///
/// - An options object carrying `Symbol.iterator`, own or inherited, is read
///   through the iterator and its own properties are ignored entirely. A
///   `lockContext` present as a property but not yielded is silently dropped —
///   the class of bug this marker exists to close, reopened on a shape almost
///   nobody passes. `Object::assign` in `wasm::new_client` does not close it
///   either: an own enumerable `[Symbol.iterator]` survives the copy.
/// - An array of `[k, v]` pairs, and a JS `Map`, are now ACCEPTED where
///   `deserialize_struct` rejected them. The array form also bypasses
///   `encode_plaintext`, so a `bigint` plaintext reaches `JsPlaintext::Number`
///   and loses precision above 2^53.
///
/// Two diagnostics regressions, both from serde's flatten path buffering the
/// map and reporting at its closing brace:
///
/// - A misspelled REQUIRED field reports `missing field \`indexType\`` and
///   never names `indexTyp`. Without the marker it read `unknown field
///   \`indexTyp\`, expected \`indexType\``, which said both.
/// - The `expected one of ...` list is gone from every rejection.
///
/// Per-key cost on wasm, for valid input: `deserialize_struct` handed serde
/// `&'static str` field names with no Rust allocation. The map path allocates a
/// JS array of pair-arrays per object plus a fresh `String` per key, known keys
/// included — roughly 5N `String`s on an N-payload `encryptBulk`. Small against
/// the crypto, but it is not nothing.
///
/// `has_flatten` also suppresses `visit_seq` and emits no `FIELDS` const, so
/// these structs no longer accept the JSON-array form of a struct.
///
/// # What the map path changes for valid input
///
/// - An unknown key's *value* is buffered into serde's `Content` before the
///   rejection. A key holding something serde can't represent (a function)
///   reports that instead of `unknown field`. Rejected either way.
/// - Enumeration includes keys whose value is `undefined`, so
///   `{...opts, typo: undefined}` is rejected here and accepted on Neon, where
///   `JSON.stringify` drops the key before serde sees it. The targets differ in
///   strictness about a mistake; they agree on every correct input.
/// - It reads own ENUMERABLE properties, where `obj[key]` also walked the
///   prototype chain and saw non-enumerable ones. An options *bag* — an object
///   literal, or a spread of one — is unaffected; a class instance passed as
///   options loses its inherited fields, and a field hidden behind
///   `Object.defineProperty` is dropped. Neon has always been `JSON.stringify`,
///   which is own-enumerable too, so this closes a gap rather than opening one.
///
///   The narrowing reaches further than the entry points that hand serde the
///   caller's object directly: the clones in `wasm.rs` are shallow, so a nested
///   [`LockContext`] — which carries this marker — is read from the caller's own
///   object on every path. `encode_plaintext_list` also returns `opts`
///   untouched when nothing needed encoding, which includes a legitimate empty
///   `plaintexts`, so the bulk entries' top-level bag is narrowed too.
#[derive(Debug, Deserialize)]
pub(crate) struct DenyUnknown {}

/// Per-item outcome from `decryptBulkFallible`.
///
/// The failure arm carries its own code because it is never thrown — it is a
/// value in the returned array, so there is no JS `Error` object for a caller
/// to read `code` off. Before #146 the Neon wrapper reconstructed one in JS by
/// running `inferErrorCode` over `error`, and the wasm entry could not do even
/// that, so its items had no code at all.
#[derive(Debug, Serialize)]
#[serde(untagged)]
enum DecryptResult {
    Success {
        data: JsPlaintext,
    },
    Error {
        error: String,
        /// Absent rather than null when the error has no code, so the shape
        /// matches the declared `code?: ProtectErrorCode`.
        #[serde(skip_serializing_if = "Option::is_none")]
        code: Option<String>,
    },
}

impl DecryptResult {
    /// Builds the failure arm from an [`Error`], keeping message and code in
    /// step — the two are read off the same value here rather than one being
    /// re-derived from the other later.
    fn from_error(err: &Error) -> Self {
        let (message, code) = err.diagnostic_parts();
        Self::Error {
            error: message,
            code,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EncryptOptions {
    plaintext: JsPlaintext,
    column: String,
    table: String,
    lock_context: Option<LockContext>,
    unverified_context: Option<UnverifiedContext>,
    #[serde(flatten)]
    _deny_unknown: DenyUnknown,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EncryptBulkOptions {
    plaintexts: Vec<PlaintextPayload>,
    unverified_context: Option<UnverifiedContext>,
    #[serde(flatten)]
    _deny_unknown: DenyUnknown,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlaintextPayload {
    plaintext: JsPlaintext,
    column: String,
    table: String,
    /// Lock context for this payload. Payloads with different lock_context values
    /// will be encrypted in separate batches to preserve per-payload context binding.
    lock_context: Option<LockContext>,
    #[serde(flatten)]
    _deny_unknown: DenyUnknown,
}

/// Options for encrypting a query term (search predicate)
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EncryptQueryOptions {
    plaintext: JsPlaintext,
    column: String,
    table: String,
    /// The index type to use: "ste_vec", "match", "ore", "unique"
    index_type: String,
    /// Which query operation to perform. Rejected at this boundary if it is
    /// not one of the four accepted spellings — see [`QueryOpName`].
    #[serde(default)]
    query_op: QueryOpName,
    lock_context: Option<LockContext>,
    unverified_context: Option<UnverifiedContext>,
    #[serde(flatten)]
    _deny_unknown: DenyUnknown,
}

fn resolve_eql_version(
    requested: Option<u8>,
    encrypt_config: &HashMap<Identifier, ColumnConfig>,
) -> Result<EqlVersion, Error> {
    let has_ste_vec = encrypt_config.values().any(|column| {
        column
            .indexes
            .iter()
            .any(|index| matches!(index.index_type, IndexType::SteVec { .. }))
    });

    match (requested, has_ste_vec) {
        (Some(version), true) if version == EqlVersion::V2 as u8 => Err(Error::SteVecRequiresV3),
        (Some(version), _) => validate_eql_version(Some(version)),
        (None, true) => Ok(EqlVersion::V3),
        (None, false) => validate_eql_version(None),
    }
}

/// Options for bulk query encryption
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EncryptQueryBulkOptions {
    queries: Vec<QueryPayload>,
    unverified_context: Option<UnverifiedContext>,
    #[serde(flatten)]
    _deny_unknown: DenyUnknown,
}

/// Individual query payload for bulk operations
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QueryPayload {
    plaintext: JsPlaintext,
    column: String,
    table: String,
    index_type: String,
    #[serde(default)]
    query_op: QueryOpName,
    lock_context: Option<LockContext>,
    #[serde(flatten)]
    _deny_unknown: DenyUnknown,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DecryptOptions {
    /// Raw JSON payload — parsed internally so decrypt accepts BOTH the v2
    /// and v3 wire formats regardless of the client's `eqlVersion`.
    ciphertext: serde_json::Value,
    lock_context: Option<LockContext>,
    unverified_context: Option<UnverifiedContext>,
    #[serde(flatten)]
    _deny_unknown: DenyUnknown,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DecryptBulkOptions {
    ciphertexts: Vec<BulkDecryptPayload>,
    unverified_context: Option<UnverifiedContext>,
    #[serde(flatten)]
    _deny_unknown: DenyUnknown,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BulkDecryptPayload {
    /// Raw JSON payload — see [`DecryptOptions::ciphertext`].
    ciphertext: serde_json::Value,
    lock_context: Option<LockContext>,
    #[serde(flatten)]
    _deny_unknown: DenyUnknown,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LockContext {
    identity_claim: Vec<String>,
    #[serde(flatten)]
    _deny_unknown: DenyUnknown,
}

impl From<LockContext> for Vec<zerokms::Context> {
    fn from(val: LockContext) -> Self {
        val.identity_claim
            .into_iter()
            .map(zerokms::Context::IdentityClaim)
            .collect()
    }
}

/// Truncate a string for error messages
fn truncate_for_error(s: &str, max_len: usize) -> String {
    if max_len == 0 {
        return "...".to_string();
    }
    let mut out = String::new();
    let mut iter = s.chars();
    for _ in 0..max_len {
        match iter.next() {
            Some(ch) => out.push(ch),
            None => return s.to_string(),
        }
    }
    if iter.next().is_none() {
        return s.to_string();
    }
    format!("{}...", out)
}

/// Validate a JSON path string
fn validate_json_path(path: &str) -> Result<(), Error> {
    if path.is_empty() {
        return Err(Error::InvalidJsonPath {
            path: Truncated::path(path.to_string()),
            reason: JsonPathReason::Empty,
            hint: JsonPathHint::TryPrefix(path.to_string()),
        });
    }
    if !path.starts_with('$') {
        return Err(Error::InvalidJsonPath {
            path: Truncated::path(path.to_string()),
            reason: JsonPathReason::MissingDollar,
            hint: JsonPathHint::TryPrefix(path.to_string()),
        });
    }
    Ok(())
}

/// Get a description of what an index type is used for
fn index_type_description(index_type: &str) -> &'static str {
    match index_type {
        "ste_vec" => "JSON path and containment queries",
        "ore" => "range comparisons (<, >, <=, >=)",
        "ope" => "range comparisons (<, >, <=, >=)",
        "match" => "full-text search queries",
        "unique" => "exact match queries",
        _ => "unknown query type",
    }
}

/// Format available indexes on a column for error messages
fn format_available_indexes(column_config: &ColumnConfig) -> String {
    let available: Vec<&str> = column_config
        .indexes
        .iter()
        .map(|idx| match &idx.index_type {
            IndexType::SteVec { .. } => "ste_vec",
            IndexType::Match { .. } => "match",
            IndexType::Ore => "ore",
            IndexType::Ope => "ope",
            IndexType::Unique { .. } => "unique",
        })
        .collect();

    if available.is_empty() {
        "No indexes are configured for this column.".to_string()
    } else {
        format!("Available indexes: {}.", available.join(", "))
    }
}

/// Find the matching index from column config by index type name
fn find_index_for_type<'a>(
    column_config: &'a ColumnConfig,
    column_name: &str,
    index_type_name: &str,
) -> Result<&'a Index, Error> {
    column_config
        .indexes
        .iter()
        .find(|idx| {
            matches!(
                (&idx.index_type, index_type_name),
                (IndexType::SteVec { .. }, "ste_vec")
                    | (IndexType::Match { .. }, "match")
                    | (IndexType::Ore, "ore")
                    | (IndexType::Ope, "ope")
                    | (IndexType::Unique { .. }, "unique")
            )
        })
        .ok_or_else(|| {
            let available = format_available_indexes(column_config);
            let description = index_type_description(index_type_name);
            Error::MissingIndex {
                column: column_name.to_string(),
                index_type: index_type_name.to_string(),
                hint: format!(
                    "{} Add an '{}' index to enable {}.",
                    available, index_type_name, description
                ),
            }
        })
}

/// Inferred operation mode for query encryption.
///
/// This determines which EqlOperation to use:
/// - QueryMode: Use EqlOperation::Query (standard query encryption)
/// - StoreMode: Use EqlOperation::Store (for containment queries that need sv array)
#[derive(Debug, Clone, Copy)]
enum InferredQueryMode {
    /// Use EqlOperation::Query with the given QueryOp
    QueryMode(QueryOp),
    /// Use EqlOperation::Store (for JSON containment queries on ste_vec)
    StoreMode,
}

/// Convert JsPlaintext to Plaintext and infer the appropriate operation mode.
///
/// Returns both the converted Plaintext and the inferred operation mode.
///
/// Query mode has different type semantics than storage mode:
/// - SteVecSelector: Always string (JSON path like "$.user.email") → QueryMode
/// - SteVecValueSelector: `{path, value}` exact-match input → QueryMode
/// - SteVecTerm: String/number ordering operand → QueryMode
/// - Default: For SteVec indexes, infers from plaintext type:
///   - String → QueryMode with SteVecSelector (path queries)
///   - Json (Object/Array) → StoreMode (containment queries need sv array)
///   - Other indexes use column's cast_type; QueryMode with Default under
///     eqlVersion 2, StoreMode under eqlVersion 3 — the v3 scalar query
///     operand must carry ALL the column domain's terms (its query twin's
///     domain CHECK requires them), so the terms are generated exactly as
///     storage encryption generates them and query_output hoists them,
///     dropping the ciphertext.
fn to_query_plaintext(
    js_plaintext: &JsPlaintext,
    query_op: QueryOp,
    index_type: &IndexType,
    column_type: cipherstash_client::schema::column::ColumnType,
    eql_version: EqlVersion,
) -> Result<(Plaintext, InferredQueryMode), Error> {
    use cipherstash_client::schema::column::ColumnType;

    match query_op {
        QueryOp::SteVecSelector => {
            // Selector queries expect a string path like "$.user.email"
            // Validate the path if we have a string
            if let JsPlaintext::String(path) = js_plaintext {
                validate_json_path(path)?;
            }
            // Force Text conversion regardless of column type
            let plaintext = js_plaintext.to_plaintext_with_type(ColumnType::Text)?;
            Ok((
                plaintext,
                InferredQueryMode::QueryMode(QueryOp::SteVecSelector),
            ))
        }
        QueryOp::SteVecValueSelector => {
            let value = match js_plaintext {
                JsPlaintext::JsonB(value) => value,
                JsPlaintext::String(value) => {
                    return Err(Error::InvalidQueryInput {
                        query_op: SteVecQueryOpKind::ValueSelector,
                        received: ReceivedKind::String(value.clone()),
                        expected: ExpectedKind::ValueSelectorObject,
                        hint: QueryInputHint::UseValueSelectorObject,
                    });
                }
                JsPlaintext::Number(value) => {
                    return Err(Error::InvalidQueryInput {
                        query_op: SteVecQueryOpKind::ValueSelector,
                        received: ReceivedKind::Number(*value),
                        expected: ExpectedKind::ValueSelectorObject,
                        hint: QueryInputHint::UseValueSelectorObject,
                    });
                }
                JsPlaintext::Boolean(value) => {
                    return Err(Error::InvalidQueryInput {
                        query_op: SteVecQueryOpKind::ValueSelector,
                        received: ReceivedKind::Boolean(*value),
                        expected: ExpectedKind::ValueSelectorObject,
                        hint: QueryInputHint::UseValueSelectorObject,
                    });
                }
                JsPlaintext::BigInt(value) => {
                    return Err(Error::InvalidQueryInput {
                        query_op: SteVecQueryOpKind::ValueSelector,
                        received: ReceivedKind::BigInt(*value),
                        expected: ExpectedKind::ValueSelectorObject,
                        hint: QueryInputHint::UseValueSelectorObject,
                    });
                }
                JsPlaintext::Date(_) => {
                    return Err(Error::InvalidQueryInput {
                        query_op: SteVecQueryOpKind::ValueSelector,
                        received: ReceivedKind::Date,
                        expected: ExpectedKind::ValueSelectorObject,
                        hint: QueryInputHint::UseValueSelectorObject,
                    });
                }
            };

            let valid = value
                .as_object()
                .filter(|object| object.len() == 2)
                .and_then(|object| {
                    let path = object.get("path")?.as_str()?;
                    let value = object.get("value")?;
                    (!value.is_object() && !value.is_array()).then_some(path)
                });
            let Some(path) = valid else {
                return Err(Error::InvalidQueryInput {
                    query_op: SteVecQueryOpKind::ValueSelector,
                    received: ReceivedKind::from_json(value),
                    expected: ExpectedKind::ValueSelectorObject,
                    hint: QueryInputHint::UseValueSelectorObject,
                });
            };
            validate_json_path(path)?;

            let plaintext = js_plaintext.to_plaintext_with_type(ColumnType::Json)?;
            Ok((
                plaintext,
                InferredQueryMode::QueryMode(QueryOp::SteVecValueSelector),
            ))
        }
        QueryOp::SteVecTerm => match js_plaintext {
            JsPlaintext::String(s) => {
                let plaintext = Plaintext::Text(Some(s.clone()));
                Ok((plaintext, InferredQueryMode::QueryMode(QueryOp::SteVecTerm)))
            }
            JsPlaintext::Number(n) => {
                let plaintext = Plaintext::Float(Some(*n));
                Ok((plaintext, InferredQueryMode::QueryMode(QueryOp::SteVecTerm)))
            }
            JsPlaintext::Boolean(b) => Err(Error::InvalidQueryInput {
                query_op: SteVecQueryOpKind::Term,
                received: ReceivedKind::Boolean(*b),
                expected: ExpectedKind::StringOrNumber,
                hint: QueryInputHint::UseOrderingScalar,
            }),
            JsPlaintext::BigInt(v) => Err(Error::InvalidQueryInput {
                query_op: SteVecQueryOpKind::Term,
                received: ReceivedKind::BigInt(*v),
                expected: ExpectedKind::StringOrNumber,
                hint: QueryInputHint::UseOrderingScalar,
            }),
            JsPlaintext::JsonB(value) => Err(Error::InvalidQueryInput {
                query_op: SteVecQueryOpKind::Term,
                received: ReceivedKind::from_json(value),
                expected: ExpectedKind::StringOrNumber,
                hint: QueryInputHint::UseOrderingScalar,
            }),
            JsPlaintext::Date(_) => Err(Error::InvalidQueryInput {
                query_op: SteVecQueryOpKind::Term,
                received: ReceivedKind::Date,
                expected: ExpectedKind::StringOrNumber,
                hint: QueryInputHint::UseOrderingScalar,
            }),
        },
        QueryOp::Default => {
            // For SteVec indexes with Default queryOp, infer from plaintext type
            if matches!(index_type, IndexType::SteVec { .. }) {
                match js_plaintext {
                    JsPlaintext::String(path) => {
                        // String → selector (path queries like "$.user.email")
                        validate_json_path(path)?;
                        let plaintext = js_plaintext.to_plaintext_with_type(ColumnType::Text)?;
                        Ok((
                            plaintext,
                            InferredQueryMode::QueryMode(QueryOp::SteVecSelector),
                        ))
                    }
                    JsPlaintext::JsonB(_) => {
                        // Object/Array → Store mode for containment queries
                        // This produces sv array needed for @> operator matching
                        let plaintext = js_plaintext.to_plaintext_with_type(ColumnType::Json)?;
                        Ok((plaintext, InferredQueryMode::StoreMode))
                    }
                    JsPlaintext::Number(n) => Err(Error::InvalidQueryInput {
                        query_op: SteVecQueryOpKind::Default,
                        received: ReceivedKind::Number(*n),
                        expected: ExpectedKind::StringPathOrJsonObjectOrArray,
                        hint: QueryInputHint::UsePathOrObject,
                    }),
                    JsPlaintext::BigInt(v) => Err(Error::InvalidQueryInput {
                        query_op: SteVecQueryOpKind::Default,
                        received: ReceivedKind::BigInt(*v),
                        expected: ExpectedKind::StringPathOrJsonObjectOrArray,
                        hint: QueryInputHint::BigIntNotJson,
                    }),
                    JsPlaintext::Boolean(b) => Err(Error::InvalidQueryInput {
                        query_op: SteVecQueryOpKind::Default,
                        received: ReceivedKind::Boolean(*b),
                        expected: ExpectedKind::StringPathOrJsonObjectOrArray,
                        hint: QueryInputHint::UsePathOrObject,
                    }),
                    JsPlaintext::Date(_) => Err(Error::InvalidQueryInput {
                        query_op: SteVecQueryOpKind::Default,
                        received: ReceivedKind::Date,
                        expected: ExpectedKind::StringPathOrJsonObjectOrArray,
                        hint: QueryInputHint::UsePathOrObject,
                    }),
                }
            } else {
                // Non-SteVec indexes: use column's storage type (original behavior)
                let plaintext = js_plaintext.to_plaintext_with_type(column_type)?;
                let mode = match eql_version {
                    EqlVersion::V2 => InferredQueryMode::QueryMode(QueryOp::Default),
                    // See the doc comment: v3 scalar operands need every
                    // term of the column's domain, so run Store mode.
                    EqlVersion::V3 => InferredQueryMode::StoreMode,
                };
                Ok((plaintext, mode))
            }
        }
    }
}

/// Build the column-config map the encrypt-query entry points use:
/// `encrypt_config` with `include_original` forced off on every match index.
///
/// `include_original: true` is a STORAGE option — it asks the indexer to add
/// the whole (filtered, untokenized) value as an extra bloom term so the
/// stored filter can also answer whole-value equality. A query bloom must
/// stay token-only: EQL matches by bit-subset (query bits ⊆ row bits), so a
/// whole-needle term in a substring query's bloom is never covered by the
/// row's per-token bits and the query matches nothing (#134). The flag would
/// otherwise reach query-term generation on two paths: v3 scalar Default
/// operands run in Store mode (see [`to_query_plaintext`]), and query-mode
/// terms are produced by the same match indexer that honours storage options.
///
/// Built once at client construction from a copy of the storage config.
fn query_config_map(
    encrypt_config: HashMap<Identifier, ColumnConfig>,
) -> Arc<HashMap<Identifier, ColumnConfig>> {
    Arc::new(
        encrypt_config
            .into_iter()
            .map(|(ident, mut config)| {
                for index in &mut config.indexes {
                    if let IndexType::Match {
                        include_original, ..
                    } = &mut index.index_type
                    {
                        *include_original = false;
                    }
                }
                (ident, config)
            })
            .collect(),
    )
}

/// Resolve a query payload's column config and build its [`PreparedPlaintext`]:
/// column lookup, index resolution, query-op parsing, plaintext conversion +
/// mode inference ([`to_query_plaintext`]), and `EqlOperation` selection.
///
/// The single seam shared by all four encrypt-query entry points (Neon +
/// wasm, single + bulk), so the version-dependent mode logic can never
/// diverge between builds. Returns the resolved `&ColumnConfig` alongside the
/// prepared plaintext — the caller needs it again for [`query_output`], and
/// returning the borrow avoids a second map lookup after encryption.
///
/// Callers pass the client's `query_config` (see [`query_config_map`]), not
/// its `encrypt_config`, so storage-only index options never shape query
/// terms.
fn prepare_query_plaintext<'a>(
    query_config: &'a HashMap<Identifier, ColumnConfig>,
    table: &str,
    column: &str,
    js_plaintext: &JsPlaintext,
    index_type_name: &str,
    query_op: QueryOpName,
    eql_version: EqlVersion,
) -> Result<(PreparedPlaintext<'a>, &'a ColumnConfig), Error> {
    let ident = Identifier::new(table.to_string(), column.to_string());
    let column_config = query_config
        .get(&ident)
        .ok_or(Error::UnknownColumn(ident))?;

    let index = find_index_for_type(column_config, column, index_type_name)?;

    // Infer type and operation mode from plaintext
    // - String on SteVec → QueryMode with SteVecSelector (path queries)
    // - Object/Array on SteVec → StoreMode (containment queries need sv array)
    // - Scalar Default under eqlVersion 3 → StoreMode (term-only operands)
    let (plaintext, inferred_mode) = to_query_plaintext(
        js_plaintext,
        query_op.to_query_op(),
        &index.index_type,
        column_config.cast_type,
        eql_version,
    )?;

    // A match QUERY needle that tokenizes to nothing (e.g. shorter than the
    // ngram token length) yields an empty bloom filter — and an empty bloom
    // filter matches EVERY row, because the EQL comparison (query bits ⊆
    // row bits) is vacuously true. cipherstash-client rejects this on its
    // own query path, but the v3 scalar path deliberately runs in StoreMode
    // (see to_query_plaintext) and store-side indexing is deliberately NOT
    // validated (storing a short string is legal). So the query-ness is
    // only known HERE — the seam shared by all four encrypt-query entry
    // points (Neon + wasm, single + bulk) — and this is where the guard
    // must live for v3.
    if matches!(&index.index_type, IndexType::Match { .. }) {
        if let Plaintext::Text(Some(value)) = &plaintext {
            MatchIndexer::try_init(&index.index_type)?
                .validate_query_input(value)
                .map_err(|source| Error::ShortMatchNeedle {
                    column: column.to_string(),
                    source,
                })?;
        }
    }

    let eql_operation = match inferred_mode {
        InferredQueryMode::QueryMode(qop) => EqlOperation::Query(&index.index_type, qop),
        InferredQueryMode::StoreMode => EqlOperation::Store,
    };

    Ok((
        PreparedPlaintext::new(
            Cow::Borrowed(column_config),
            EqlIdentifier::new(table, column),
            plaintext,
            eql_operation,
        ),
        column_config,
    ))
}

#[cfg(not(target_arch = "wasm32"))]
#[neon::export]
pub async fn new_client(
    // First-arg `Channel` is captured per-call by the `#[neon::export]` macro
    // from the calling isolate's `Cx`. Threading it into `NeonJsAuthStrategy`
    // is what keeps JS callbacks pinned to the isolate that owns the
    // strategy `Root` — see the rationale on `from_root`.
    channel: Channel,
    Json(opts): Json<NewClientOptions>,
    strategy: Option<Root<JsObject>>,
) -> Result<Boxed<Client>, impl for<'cx> TryIntoJs<'cx>> {
    do_new_client(channel, opts, strategy)
        .await
        .map(Boxed)
        .map_err(into_js_error)
}

#[cfg(not(target_arch = "wasm32"))]
async fn do_new_client(
    channel: Channel,
    opts: NewClientOptions,
    strategy: Option<Root<JsObject>>,
) -> Result<Client, Error> {
    // Parse the config and resolve the version before any network I/O. Client
    // 0.42's SteVec key-header envelope is v3-only; scalar-only clients retain
    // the historical v2 default.
    let encrypt_config = opts.encrypt_config.0.into_config_map()?;
    let eql_version = resolve_eql_version(opts.eql_version, &encrypt_config)?;
    let client_opts = opts.client_opts.unwrap_or_default();

    let auth = match strategy {
        Some(s) => NodeAuthStrategy::JsBacked(NeonJsAuthStrategy::from_root(s, channel).await?),
        None => NodeAuthStrategy::Auto(Box::new(client_opts.creds.build_strategy()?)),
    };
    let zerokms = ZeroKMSBuilder::new(auth)
        .with_key_provider(client_opts.creds.build_key_provider()?)
        .build()
        .await?;

    let zerokms = Arc::new(zerokms);
    let cipher = ScopedZeroKMS::init(zerokms.clone(), client_opts.keyset).await?;

    let query_config = query_config_map(encrypt_config.clone());
    let encrypt_config = Arc::new(encrypt_config);
    Ok(Client {
        cipher: Arc::new(cipher),
        zerokms,
        encrypt_config,
        query_config,
        eql_version,
    })
}

/// Test-only helper: ensures a keyset with the given name exists, creating it if necessary,
/// and grants the current client access.
///
/// This function is designed for **test setup**, not production use. It performs a simple
/// list-then-create which is not safe against concurrent calls (TOCTOU), but that's acceptable
/// because test setup runs sequentially before any test execution.
///
/// The grant step is best-effort: "already granted" errors are expected and ignored,
/// but other grant failures are logged as warnings since they may indicate misconfiguration.
#[cfg(not(target_arch = "wasm32"))]
#[neon::export]
pub async fn ensure_keyset(
    Json(opts): Json<EnsureKeysetOpts>,
) -> Result<Json<EnsureKeysetResult>, impl for<'cx> TryIntoJs<'cx>> {
    do_ensure_keyset(opts)
        .await
        .map(Json)
        .map_err(into_js_error)
}

#[cfg(not(target_arch = "wasm32"))]
async fn do_ensure_keyset(opts: EnsureKeysetOpts) -> Result<EnsureKeysetResult, Error> {
    let strategy = opts.creds.build_strategy()?;

    // Management-only client (no client key needed for list/create)
    let zerokms = ZeroKMSBuilder::new(strategy).build()?;

    let keysets = zerokms.list_keysets(false).await?;

    let (keyset_id, name) = match keysets.iter().find(|ks| ks.name == opts.name) {
        Some(ks) => (ks.id, ks.name.clone()),
        None => {
            let created = zerokms
                .create_keyset(&opts.name, &format!("Auto-created keyset '{}'", opts.name))
                .await?;
            (created.id, created.name)
        }
    };

    // Grant the client access to the keyset.
    // "Already granted" errors are expected and ignored; other failures are logged.
    match opts.creds.build_key_provider()?.client_key().await {
        Ok(client_key) => {
            if let Err(e) = zerokms.grant_keyset(client_key.key_id, keyset_id).await {
                eprintln!("Warning: grant_keyset failed (may be already granted): {e}");
            }
        }
        Err(e) => {
            eprintln!("Warning: could not resolve client key for grant: {e}");
        }
    }

    Ok(EnsureKeysetResult {
        id: keyset_id.to_string(),
        name,
    })
}

#[cfg(not(target_arch = "wasm32"))]
#[neon::export]
async fn encrypt(
    Boxed(client): Boxed<Client>,
    Json(opts): Json<EncryptOptions>,
) -> Result<Json<EncryptedOutput>, impl for<'cx> TryIntoJs<'cx>> {
    do_encrypt(client, opts)
        .await
        .map(Json)
        .map_err(into_js_error)
}

#[cfg(not(target_arch = "wasm32"))]
async fn do_encrypt(client: Client, opts: EncryptOptions) -> Result<EncryptedOutput, Error> {
    let ident = Identifier::new(opts.table.clone(), opts.column.clone());

    let column_config = client
        .encrypt_config
        .get(&ident)
        .ok_or_else(|| Error::UnknownColumn(ident.clone()))?;

    let plaintext = opts
        .plaintext
        .to_plaintext_with_type(column_config.cast_type)?;

    // Prepare for encrypt_eql
    let eql_ident = EqlIdentifier::new(&opts.table, &opts.column);
    let prepared = PreparedPlaintext::new(
        Cow::Borrowed(column_config),
        eql_ident,
        plaintext,
        EqlOperation::Store,
    );

    let eql_opts = EqlEncryptOpts {
        keyset_id: None, // Use cipher's default
        lock_context: Cow::Owned(opts.lock_context.map(Into::into).unwrap_or_default()),
        unverified_context: opts.unverified_context.map(Cow::Owned),
        index_types: None,
        decryption_policy: None,
    };

    // v3 clients emit natively via encrypt_eql_v3 (no from_v2); v2 clients keep
    // the historical encrypt_eql + storage_output path.
    let output = if client.eql_version == EqlVersion::V3 {
        let mut encrypted =
            encrypt_eql_v3(client.cipher.clone(), vec![prepared], &eql_opts).await?;
        storage_output_v3(
            into_store_ciphertext_v3(encrypted.remove(0))?,
            column_config,
        )?
    } else {
        let mut encrypted = encrypt_eql(client.cipher.clone(), vec![prepared], &eql_opts).await?;
        storage_output(
            into_store_ciphertext(encrypted.remove(0))?,
            client.eql_version,
            column_config,
        )?
    };

    Ok(output)
}

#[cfg(not(target_arch = "wasm32"))]
#[neon::export]
async fn encrypt_bulk(
    Boxed(client): Boxed<Client>,
    Json(opts): Json<EncryptBulkOptions>,
) -> Result<Json<Vec<EncryptedOutput>>, impl for<'cx> TryIntoJs<'cx>> {
    do_encrypt_bulk(client, opts)
        .await
        .map(Json)
        .map_err(into_js_error)
}

#[cfg(not(target_arch = "wasm32"))]
async fn do_encrypt_bulk(
    client: Client,
    opts: EncryptBulkOptions,
) -> Result<Vec<EncryptedOutput>, Error> {
    // Group payloads by lock_context for batch processing
    // BTreeMap provides deterministic ordering of groups
    let mut groups: BTreeMap<Vec<String>, Vec<(usize, PlaintextPayload)>> = BTreeMap::new();

    for (idx, payload) in opts.plaintexts.into_iter().enumerate() {
        let key = payload
            .lock_context
            .as_ref()
            .map(|lc| lc.identity_claim.clone())
            .unwrap_or_default();
        groups.entry(key).or_default().push((idx, payload));
    }

    // Pre-allocate results vector
    let total_count: usize = groups.values().map(|g| g.len()).sum();
    let mut results: Vec<Option<EncryptedOutput>> = (0..total_count).map(|_| None).collect();

    // Process each lock_context group
    for (lock_context_claims, payloads) in groups {
        let lock_context: Vec<zerokms::Context> = lock_context_claims
            .into_iter()
            .map(zerokms::Context::IdentityClaim)
            .collect();

        // Build PreparedPlaintext items for this group
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

        // v3 clients emit natively via encrypt_eql_v3 (no from_v2); v2 clients
        // keep the historical encrypt_eql + storage_output path. Only one branch
        // runs, so both may consume `prepared_plaintexts` / `payload_data`.
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

    // Unwrap all results (all should be Some)
    let final_results: Vec<EncryptedOutput> = results
        .into_iter()
        .enumerate()
        .map(|(i, opt)| {
            opt.ok_or_else(|| {
                Error::InvariantViolation(format!("Missing encryption result for index {}", i))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(final_results)
}

/// Deserialize a Neon JSON argument through this crate's [`Error`] router.
///
/// `Json<T>` would deserialize before the export body and let neon turn a
/// failure into its own message-only error. Extracting
/// [`serde_json::value::RawValue`] lets neon stringify and retain the JSON
/// without deserializing it into an options type. The typed parse happens here,
/// where `UNKNOWN_QUERY_OP` can be attached, while preserving the direct
/// `Json<T>` path's serde error details and field handling.
#[cfg(not(target_arch = "wasm32"))]
fn decode_coded_json<T>(Json(raw): Json<Box<serde_json::value::RawValue>>) -> Result<T, Error>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_str(raw.get()).map_err(Error::from)
}

#[cfg(not(target_arch = "wasm32"))]
#[neon::export]
async fn encrypt_query(
    Boxed(client): Boxed<Client>,
    raw_opts: Json<Box<serde_json::value::RawValue>>,
) -> Result<Json<QueryOutput>, impl for<'cx> TryIntoJs<'cx>> {
    let opts = match decode_coded_json(raw_opts) {
        Ok(opts) => opts,
        Err(err) => return Err(into_js_error(err)),
    };

    do_encrypt_query(client, opts)
        .await
        .map(Json)
        .map_err(into_js_error)
}

#[cfg(not(target_arch = "wasm32"))]
async fn do_encrypt_query(client: Client, opts: EncryptQueryOptions) -> Result<QueryOutput, Error> {
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
    // v2 clients keep the historical encrypt_eql + query_output path.
    let output = if client.eql_version == EqlVersion::V3 {
        let mut encrypted =
            encrypt_eql_v3(client.cipher.clone(), vec![prepared], &eql_opts).await?;
        query_output_v3(encrypted.remove(0), column_config)?
    } else {
        let mut encrypted = encrypt_eql(client.cipher.clone(), vec![prepared], &eql_opts).await?;
        query_output(encrypted.remove(0), client.eql_version, column_config)?
    };

    Ok(output)
}

#[cfg(not(target_arch = "wasm32"))]
#[neon::export]
async fn encrypt_query_bulk(
    Boxed(client): Boxed<Client>,
    raw_opts: Json<Box<serde_json::value::RawValue>>,
) -> Result<Json<Vec<QueryOutput>>, impl for<'cx> TryIntoJs<'cx>> {
    let opts = match decode_coded_json(raw_opts) {
        Ok(opts) => opts,
        Err(err) => return Err(into_js_error(err)),
    };

    do_encrypt_query_bulk(client, opts)
        .await
        .map(Json)
        .map_err(into_js_error)
}

#[cfg(not(target_arch = "wasm32"))]
async fn do_encrypt_query_bulk(
    client: Client,
    opts: EncryptQueryBulkOptions,
) -> Result<Vec<QueryOutput>, Error> {
    // Group payloads by lock_context (same pattern as encrypt_bulk)
    let mut groups: BTreeMap<Vec<String>, Vec<(usize, QueryPayload)>> = BTreeMap::new();

    for (idx, payload) in opts.queries.into_iter().enumerate() {
        let key = payload
            .lock_context
            .as_ref()
            .map(|lc| lc.identity_claim.clone())
            .unwrap_or_default();
        groups.entry(key).or_default().push((idx, payload));
    }

    let total_count: usize = groups.values().map(|g| g.len()).sum();
    let mut results: Vec<Option<QueryOutput>> = (0..total_count).map(|_| None).collect();

    for (lock_context_claims, payloads) in groups {
        let lock_context: Vec<zerokms::Context> = lock_context_claims
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
        // from_v2); v2 keeps the historical path. Only one branch runs, so both
        // may consume the moved `prepared_plaintexts` / `payload_data`.
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

    let final_results: Vec<QueryOutput> = results
        .into_iter()
        .enumerate()
        .map(|(i, opt)| {
            opt.ok_or_else(|| {
                Error::InvariantViolation(format!("Missing query result for index {}", i))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(final_results)
}

/// Build the JS `Error` an export throws, carrying `err.code`.
///
/// This is why the exports below return an opaque `impl TryIntoJs` instead of
/// neon's own `extract::Error`. That type's conversion is
/// `cx.error(self.cause.to_string())` — message only, no hook for a property —
/// and `TryIntoJs` is sealed behind a private module, so no type declared here
/// can implement it either. [`extract::with`] is the one escape hatch neon
/// offers: it defers the conversion until the JS thread and hands it a [`Cx`],
/// which is what setting a property on the error needs.
///
/// The cost is that an export cannot use `?` against its own error type. Each
/// one runs its body in a `do_*` helper returning `Result<_, Error>` — the
/// shape `wasm.rs` already uses — and maps once on the way out.
#[cfg(not(target_arch = "wasm32"))]
fn into_js_error(err: Error) -> impl for<'cx> TryIntoJs<'cx, Value = JsError> {
    let (message, code) = err.diagnostic_parts();
    extract::with(move |cx: &mut Cx| -> JsResult<JsError> {
        let error = cx.error(message)?;
        // Left unset rather than set to null when absent, so `'code' in err`
        // answers the question a caller is actually asking.
        if let Some(code) = code {
            let code = cx.string(code);
            error.set(cx, "code", code)?;
        }
        Ok(error)
    })
}

/// Convert a decrypted [`JsPlaintext`] into a JS value on the JS thread.
///
/// The `Json` return path (serde_json → `JSON.parse`) cannot produce a JS
/// `bigint`, so the BigInt variant is constructed directly with
/// [`JsBigInt::from_i64`]; every other variant keeps the JSON path
/// unchanged.
#[cfg(not(target_arch = "wasm32"))]
fn js_plaintext_into_js<'cx>(cx: &mut Cx<'cx>, plaintext: JsPlaintext) -> JsResult<'cx, JsValue> {
    match plaintext {
        JsPlaintext::BigInt(v) => Ok(JsBigInt::from_i64(cx, v).upcast()),
        other => Json(other).try_into_js(cx),
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[neon::export]
async fn decrypt(
    Boxed(client): Boxed<Client>,
    Json(opts): Json<DecryptOptions>,
) -> Result<impl for<'cx> TryIntoJs<'cx>, impl for<'cx> TryIntoJs<'cx>> {
    match do_decrypt(client, opts).await {
        Ok(js_plaintext) => Ok(extract::with(move |cx| -> NeonResult<_> {
            js_plaintext_into_js(cx, js_plaintext)
        })),
        Err(err) => Err(into_js_error(err)),
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn do_decrypt(client: Client, opts: DecryptOptions) -> Result<JsPlaintext, Error> {
    let lock_context = opts.lock_context.map(Into::into).unwrap_or_default();
    let encrypted_record = encrypted_record_from_value(opts.ciphertext, lock_context)?;

    let plaintext = client
        .zerokms
        .decrypt_single(
            encrypted_record,
            // Specifying None here will result in the client using the keyset identifier from the client
            None,
            opts.unverified_context.as_ref(),
        )
        .await
        .map_err(Error::from)
        .and_then(|bytes| Plaintext::from_slice(bytes.as_slice()).map_err(Error::from))?;

    JsPlaintext::try_from(plaintext).map_err(Error::from)
}

#[cfg(not(target_arch = "wasm32"))]
#[neon::export]
async fn decrypt_bulk(
    Boxed(client): Boxed<Client>,
    Json(opts): Json<DecryptBulkOptions>,
) -> Result<impl for<'cx> TryIntoJs<'cx>, impl for<'cx> TryIntoJs<'cx>> {
    match do_decrypt_bulk(client, opts).await {
        Ok(plaintexts) => Ok(extract::with(move |cx| -> NeonResult<_> {
            let arr = cx.empty_array();
            for (i, plaintext) in plaintexts.into_iter().enumerate() {
                let value = js_plaintext_into_js(cx, plaintext)?;
                arr.set(cx, i as u32, value)?;
            }
            Ok(arr)
        })),
        Err(err) => Err(into_js_error(err)),
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn do_decrypt_bulk(
    client: Client,
    opts: DecryptBulkOptions,
) -> Result<Vec<JsPlaintext>, Error> {
    let encrypted_records: Vec<WithContext<'static, eql_v3::DecryptableRecord>> = opts
        .ciphertexts
        .into_iter()
        .map(|payload| {
            let lock_context = payload.lock_context.map(Into::into).unwrap_or_default();
            encrypted_record_from_value(payload.ciphertext, lock_context)
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let decrypted = client
        .zerokms
        .decrypt(
            encrypted_records,
            // Specifying None here will result in the client using the keyset identifier from the client
            None,
            opts.unverified_context.as_ref(),
        )
        .await?;

    decrypted
        .into_iter()
        .map(|bytes| Plaintext::from_slice(&bytes).and_then(JsPlaintext::try_from))
        .collect::<Result<Vec<JsPlaintext>, TypeParseError>>()
        .map_err(Error::from)
}

#[cfg(not(target_arch = "wasm32"))]
#[neon::export]
async fn decrypt_bulk_fallible(
    Boxed(client): Boxed<Client>,
    Json(opts): Json<DecryptBulkOptions>,
) -> Result<impl for<'cx> TryIntoJs<'cx>, impl for<'cx> TryIntoJs<'cx>> {
    match do_decrypt_bulk_fallible(client, opts).await {
        Ok(results) => Ok(extract::with(move |cx| -> NeonResult<_> {
            let arr = cx.empty_array();
            for (i, result) in results.into_iter().enumerate() {
                let obj = cx.empty_object();
                match result {
                    DecryptResult::Success { data } => {
                        let value = js_plaintext_into_js(cx, data)?;
                        obj.set(cx, "data", value)?;
                    }
                    DecryptResult::Error { error, code } => {
                        let message = cx.string(error);
                        obj.set(cx, "error", message)?;
                        // Left unset rather than set to null when absent, so
                        // the item matches the declared
                        // `code?: ProtectErrorCode`.
                        if let Some(code) = code {
                            let code = cx.string(code);
                            obj.set(cx, "code", code)?;
                        }
                    }
                }
                arr.set(cx, i as u32, obj)?;
            }
            Ok(arr)
        })),
        Err(err) => Err(into_js_error(err)),
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn do_decrypt_bulk_fallible(
    client: Client,
    opts: DecryptBulkOptions,
) -> Result<Vec<DecryptResult>, Error> {
    // Decode each ciphertext independently so a single invalid payload turns
    // into a per-item `DecryptResult::Error` rather than aborting the whole
    // batch — matches the `*Fallible` contract.
    let parsed: Vec<Result<WithContext<'static, eql_v3::DecryptableRecord>, Error>> = opts
        .ciphertexts
        .into_iter()
        .map(|payload| {
            let lock_context = payload.lock_context.map(Into::into).unwrap_or_default();
            encrypted_record_from_value(payload.ciphertext, lock_context)
        })
        .collect();

    let mut results: Vec<Option<DecryptResult>> = (0..parsed.len()).map(|_| None).collect();
    let mut valid_records: Vec<WithContext<'static, eql_v3::DecryptableRecord>> =
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

    let decrypted: Vec<Result<Vec<u8>, RecordDecryptError>> = client
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

#[cfg(not(target_arch = "wasm32"))]
#[neon::export]
fn is_encrypted(Json(raw): Json<serde_json::Value>) -> bool {
    is_encrypted_value(&raw)
}

fn encrypted_record_from_mp_base85(
    encrypted: EqlCiphertext,
    encryption_context: Vec<zerokms::Context>,
) -> Result<WithContext<'static>, Error> {
    // SteVec root invariant: ciphertext is always `sv[0]` (mirrors upstream
    // `SteVec::into_root_ciphertext`, which is not exposed on the wire type).
    let encrypted_record = match encrypted {
        EqlCiphertext::Encrypted(payload) => payload.ciphertext,
        EqlCiphertext::SteVec(payload) => {
            payload
                .ste_vec
                .into_iter()
                .next()
                .ok_or_else(|| {
                    Error::InvariantViolation(
                        "Missing root entry in SteVec EQL payload".to_string(),
                    )
                })?
                .ciphertext
        }
    };

    Ok(WithContext {
        record: encrypted_record,
        context: Cow::Owned(encryption_context),
    })
}

/// Extracts the [`EqlCiphertext`] from a Store-mode [`EqlOutput`].
///
/// Used by `encrypt` / `encrypt_bulk`, which always run with `EqlOperation::Store` and
/// therefore must produce storage ciphertexts (never query payloads).
fn into_store_ciphertext(output: EqlOutput) -> Result<EqlCiphertext, Error> {
    match output {
        EqlOutput::Store(ciphertext) => Ok(ciphertext),
        EqlOutput::Query(_) => Err(Error::InvariantViolation(
            "encrypt_eql returned a query payload for a store-mode encryption".to_string(),
        )),
    }
}

/// The v3 counterpart of [`into_store_ciphertext`] — extract the native v3
/// storage payload from an [`encrypt_eql_v3`] result.
fn into_store_ciphertext_v3(output: EqlOutputV3) -> Result<EqlCiphertextV3, Error> {
    match output {
        EqlOutputV3::Store(ciphertext) => Ok(ciphertext),
        EqlOutputV3::Query(_) => Err(Error::InvariantViolation(
            "encrypt_eql_v3 returned a query payload for a store-mode encryption".to_string(),
        )),
    }
}

#[cfg(not(target_arch = "wasm32"))]
static RUNTIME: OnceCell<Runtime> = OnceCell::new();

#[cfg(not(target_arch = "wasm32"))]
#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    let runtime = RUNTIME
        .get_or_try_init(Runtime::new)
        .or_else(|err| cx.throw_error(err.to_string()))?;

    let _ = neon::set_global_executor(&mut cx, runtime);

    neon::registered().export(&mut cx)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `ProtectErrorCode` an error crosses the boundary with.
    ///
    /// `src/errorCodes.test.ts` proves the code SET matches the TypeScript
    /// union; these prove the routing — which error produces which code —
    /// because that is where the judgement is. The `From<ConfigError>` cases
    /// especially: three codes come out of one upstream type, and getting the
    /// arms wrong is invisible to the compiler.
    mod error_codes {
        use super::*;

        fn config(err: ConfigError) -> Option<String> {
            Error::from(err).error_code()
        }

        /// Deserializes a real options object through the Neon query decoder,
        /// so this assertion covers the boundary seam that assigns the code.
        fn deserialize_query_op(raw: serde_json::Value) -> Error {
            let raw = serde_json::value::to_raw_value(&serde_json::json!({
                "plaintext": "x",
                "column": "email",
                "table": "users",
                "queryOp": raw,
            }))
            .expect("the test options serialize");

            decode_coded_json::<EncryptQueryOptions>(Json(raw))
                .map(|_| ())
                .expect_err("an unknown queryOp is an error")
        }

        #[test]
        fn an_unknown_query_op_is_routed_off_the_serde_message() {
            // The one code that cannot come from a variant the error was
            // constructed as: `QueryOpName` rejects inside `Deserialize`, so
            // `Error::unknown_query_op` recovers it from the message prefix.
            // `query_op`'s tests pin the prefix from the other side.
            assert_eq!(
                deserialize_query_op(serde_json::json!("frobnicate"))
                    .error_code()
                    .as_deref(),
                Some("UNKNOWN_QUERY_OP")
            );
        }

        #[test]
        fn other_deserialization_failures_stay_uncoded() {
            // The routing is a prefix match, so it has to be shown NOT to
            // capture every serde failure — `Error::Parse` carries no code.
            assert_eq!(
                deserialize_query_op(serde_json::json!(42)).error_code(),
                None
            );
        }

        #[test]
        fn ste_vec_on_a_non_json_column() {
            assert_eq!(
                config(ConfigError::SteVecRequiresJson {
                    table: "users".into(),
                    column: "meta".into(),
                    found_plaintext_type: "text".into(),
                })
                .as_deref(),
                Some("STE_VEC_REQUIRES_JSON_CAST_AS")
            );
        }

        #[test]
        fn match_on_a_non_text_column() {
            assert_eq!(
                config(ConfigError::MatchRequiresText {
                    table: "users".into(),
                    column: "age".into(),
                    found_plaintext_type: "int".into(),
                })
                .as_deref(),
                Some("MATCH_REQUIRES_TEXT")
            );
        }

        #[test]
        fn a_config_version_this_build_does_not_support() {
            assert_eq!(
                config(ConfigError::UnsupportedVersion {
                    version: 2,
                    expected: 1,
                })
                .as_deref(),
                Some("UNSUPPORTED_CONFIG_VERSION")
            );
        }

        #[test]
        fn any_other_config_error_has_no_code() {
            // Reaches JS as UNKNOWN. A new upstream variant lands here, which
            // is the same outcome the substring table gave it — the difference
            // is that this arm is visible and the old one was not.
            assert_eq!(config(ConfigError::MismatchedScope), None);
        }

        #[test]
        fn transparent_upstream_wrappers_have_no_code() {
            // Their Display belongs to cipherstash-client. Claiming a code for
            // them would be claiming to know which upstream failure occurred,
            // which is exactly what the message matching used to guess at.
            let err = Error::Parse(serde_json::from_str::<u8>("nope").unwrap_err());
            assert_eq!(err.error_code(), None);
        }

        #[test]
        fn both_v3_conversion_paths_share_one_code() {
            // A caller branching on EQL_V3_CONVERSION_FAILED cares that the v3
            // payload was refused, not which of the two paths refused it.
            let native = Error::V3NativeParse {
                domain: "eql_v3_text_search_ore".into(),
                source: serde_json::from_str::<u8>("nope").unwrap_err(),
            };
            assert_eq!(
                native.error_code().as_deref(),
                Some("EQL_V3_CONVERSION_FAILED")
            );
        }

        #[test]
        fn both_ciphertext_failures_share_one_code() {
            assert_eq!(
                Error::InvalidSteVecSelector.error_code().as_deref(),
                Some("INVALID_CIPHERTEXT")
            );
        }

        #[test]
        fn a_code_never_replaces_the_message() {
            // The code is additional to Display, not a substitute for it: the
            // JS error keeps the text it has always had.
            let err = Error::InvalidEqlVersion(4);
            assert_eq!(err.to_string(), "Invalid eqlVersion 4: expected 2 or 3");
            assert_eq!(err.error_code().as_deref(), Some("INVALID_EQL_VERSION"));
        }

        #[test]
        fn a_transparent_config_error_keeps_upstream_wording() {
            // Splitting `Error::Config` into four variants must not change what
            // a caller reads — only what it can branch on.
            let err = Error::from(ConfigError::UnsupportedVersion {
                version: 2,
                expected: 1,
            });
            assert_eq!(
                err.to_string(),
                "unsupported config version: 2 (expected 1)"
            );
        }
    }

    mod truncate_for_error {
        use super::*;

        #[test]
        fn handles_non_ascii_without_panicking() {
            let input = "ééé";
            assert_eq!(truncate_for_error(input, 1), "é...");
        }

        #[test]
        fn returns_ellipsis_when_max_len_zero() {
            assert_eq!(truncate_for_error("abc", 0), "...");
        }
    }

    mod is_encrypted {
        use super::*;
        use cipherstash_client::eql::{
            EncryptedPayload, SteVecEntry, SteVecPayload, EQL_SCHEMA_VERSION,
        };
        use cipherstash_client::zerokms::EncryptedRecord;
        use serde_json::json;

        fn dummy_encrypted_record() -> EncryptedRecord {
            EncryptedRecord {
                iv: Default::default(),
                ciphertext: vec![1; 16],
                tag: vec![2; 16],
                descriptor: "users/email".to_string(),
                keyset_id: None,
                decryption_policy: None,
            }
        }

        #[test]
        fn valid_scalar_ciphertext_is_encrypted() {
            let payload = EqlCiphertext::Encrypted(EncryptedPayload {
                version: EQL_SCHEMA_VERSION,
                identifier: EqlIdentifier::new("users", "email"),
                ciphertext: dummy_encrypted_record(),
                hmac_256: None,
                bloom_filter: None,
                ore_block_u64_8_256: None,
                ope_cllw: None,
            });
            let value = serde_json::to_value(&payload).unwrap();
            assert_eq!(value["k"], "ct");
            assert!(is_encrypted(Json(value)));
        }

        #[test]
        fn valid_ste_vec_ciphertext_is_encrypted() {
            let payload = EqlCiphertext::SteVec(SteVecPayload {
                version: EQL_SCHEMA_VERSION,
                identifier: EqlIdentifier::new("users", "profile"),
                ste_vec: vec![SteVecEntry {
                    selector: "deadbeef".into(),
                    ciphertext: dummy_encrypted_record(),
                    is_array: None,
                    term: None,
                }],
            });
            let value = serde_json::to_value(&payload).unwrap();
            assert_eq!(value["k"], "sv");
            assert!(is_encrypted(Json(value)));
        }

        #[test]
        fn invalid_ciphertext_is_not_encrypted() {
            // Random JSON without the EQL discriminator must not be recognized as an
            // encrypted payload.
            let invalid_encrypted = json!({"random": "data"});
            assert!(!is_encrypted(Json(invalid_encrypted)));
        }

        #[test]
        fn missing_discriminator_is_not_encrypted() {
            // EQL v2.3 requires a `k` discriminator at the root ("ct" for scalar
            // payloads, "sv" for SteVec). Payloads without `k` are rejected even if
            // the other required fields are present.
            let no_discriminator = json!({
                "i": {"t": "users", "c": "email"},
                "v": 2
            });
            assert!(!is_encrypted(Json(no_discriminator)));
        }

        #[test]
        fn unknown_discriminator_is_not_encrypted() {
            // Only "ct" and "sv" are valid EQL v2.3 root discriminators.
            let unknown_discriminator = json!({
                "k": "wat",
                "i": {"t": "users", "c": "email"},
                "v": 2
            });
            assert!(!is_encrypted(Json(unknown_discriminator)));
        }
    }

    mod lock_context_grouping {
        use std::collections::BTreeMap;

        // Helper to simulate the grouping logic
        fn group_by_lock_context(
            payloads: Vec<(String, Option<Vec<String>>)>,
        ) -> BTreeMap<Vec<String>, Vec<(usize, String)>> {
            let mut groups: BTreeMap<Vec<String>, Vec<(usize, String)>> = BTreeMap::new();
            for (idx, (data, lock_context)) in payloads.into_iter().enumerate() {
                let key = lock_context.unwrap_or_default();
                groups.entry(key).or_default().push((idx, data));
            }
            groups
        }

        #[test]
        fn same_lock_context_groups_together() {
            let payloads = vec![
                ("a".to_string(), Some(vec!["user:1".to_string()])),
                ("b".to_string(), Some(vec!["user:1".to_string()])),
                ("c".to_string(), Some(vec!["user:1".to_string()])),
            ];

            let groups = group_by_lock_context(payloads);

            assert_eq!(groups.len(), 1);
            assert_eq!(groups[&vec!["user:1".to_string()]].len(), 3);
        }

        #[test]
        fn different_lock_contexts_separate_groups() {
            let payloads = vec![
                ("a".to_string(), Some(vec!["user:1".to_string()])),
                ("b".to_string(), Some(vec!["user:2".to_string()])),
                ("c".to_string(), Some(vec!["user:1".to_string()])),
            ];

            let groups = group_by_lock_context(payloads);

            assert_eq!(groups.len(), 2);
            assert_eq!(groups[&vec!["user:1".to_string()]].len(), 2);
            assert_eq!(groups[&vec!["user:2".to_string()]].len(), 1);
        }

        #[test]
        fn none_lock_context_groups_together() {
            let payloads = vec![
                ("a".to_string(), None),
                ("b".to_string(), None),
                ("c".to_string(), Some(vec!["user:1".to_string()])),
            ];

            let groups = group_by_lock_context(payloads);

            assert_eq!(groups.len(), 2);
            assert_eq!(groups[&vec![]].len(), 2); // None becomes empty vec
            assert_eq!(groups[&vec!["user:1".to_string()]].len(), 1);
        }

        #[test]
        fn preserves_original_indices() {
            let payloads = vec![
                ("a".to_string(), Some(vec!["user:2".to_string()])),
                ("b".to_string(), Some(vec!["user:1".to_string()])),
                ("c".to_string(), Some(vec!["user:2".to_string()])),
            ];

            let groups = group_by_lock_context(payloads);

            // user:1 group should have index 1
            let user1_group = &groups[&vec!["user:1".to_string()]];
            assert_eq!(user1_group[0], (1, "b".to_string()));

            // user:2 group should have indices 0 and 2
            let user2_group = &groups[&vec!["user:2".to_string()]];
            assert_eq!(user2_group[0], (0, "a".to_string()));
            assert_eq!(user2_group[1], (2, "c".to_string()));
        }
    }

    mod eql_version_resolution {
        use super::*;
        use cipherstash_client::schema::column::{ColumnMode, ColumnType, Index};

        fn ste_vec_config() -> HashMap<Identifier, ColumnConfig> {
            HashMap::from([(
                Identifier::new("users", "profile"),
                ColumnConfig {
                    name: "profile".to_string(),
                    cast_type: ColumnType::Json,
                    indexes: vec![Index::new(IndexType::SteVec {
                        prefix: "users/profile".to_string(),
                        term_filters: vec![],
                        array_index_mode: Default::default(),
                        mode: Default::default(),
                    })],
                    in_place: false,
                    mode: ColumnMode::Encrypted,
                },
            )])
        }

        #[test]
        fn omitted_version_uses_v3_for_ste_vec() {
            assert_eq!(
                resolve_eql_version(None, &ste_vec_config()).unwrap(),
                EqlVersion::V3
            );
        }

        #[test]
        fn explicit_v2_is_rejected_for_ste_vec() {
            assert!(matches!(
                resolve_eql_version(Some(2), &ste_vec_config()),
                Err(Error::SteVecRequiresV3)
            ));
        }

        #[test]
        fn explicit_v3_is_accepted_for_ste_vec() {
            assert_eq!(
                resolve_eql_version(Some(3), &ste_vec_config()).unwrap(),
                EqlVersion::V3
            );
        }

        #[test]
        fn scalar_only_config_retains_the_v2_default() {
            assert_eq!(
                resolve_eql_version(None, &HashMap::new()).unwrap(),
                EqlVersion::V2
            );
        }

        #[test]
        fn scalar_only_config_honours_an_explicit_v2() {
            assert_eq!(
                resolve_eql_version(Some(2), &HashMap::new()).unwrap(),
                EqlVersion::V2
            );
        }
    }

    mod find_index_for_type_tests {
        use super::*;
        use cipherstash_client::schema::column::{Index, IndexType, Tokenizer};

        fn make_column_config_with_indexes(indexes: Vec<Index>) -> ColumnConfig {
            ColumnConfig {
                name: "test_column".to_string(),
                cast_type: cipherstash_client::schema::column::ColumnType::Text,
                indexes,
                in_place: false,
                mode: cipherstash_client::schema::column::ColumnMode::Encrypted,
            }
        }

        #[test]
        fn find_ste_vec_index() {
            let config = make_column_config_with_indexes(vec![Index::new(IndexType::SteVec {
                prefix: "test".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            })]);
            let result = find_index_for_type(&config, "test_column", "ste_vec");
            assert!(result.is_ok());
            assert!(matches!(
                result.unwrap().index_type,
                IndexType::SteVec { .. }
            ));
        }

        #[test]
        fn find_ore_index() {
            let config = make_column_config_with_indexes(vec![Index::new(IndexType::Ore)]);
            let result = find_index_for_type(&config, "test_column", "ore");
            assert!(result.is_ok());
            assert!(matches!(result.unwrap().index_type, IndexType::Ore));
        }

        #[test]
        fn find_unique_index() {
            let config = make_column_config_with_indexes(vec![Index::new(IndexType::Unique {
                token_filters: vec![],
            })]);
            let result = find_index_for_type(&config, "test_column", "unique");
            assert!(result.is_ok());
            assert!(matches!(
                result.unwrap().index_type,
                IndexType::Unique { .. }
            ));
        }

        #[test]
        fn find_match_index() {
            let config = make_column_config_with_indexes(vec![Index::new(IndexType::Match {
                tokenizer: Tokenizer::Standard,
                token_filters: vec![],
                k: 3,
                m: 2048,
                include_original: false,
            })]);
            let result = find_index_for_type(&config, "test_column", "match");
            assert!(result.is_ok());
            assert!(matches!(
                result.unwrap().index_type,
                IndexType::Match { .. }
            ));
        }

        #[test]
        fn missing_index_returns_error() {
            let config = make_column_config_with_indexes(vec![Index::new(IndexType::Ore)]);
            let result = find_index_for_type(&config, "test_column", "ste_vec");
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.to_string().contains("does not have"));
            assert!(err.to_string().contains("test_column"));
        }

        #[test]
        fn unknown_index_type_returns_error() {
            let config = make_column_config_with_indexes(vec![Index::new(IndexType::Ore)]);
            let result = find_index_for_type(&config, "test_column", "invalid_type");
            assert!(result.is_err());
        }

        #[test]
        fn missing_index_error_includes_column_and_suggestions() {
            let config = make_column_config_with_indexes(vec![
                Index::new(IndexType::Ore),
                Index::new(IndexType::Match {
                    tokenizer: Tokenizer::Standard,
                    token_filters: vec![],
                    k: 6,
                    m: 2048,
                    include_original: false,
                }),
            ]);
            let result = find_index_for_type(&config, "email", "ste_vec");
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            // Should include column name
            assert!(
                err_msg.contains("email"),
                "Error should include column name: {}",
                err_msg
            );
            // Should include index type
            assert!(
                err_msg.contains("ste_vec"),
                "Error should include requested index type: {}",
                err_msg
            );
            // Should show available indexes
            assert!(
                err_msg.contains("ore"),
                "Error should show available ore index: {}",
                err_msg
            );
            assert!(
                err_msg.contains("match"),
                "Error should show available match index: {}",
                err_msg
            );
        }
    }

    // A match query needle that tokenizes to nothing (shorter than the
    // ngram, LIKE wrappers stripped, …) mints an empty bloom filter that
    // matches EVERY row. cipherstash-client guards its own query path, but
    // the v3 scalar path runs in StoreMode where store-side indexing is
    // (deliberately) unvalidated — so prepare_query_plaintext is the seam
    // that must reject it for all four entry points, on both EQL versions.
    mod short_match_needle_guard {
        use super::*;
        use cipherstash_client::schema::column::{
            ColumnMode, ColumnType, Index, IndexType, Tokenizer,
        };
        use std::collections::HashMap;

        fn match_config(tokenizer: Tokenizer) -> HashMap<Identifier, ColumnConfig> {
            let config = ColumnConfig {
                name: "email".to_string(),
                cast_type: ColumnType::Text,
                indexes: vec![Index::new(IndexType::Match {
                    tokenizer,
                    token_filters: vec![],
                    k: 6,
                    m: 2048,
                    include_original: false,
                })],
                in_place: false,
                mode: ColumnMode::Encrypted,
            };
            HashMap::from([(
                Identifier::new("users".to_string(), "email".to_string()),
                config,
            )])
        }

        fn prepare(
            config: &HashMap<Identifier, ColumnConfig>,
            needle: &str,
            eql_version: EqlVersion,
        ) -> Result<(), Error> {
            prepare_query_plaintext(
                config,
                "users",
                "email",
                &JsPlaintext::String(needle.to_string()),
                "match",
                QueryOpName::Default,
                eql_version,
            )
            .map(|_| ())
        }

        #[test]
        fn v3_short_needle_is_rejected() {
            // The load-bearing case: v3 runs StoreMode, so without this
            // guard the empty-bloom term reaches the database and the
            // query matches every row (rc.2 skilltester blocker B2).
            let config = match_config(Tokenizer::Ngram { token_length: 3 });
            let err = prepare(&config, "zq", EqlVersion::V3).unwrap_err();
            assert!(matches!(err, Error::ShortMatchNeedle { .. }));
            let msg = err.to_string();
            assert!(
                msg.contains("Invalid match query on column 'email'"),
                "{msg}"
            );
            assert!(msg.contains("minimum token length is 3"), "{msg}");
            assert!(!msg.contains("zq"), "must not leak the needle: {msg}");
        }

        #[test]
        fn v2_short_needle_is_rejected_at_the_same_boundary() {
            let config = match_config(Tokenizer::Ngram { token_length: 3 });
            let err = prepare(&config, "bp", EqlVersion::V2).unwrap_err();
            assert!(matches!(err, Error::ShortMatchNeedle { .. }));
        }

        #[test]
        fn like_wrappers_do_not_count_toward_the_minimum() {
            let config = match_config(Tokenizer::Ngram { token_length: 3 });
            assert!(prepare(&config, "%ab%", EqlVersion::V3).is_err());
            assert!(prepare(&config, "%abc%", EqlVersion::V3).is_ok());
        }

        #[test]
        fn valid_needles_pass_on_both_versions() {
            let config = match_config(Tokenizer::Ngram { token_length: 3 });
            assert!(prepare(&config, "abc", EqlVersion::V3).is_ok());
            assert!(prepare(&config, "Netflix", EqlVersion::V2).is_ok());
        }

        #[test]
        fn standard_tokenizer_keeps_single_characters_queryable() {
            // Standard has no length minimum: a one-character word is a
            // real token and must not be rejected.
            let config = match_config(Tokenizer::Standard);
            assert!(prepare(&config, "a", EqlVersion::V3).is_ok());
        }
    }

    mod query_inference_tests {
        use super::*;
        use cipherstash_client::encryption::Plaintext;
        use cipherstash_client::schema::column::Tokenizer;
        use cipherstash_client::schema::column::{ColumnType, IndexType};

        #[test]
        fn test_ste_vec_default_with_string_infers_selector() {
            let js_plaintext = JsPlaintext::String("$.user.email".to_string());
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::Default,
                &index_type,
                ColumnType::Json,
                EqlVersion::V2,
            );

            // String on SteVec should infer QueryMode with SteVecSelector
            assert!(matches!(
                result,
                Ok((
                    Plaintext::Text(Some(_)),
                    InferredQueryMode::QueryMode(QueryOp::SteVecSelector)
                ))
            ));
        }

        #[test]
        fn test_ste_vec_default_with_object_infers_store_mode() {
            let js_plaintext = JsPlaintext::JsonB(serde_json::json!({"role": "admin"}));
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::Default,
                &index_type,
                ColumnType::Json,
                EqlVersion::V2,
            );

            // Object on SteVec should infer StoreMode (produces sv array for containment)
            assert!(matches!(
                result,
                Ok((Plaintext::Json(Some(_)), InferredQueryMode::StoreMode))
            ));
        }

        #[test]
        fn test_ste_vec_default_with_array_infers_store_mode() {
            let js_plaintext = JsPlaintext::JsonB(serde_json::json!(["admin", "user"]));
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::Default,
                &index_type,
                ColumnType::Json,
                EqlVersion::V2,
            );

            // Array on SteVec should infer StoreMode (produces sv array for containment)
            assert!(matches!(
                result,
                Ok((Plaintext::Json(Some(_)), InferredQueryMode::StoreMode))
            ));
        }

        #[test]
        fn test_ste_vec_default_with_number_returns_error() {
            let js_plaintext = JsPlaintext::Number(42.0);
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::Default,
                &index_type,
                ColumnType::Json,
                EqlVersion::V2,
            );

            // Numbers should return error for SteVec queries
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("Invalid query input"),
                "Error message should mention invalid input: {}",
                err_msg
            );
        }

        #[test]
        fn test_ste_vec_default_with_bigint_returns_error() {
            let js_plaintext = JsPlaintext::BigInt(42);
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::Default,
                &index_type,
                ColumnType::Json,
                EqlVersion::V2,
            );

            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("BigInt"),
                "error should name the received BigInt: {}",
                err_msg
            );
        }

        #[test]
        fn test_ste_vec_term_with_bigint_returns_error() {
            let js_plaintext = JsPlaintext::BigInt(42);
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::SteVecTerm,
                &index_type,
                ColumnType::Json,
                EqlVersion::V2,
            );

            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("BigInt") && err_msg.contains("String or Number"),
                "error should explain the accepted ordering scalar types: {}",
                err_msg
            );
        }

        #[test]
        fn test_ste_vec_term_rejects_boolean_and_date() {
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            };

            for js_plaintext in [
                JsPlaintext::Boolean(true),
                JsPlaintext::Date(chrono::Utc::now()),
            ] {
                let err = to_query_plaintext(
                    &js_plaintext,
                    QueryOp::SteVecTerm,
                    &index_type,
                    ColumnType::Json,
                    EqlVersion::V3,
                )
                .unwrap_err();
                assert!(matches!(
                    err,
                    Error::InvalidQueryInput {
                        query_op: SteVecQueryOpKind::Term,
                        ..
                    }
                ));
            }
        }

        #[test]
        fn test_non_ste_vec_default_with_bigint_uses_column_type() {
            // An ore/unique query term on a bigint column accepts a bigint
            // and converts it via the column's cast type — the same path
            // index-term generation uses on the storage side, so the
            // boundary i64 bounds check covers both.
            let js_plaintext = JsPlaintext::BigInt(i64::MAX);
            let index_type = IndexType::Ore;

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::Default,
                &index_type,
                ColumnType::BigInt,
                EqlVersion::V2,
            );

            assert!(matches!(
                result,
                Ok((
                    Plaintext::BigInt(Some(i64::MAX)),
                    InferredQueryMode::QueryMode(QueryOp::Default)
                ))
            ));
        }

        #[test]
        fn test_ste_vec_default_with_boolean_returns_error() {
            let js_plaintext = JsPlaintext::Boolean(true);
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::Default,
                &index_type,
                ColumnType::Json,
                EqlVersion::V2,
            );

            // Booleans should return error for SteVec queries
            assert!(result.is_err());
        }

        #[test]
        fn test_explicit_ste_vec_selector_uses_query_mode() {
            let js_plaintext = JsPlaintext::String("$.name".to_string());
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::SteVecSelector,
                &index_type,
                ColumnType::Json,
                EqlVersion::V2,
            );

            // Explicit SteVecSelector should use QueryMode
            assert!(matches!(
                result,
                Ok((
                    Plaintext::Text(Some(_)),
                    InferredQueryMode::QueryMode(QueryOp::SteVecSelector)
                ))
            ));
        }

        #[test]
        fn test_explicit_ste_vec_term_string_uses_query_mode() {
            let js_plaintext = JsPlaintext::String("value".to_string());
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::SteVecTerm,
                &index_type,
                ColumnType::Json,
                EqlVersion::V2,
            );

            assert!(matches!(
                result,
                Ok((
                    Plaintext::Text(Some(_)),
                    InferredQueryMode::QueryMode(QueryOp::SteVecTerm)
                ))
            ));
        }

        #[test]
        fn test_explicit_ste_vec_term_number_uses_query_mode() {
            let js_plaintext = JsPlaintext::Number(42.5);
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::SteVecTerm,
                &index_type,
                ColumnType::Json,
                EqlVersion::V3,
            );

            assert!(matches!(
                result,
                Ok((
                    Plaintext::Float(Some(42.5)),
                    InferredQueryMode::QueryMode(QueryOp::SteVecTerm)
                ))
            ));
        }

        #[test]
        fn test_non_ste_vec_default_uses_column_type() {
            let js_plaintext = JsPlaintext::String("search term".to_string());
            let index_type = IndexType::Match {
                tokenizer: Tokenizer::Standard,
                token_filters: vec![],
                k: 6,
                m: 2048,
                include_original: true,
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::Default,
                &index_type,
                ColumnType::Text,
                EqlVersion::V2,
            );

            // Non-SteVec with Default should use column type and QueryMode with Default
            assert!(matches!(
                result,
                Ok((
                    Plaintext::Text(Some(_)),
                    InferredQueryMode::QueryMode(QueryOp::Default)
                ))
            ));
        }

        #[test]
        fn test_ste_vec_term_with_json_error_is_helpful() {
            let js_plaintext = JsPlaintext::JsonB(serde_json::json!({"role": "admin"}));
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::SteVecTerm,
                &index_type,
                ColumnType::Json,
                EqlVersion::V2,
            );

            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            // Should mention it's for ste_vec_term
            assert!(
                err_msg.contains("ste_vec_term"),
                "Error should mention ste_vec_term: {}",
                err_msg
            );
            assert!(
                err_msg.contains("JSON object"),
                "Error should mention the received JSON object: {}",
                err_msg
            );
            assert!(
                err_msg.contains("ste_vec_value_selector") || err_msg.contains("ordering"),
                "Error should explain term and exact-match operations: {}",
                err_msg
            );
        }

        #[test]
        fn test_ste_vec_value_selector_uses_query_mode() {
            let js_plaintext = JsPlaintext::JsonB(serde_json::json!({
                "path": "$.user.email",
                "value": "dan@example.com"
            }));
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::SteVecValueSelector,
                &index_type,
                ColumnType::Json,
                EqlVersion::V3,
            );

            assert!(matches!(
                result,
                Ok((
                    Plaintext::Json(Some(_)),
                    InferredQueryMode::QueryMode(QueryOp::SteVecValueSelector)
                ))
            ));
        }

        #[test]
        fn test_ste_vec_value_selector_rejects_container_values() {
            let js_plaintext = JsPlaintext::JsonB(serde_json::json!({
                "path": "$.user",
                "value": {"role": "admin"}
            }));
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            };

            let err = to_query_plaintext(
                &js_plaintext,
                QueryOp::SteVecValueSelector,
                &index_type,
                ColumnType::Json,
                EqlVersion::V3,
            )
            .unwrap_err();

            assert!(err.to_string().contains("containment query"));
        }

        #[test]
        fn test_ste_vec_value_selector_rejects_malformed_shapes() {
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            };

            for bad in [
                serde_json::json!({"path": "$.a"}),
                serde_json::json!({"value": "x"}),
                serde_json::json!({"path": "$.a", "value": "x", "extra": 1}),
                serde_json::json!({"path": 123, "value": "x"}),
                serde_json::json!({"path": "$.a", "value": [1, 2]}),
            ] {
                let err = to_query_plaintext(
                    &JsPlaintext::JsonB(bad.clone()),
                    QueryOp::SteVecValueSelector,
                    &index_type,
                    ColumnType::Json,
                    EqlVersion::V3,
                )
                .unwrap_err();
                assert!(
                    matches!(
                        &err,
                        Error::InvalidQueryInput {
                            query_op: SteVecQueryOpKind::ValueSelector,
                            ..
                        }
                    ),
                    "{bad} should be rejected: {err}"
                );
            }
        }

        #[test]
        fn test_ste_vec_value_selector_rejects_invalid_json_path() {
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            };
            let js_plaintext = JsPlaintext::JsonB(serde_json::json!({
                "path": "role",
                "value": "admin"
            }));

            let err = to_query_plaintext(
                &js_plaintext,
                QueryOp::SteVecValueSelector,
                &index_type,
                ColumnType::Json,
                EqlVersion::V3,
            )
            .unwrap_err();
            assert!(matches!(err, Error::InvalidJsonPath { .. }));
        }

        #[test]
        fn test_ste_vec_value_selector_rejects_non_json_inputs() {
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            };

            for js_plaintext in [
                JsPlaintext::String("$.role".to_string()),
                JsPlaintext::Number(42.0),
                JsPlaintext::Boolean(true),
                JsPlaintext::BigInt(42),
                JsPlaintext::Date(chrono::Utc::now()),
            ] {
                let err = to_query_plaintext(
                    &js_plaintext,
                    QueryOp::SteVecValueSelector,
                    &index_type,
                    ColumnType::Json,
                    EqlVersion::V3,
                )
                .unwrap_err();
                assert!(matches!(
                    err,
                    Error::InvalidQueryInput {
                        query_op: SteVecQueryOpKind::ValueSelector,
                        expected: ExpectedKind::ValueSelectorObject,
                        hint: QueryInputHint::UseValueSelectorObject,
                        ..
                    }
                ));
            }
        }

        #[test]
        fn test_invalid_json_path_error() {
            let js_plaintext = JsPlaintext::String("user.email".to_string()); // Missing $ prefix
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::SteVecSelector,
                &index_type,
                ColumnType::Json,
                EqlVersion::V2,
            );

            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            // Should mention the invalid path
            assert!(
                err_msg.contains("user.email"),
                "Error should show the invalid path: {}",
                err_msg
            );
            // Should suggest the correct format
            assert!(
                err_msg.contains("$.user.email") || err_msg.contains("$"),
                "Error should suggest correct format with $: {}",
                err_msg
            );
        }

        #[test]
        fn test_default_scalar_under_v3_infers_store_mode() {
            // A v3 scalar query operand must carry ALL the column domain's
            // terms (the SQL pairs each domain only with its same-name query
            // twin), so the scalar Default path runs Store mode and
            // query_output hoists the terms.
            let js_plaintext = JsPlaintext::String("hello".to_string());
            let index_type = IndexType::Unique {
                token_filters: vec![],
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::Default,
                &index_type,
                ColumnType::Text,
                EqlVersion::V3,
            );

            assert!(matches!(
                result,
                Ok((Plaintext::Text(Some(_)), InferredQueryMode::StoreMode))
            ));
        }

        #[test]
        fn test_default_scalar_under_v2_keeps_query_mode() {
            let js_plaintext = JsPlaintext::String("hello".to_string());
            let index_type = IndexType::Unique {
                token_filters: vec![],
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::Default,
                &index_type,
                ColumnType::Text,
                EqlVersion::V2,
            );

            assert!(matches!(
                result,
                Ok((
                    Plaintext::Text(Some(_)),
                    InferredQueryMode::QueryMode(QueryOp::Default)
                ))
            ));
        }

        #[test]
        fn test_ste_vec_selector_under_v3_stays_query_mode() {
            // Selector queries are version-independent at this layer:
            // query_output turns the v2 selector payload into the bare
            // selector string under v3.
            let js_plaintext = JsPlaintext::String("$.user.email".to_string());
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::SteVecSelector,
                &index_type,
                ColumnType::Json,
                EqlVersion::V3,
            );

            assert!(matches!(
                result,
                Ok((
                    Plaintext::Text(Some(_)),
                    InferredQueryMode::QueryMode(QueryOp::SteVecSelector)
                ))
            ));
        }

        #[test]
        fn test_ste_vec_containment_under_v3_stays_store_mode() {
            let js_plaintext = JsPlaintext::JsonB(serde_json::json!({"role": "admin"}));
            let index_type = IndexType::SteVec {
                prefix: "test/col".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode: Default::default(),
            };

            let result = to_query_plaintext(
                &js_plaintext,
                QueryOp::Default,
                &index_type,
                ColumnType::Json,
                EqlVersion::V3,
            );

            assert!(matches!(
                result,
                Ok((Plaintext::Json(Some(_)), InferredQueryMode::StoreMode))
            ));
        }
    }

    mod query_config_map {
        use super::*;
        use cipherstash_client::schema::column::{TokenFilter, Tokenizer};

        fn match_index(include_original: bool) -> Index {
            Index::new(IndexType::Match {
                tokenizer: Tokenizer::Ngram { token_length: 3 },
                token_filters: vec![TokenFilter::Downcase],
                k: 6,
                m: 2048,
                include_original,
            })
        }

        fn config_map(columns: Vec<(&str, &str, Vec<Index>)>) -> HashMap<Identifier, ColumnConfig> {
            columns
                .into_iter()
                .map(|(table, column, indexes)| {
                    let config = indexes
                        .into_iter()
                        .fold(ColumnConfig::build(column), ColumnConfig::add_index);
                    (
                        Identifier::new(table.to_string(), column.to_string()),
                        config,
                    )
                })
                .collect()
        }

        fn include_original_flags(
            map: &HashMap<Identifier, ColumnConfig>,
            table: &str,
            column: &str,
        ) -> Vec<bool> {
            map[&Identifier::new(table.to_string(), column.to_string())]
                .indexes
                .iter()
                .filter_map(|index| match &index.index_type {
                    IndexType::Match {
                        include_original, ..
                    } => Some(*include_original),
                    _ => None,
                })
                .collect()
        }

        #[test]
        fn strips_include_original_from_every_match_index() {
            let encrypt_config = config_map(vec![
                (
                    "users",
                    "email",
                    vec![match_index(true), Index::new(IndexType::Ore)],
                ),
                ("users", "name", vec![match_index(false)]),
            ]);

            let query_config = query_config_map(encrypt_config);

            assert_eq!(
                include_original_flags(&query_config, "users", "email"),
                vec![false]
            );
            assert_eq!(
                include_original_flags(&query_config, "users", "name"),
                vec![false]
            );
        }

        #[test]
        fn leaves_the_storage_config_and_other_indexes_untouched() {
            let encrypt_config = config_map(vec![(
                "users",
                "email",
                vec![match_index(true), Index::new(IndexType::Ore)],
            )]);

            let query_config = query_config_map(encrypt_config.clone());

            // The storage map keeps the flag: include_original stays honoured
            // for stored blooms.
            assert_eq!(
                include_original_flags(&encrypt_config, "users", "email"),
                vec![true]
            );
            // Non-match indexes survive the copy.
            let ident = Identifier::new("users".to_string(), "email".to_string());
            assert!(query_config[&ident]
                .indexes
                .iter()
                .any(|index| matches!(index.index_type, IndexType::Ore)));
        }
    }

    /// A key an options struct doesn't declare is an error, not a silent drop.
    ///
    /// These run through `serde_json`, which is the Neon boundary exactly:
    /// neon's `Json` extractor is `JSON.stringify` on the JS side. The wasm
    /// boundary is `serde_wasm_bindgen` and can't be driven from a native
    /// test — `integration-tests/tests/strict-options.test.ts` covers it, and
    /// covers it deliberately, because that boundary needs [`DenyUnknown`] to
    /// reject anything at all.
    mod deny_unknown_fields {
        use super::*;
        use crate::client_options::{EnsureKeysetOpts, NewClientOptions};
        use serde_json::json;

        fn rejection<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> String {
            serde_json::from_value::<T>(value)
                .err()
                .expect("expected deserialization to fail")
                .to_string()
        }

        fn accepts<T: serde::de::DeserializeOwned>(value: serde_json::Value) {
            if let Err(e) = serde_json::from_value::<T>(value) {
                panic!("expected deserialization to succeed, got: {e}");
            }
        }

        fn encrypt_config() -> serde_json::Value {
            json!({"v": 1, "tables": {}})
        }

        const CLIENT_ID: &str = "8f7ae6de-6b6a-4f9e-9dd4-2b2e39bc3b52";

        #[test]
        fn new_client_rejects_credentials_at_the_top_level() {
            // The incident behind #144: credentials belong under `clientOpts`.
            // Dropped silently, they surfaced later as "clientId and clientKey
            // are required" — with the caller looking straight at them.
            let msg = rejection::<NewClientOptions>(json!({
                "encryptConfig": encrypt_config(),
                "clientId": CLIENT_ID,
                "clientKey": "ab",
            }));
            assert!(msg.contains("unknown field `clientId`"), "{msg}");
        }

        #[test]
        fn new_client_accepts_the_documented_shape() {
            accepts::<NewClientOptions>(json!({
                "encryptConfig": encrypt_config(),
                "clientOpts": {"clientId": CLIENT_ID, "clientKey": "ab"},
                "eqlVersion": 3,
            }));
        }

        #[test]
        fn client_opts_rejects_an_unknown_key() {
            let msg = rejection::<NewClientOptions>(json!({
                "encryptConfig": encrypt_config(),
                "clientOpts": {"clientId": CLIENT_ID, "region": "ap-southeast-2"},
            }));
            assert!(msg.contains("unknown field `region`"), "{msg}");
        }

        #[test]
        fn ensure_keyset_rejects_an_unknown_key_but_keeps_the_flattened_credentials() {
            accepts::<EnsureKeysetOpts>(json!({"name": "ks", "clientId": CLIENT_ID}));

            let msg = rejection::<EnsureKeysetOpts>(json!({"name": "ks", "id": "ks-1"}));
            assert!(msg.contains("unknown field `id`"), "{msg}");
        }

        #[test]
        fn encrypt_rejects_a_misspelled_unverified_context() {
            let msg = rejection::<EncryptOptions>(json!({
                "plaintext": "hello",
                "column": "email",
                "table": "users",
                "unverifedContext": {"sub": "user-1"},
            }));
            assert!(msg.contains("unknown field `unverifedContext`"), "{msg}");
        }

        #[test]
        fn encrypt_bulk_rejects_a_lock_context_at_the_top_level() {
            // The security case. `lockContext` is per-payload on a bulk call;
            // at the top level it was dropped, and every value encrypted
            // UNBOUND while the caller believed it was identity-bound. Nothing
            // in the output distinguishes the two.
            let msg = rejection::<EncryptBulkOptions>(json!({
                "plaintexts": [{"plaintext": "hello", "column": "email", "table": "users"}],
                "lockContext": {"identityClaim": ["sub"]},
            }));
            assert!(msg.contains("unknown field `lockContext`"), "{msg}");
        }

        #[test]
        fn bulk_payloads_still_take_their_own_lock_context() {
            accepts::<EncryptBulkOptions>(json!({
                "plaintexts": [{
                    "plaintext": "hello",
                    "column": "email",
                    "table": "users",
                    "lockContext": {"identityClaim": ["sub"]},
                }],
            }));
        }

        #[test]
        fn decrypt_bulk_rejects_a_lock_context_at_the_top_level() {
            let msg = rejection::<DecryptBulkOptions>(json!({
                "ciphertexts": [{"ciphertext": {}}],
                "lockContext": {"identityClaim": ["sub"]},
            }));
            assert!(msg.contains("unknown field `lockContext`"), "{msg}");
        }

        #[test]
        fn lock_context_rejects_an_unknown_key() {
            let msg = rejection::<LockContext>(json!({
                "identityClaim": ["sub"],
                "identityClaims": ["sub"],
            }));
            assert!(msg.contains("unknown field `identityClaims`"), "{msg}");
        }

        #[test]
        fn a_bulk_payload_rejects_a_misspelled_lock_context() {
            // The per-item form of the case above, and the likelier of the
            // two: the container rejects `lockContext` because it belongs on
            // the item, and the item silently dropped a misspelling of it.
            // Both spellings encrypt UNBOUND.
            let msg = rejection::<EncryptBulkOptions>(json!({
                "plaintexts": [{
                    "plaintext": "hello",
                    "column": "email",
                    "table": "users",
                    "lokContext": {"identityClaim": ["sub"]},
                }],
            }));
            assert!(msg.contains("unknown field `lokContext`"), "{msg}");
        }

        #[test]
        fn the_containers_and_the_payloads_do_not_share_a_vocabulary() {
            // The mirror-image trap for anyone copying the scalar call shape:
            // `unverifiedContext` is a container key and `lockContext` a
            // payload one, and each is now rejected in the other's place
            // rather than dropped.
            let msg = rejection::<EncryptBulkOptions>(json!({
                "plaintexts": [{
                    "plaintext": "hello",
                    "column": "email",
                    "table": "users",
                    "unverifiedContext": {"sub": "user-1"},
                }],
            }));
            assert!(msg.contains("unknown field `unverifiedContext`"), "{msg}");

            let msg = rejection::<DecryptBulkOptions>(json!({
                "ciphertexts": [{"ciphertext": {}, "unverifiedContext": {"sub": "u"}}],
            }));
            assert!(msg.contains("unknown field `unverifiedContext`"), "{msg}");
        }

        #[test]
        fn a_decrypt_payload_rejects_a_misspelled_lock_context() {
            let msg = rejection::<DecryptBulkOptions>(json!({
                "ciphertexts": [{
                    "ciphertext": {},
                    "lokContext": {"identityClaim": ["sub"]},
                }],
            }));
            assert!(msg.contains("unknown field `lokContext`"), "{msg}");
        }

        #[test]
        fn decrypt_rejects_an_unknown_key() {
            let msg = rejection::<DecryptOptions>(json!({
                "ciphertext": {},
                "lockContexts": {"identityClaim": ["sub"]},
            }));
            assert!(msg.contains("unknown field `lockContexts`"), "{msg}");
        }

        #[test]
        fn encrypt_query_rejects_a_misspelled_index_type() {
            // `indexType` is required, so misspelling it reports the MISSING
            // field rather than the unknown one — see the note on
            // [`DenyUnknown`]. The key is still named, just not by this
            // message.
            let msg = rejection::<EncryptQueryOptions>(json!({
                "plaintext": "hello",
                "column": "email",
                "table": "users",
                "indexTyp": "unique",
            }));
            assert!(msg.contains("missing field `indexType`"), "{msg}");
        }

        #[test]
        fn encrypt_query_rejects_a_misspelled_query_op() {
            let msg = rejection::<EncryptQueryOptions>(json!({
                "plaintext": "hello",
                "column": "email",
                "table": "users",
                "indexType": "unique",
                "queryOpp": "match",
            }));
            assert!(msg.contains("unknown field `queryOpp`"), "{msg}");
            // And nothing more. Serde's flatten path buffers the map and
            // reports at its closing brace, so the `expected one of ...` list
            // every other rejection used to carry is gone — see the note on
            // [`DenyUnknown`]. Asserted so the cost stays visible.
            assert!(!msg.contains("expected"), "{msg}");
        }

        #[test]
        fn encrypt_query_bulk_rejects_an_unknown_key_on_either_level() {
            let msg = rejection::<EncryptQueryBulkOptions>(json!({
                "queries": [],
                "lockContext": {"identityClaim": ["sub"]},
            }));
            assert!(msg.contains("unknown field `lockContext`"), "{msg}");

            let msg = rejection::<EncryptQueryBulkOptions>(json!({
                "queries": [{
                    "plaintext": "hello",
                    "column": "email",
                    "table": "users",
                    "indexType": "unique",
                    "unverifiedContext": {"sub": "user-1"},
                }],
            }));
            assert!(msg.contains("unknown field `unverifiedContext`"), "{msg}");
        }

        #[test]
        fn encrypt_query_keeps_its_query_op_default() {
            // `DenyUnknown` moves deserialization onto serde's flatten path.
            // Field defaults have to survive that, and an absent `queryOp` is
            // the one this crate relies on.
            let opts: EncryptQueryOptions = serde_json::from_value(json!({
                "plaintext": "hello",
                "column": "email",
                "table": "users",
                "indexType": "unique",
            }))
            .expect("valid query options");
            assert_eq!(opts.query_op, QueryOpName::Default);
        }

        #[test]
        fn encrypt_query_still_reports_a_missing_required_field_as_missing() {
            let msg = rejection::<EncryptQueryOptions>(json!({
                "column": "email",
                "table": "users",
                "indexType": "unique",
            }));
            assert!(msg.contains("missing field `plaintext`"), "{msg}");
        }
    }
}
