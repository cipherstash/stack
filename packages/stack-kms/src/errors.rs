use miette::Diagnostic;
use stack_auth::diagnostic::{payload, ErrorPayload};
use thiserror::Error;
use vitaminc::random::RandomError;
use zerokms_protocol::{IdentifiedBy, ViturRequestError, ViturRequestErrorKind};

/// The fields a failed ZeroKMS request contributes: the request kind
/// (`NotFound`, `SendRequest`, ...), and nothing from the response body.
fn request_payload(error: &ViturRequestError) -> serde_json::Map<String, serde_json::Value> {
    payload([("request_kind", request_kind(&error.kind).into())])
}

/// A request kind as the payload spells it. Written out rather than taken
/// from `Debug`, which is no format and belongs to `zerokms-protocol`: the
/// match has no wildcard, so a kind added there fails to compile here
/// instead of reaching a caller as a value nobody wrote down.
fn request_kind(kind: &ViturRequestErrorKind) -> &'static str {
    match kind {
        ViturRequestErrorKind::PrepareRequest => "PrepareRequest",
        ViturRequestErrorKind::SendRequest => "SendRequest",
        ViturRequestErrorKind::NotFound => "NotFound",
        ViturRequestErrorKind::Conflict => "Conflict",
        ViturRequestErrorKind::FailureResponse => "FailureResponse",
        ViturRequestErrorKind::ParseResponse => "ParseResponse",
        ViturRequestErrorKind::Unauthorized => "Unauthorized",
        ViturRequestErrorKind::Forbidden => "Forbidden",
        ViturRequestErrorKind::Other => "Other",
    }
}

/// The fields a failed keyset load contributes: its request kind, and the
/// keyset it asked for, as `keyset_id` or `keyset_name`, or neither for the
/// client's default keyset. Keyset ids and names are details the
/// [`ErrorPayload`] policy allows.
fn keyset_request_payload(
    keyset: Option<&IdentifiedBy>,
    error: &ViturRequestError,
) -> serde_json::Map<String, serde_json::Value> {
    let mut fields = request_payload(error);
    let named = match keyset {
        Some(IdentifiedBy::Uuid(id)) => Some(("keyset_id", id.to_string())),
        Some(IdentifiedBy::Name(name)) => Some(("keyset_name", name.to_string())),
        None => None,
    };
    fields.extend(named.map(|(key, value)| (key.to_owned(), value.into())));
    fields
}

/// The keyset a load asked for, as a message names it: `name "tenant-42"`,
/// `id 6a70bd18-...`, or the client's default keyset. A name is quoted with
/// Rust's escapes, so a name that ZeroKMS would not issue still prints on
/// one line.
fn requested_keyset(keyset: Option<&IdentifiedBy>) -> String {
    match keyset {
        Some(IdentifiedBy::Uuid(id)) => format!("keyset id {id}"),
        Some(IdentifiedBy::Name(name)) => format!("keyset name {:?}", &**name),
        None => "the client's default keyset".into(),
    }
}

/// What a keyset-not-found message says after "Keyset not found: ". ZeroKMS
/// looks a keyset up through the client's grant of it, so a keyset asked
/// for by id or name is also not found when it is not granted to this
/// client, and when the client is unknown. The default keyset is missing
/// when the client is unknown or has none.
fn not_found(keyset: Option<&IdentifiedBy>) -> String {
    match keyset {
        Some(_) => format!(
            "{} does not exist, is not granted to this client, or the client is unknown",
            requested_keyset(keyset)
        ),
        None => "the client is unknown, or has no default keyset".into(),
    }
}

/// The help for a data-key request ZeroKMS failed, by the request kind.
///
/// ZeroKMS answers a data-key request with HTTP 403 for three causes, and
/// its answer does not say which: the value is opened under another context
/// than the one it was sealed under, the keyset is disabled, or the access
/// token lacks the scope to retrieve keys. So the help for a 403 names all
/// three. A client with no grant for the keyset is answered 404, not 403.
/// A binding that knows more about the call, such as whether it loaded the
/// keyset first, may replace the help with the likely cause.
fn retrieve_help(kind: &ViturRequestErrorKind) -> &'static str {
    match kind {
        ViturRequestErrorKind::Forbidden => {
            "ZeroKMS refused the data key. The value is opened under another context than the one it was sealed under, the keyset is disabled, or the access token lacks the scope to retrieve keys. Open the value under the context it was sealed with."
        }
        ViturRequestErrorKind::Unauthorized => {
            "ZeroKMS refused the access token. Refresh the credential and retry."
        }
        ViturRequestErrorKind::NotFound => {
            "ZeroKMS found no grant of the value's keyset to this client, or does not know the client. Check the keyset's grants in ZeroKMS, and the client ID."
        }
        ViturRequestErrorKind::PrepareRequest | ViturRequestErrorKind::SendRequest => {
            "The request did not reach ZeroKMS. Check the network and the ZeroKMS endpoint, and retry."
        }
        ViturRequestErrorKind::Conflict
        | ViturRequestErrorKind::FailureResponse
        | ViturRequestErrorKind::ParseResponse
        | ViturRequestErrorKind::Other => {
            "ZeroKMS failed the request, or sent a response the client could not read. Retry, and report the error if it persists."
        }
    }
}

/// The fields of a key-count mismatch.
fn count_payload(expected: usize, received: usize) -> serde_json::Map<String, serde_json::Value> {
    payload([("expected", expected.into()), ("received", received.into())])
}

/// Key material returned by ZeroKMS failed up-front validation before key
/// derivation — e.g. a truncated or corrupt response whose material is not the
/// exact length the keyset's block permutation covers. The material is
/// network-supplied, so this must surface as an error, never a panic.
#[derive(Diagnostic, Error, Debug)]
#[error("Invalid keyset key material: {0}")]
#[diagnostic(code(stack_kms::invalid_key_material))]
pub struct InvalidKeyMaterialError(#[from] pub zerokms_keyset::Error);

impl ErrorPayload for InvalidKeyMaterialError {}

#[derive(Diagnostic, Error, Debug)]
pub enum RetrieveKeyError {
    // `ViturRequestError`'s Display is its kind and a static message; the
    // response it carries stays behind `source()`. The help is the request
    // kind's (see `retrieve_help`).
    #[error("Failed to send request: {0}")]
    #[diagnostic(
        code(stack_kms::retrieve_key_failed),
        help("{}", retrieve_help(&.0.kind))
    )]
    RequestFailed(#[from] ViturRequestError),
    #[error("Received an invalid number of keys from request. Expected {expected} but received {received}")]
    #[diagnostic(code(stack_kms::retrieved_key_count))]
    InvalidNumberOfKeys { expected: usize, received: usize },

    /// Represents an error that occurs when a single key retrieval fails.
    /// May be part of a batch retrieval operation.
    ///
    /// The string is ZeroKMS's own reason for the one key, kept for a caller
    /// in this process to inspect. It is response text, so the message does
    /// not repeat it (see [`ErrorPayload`] for the rule).
    #[error("Failed to retrieve key")]
    #[diagnostic(
        code(stack_kms::key_not_retrieved),
        help("ZeroKMS returned no data key for this value. Check it is opened under the context it was sealed with.")
    )]
    FailedRetrieval(String),

    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidKeyMaterial(#[from] InvalidKeyMaterialError),
}

#[derive(Diagnostic, Error, Debug)]
pub enum GenerateKeyError {
    #[error("Request not authorized")]
    #[diagnostic(
        code(stack_kms::generate_key_unauthorized),
        help("ZeroKMS refused the access token. Refresh the credential and retry.")
    )]
    Unauthorized,
    #[error("Request forbidden due to insufficient permissions")]
    #[diagnostic(
        code(stack_kms::generate_key_forbidden),
        help("The client is not allowed to generate keys in this keyset: check the keyset's grants, and that it is enabled.")
    )]
    Forbidden,
    // The random source's own message is not repeated; it is the source.
    #[error("Failed to generate IV")]
    #[diagnostic(code(stack_kms::generate_iv))]
    GenerateIv(#[source] RandomError),
    #[error("Received an invalid number of keys from request. Expected {expected} but received {received}")]
    #[diagnostic(code(stack_kms::generated_key_count))]
    InvalidNumberOfKeys { expected: usize, received: usize },

    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidKeyMaterial(#[from] InvalidKeyMaterialError),
    // Catch-all for any `ViturRequestError` not classified as Forbidden /
    // Unauthorized above. Display surfaces the `kind` (operational enum
    // — `SendRequest`, `Other`, `ParseResponse`, ...) and `message`
    // (`&'static str`, build-time only, no dynamic data) so the bare
    // failure mode is visible. The dynamic `error: ShareableError` field
    // is reachable through `Error::source()` via `#[source]`, so callers
    // using anyhow chain formatting (`{:?}` / `{:#}`) or `tracing` get the
    // underlying transport / response error; the Display string itself
    // stays free of dynamic data.
    #[error("Unexpected error ({}: {})", .0.kind, .0.message)]
    #[diagnostic(code(stack_kms::generate_key_failed))]
    RequestFailed(#[source] ViturRequestError),
}

impl ErrorPayload for RetrieveKeyError {
    fn payload(&self) -> serde_json::Map<String, serde_json::Value> {
        match self {
            Self::RequestFailed(error) => request_payload(error),
            Self::InvalidNumberOfKeys { expected, received } => count_payload(*expected, *received),
            Self::FailedRetrieval(_) => serde_json::Map::new(),
            Self::InvalidKeyMaterial(error) => error.payload(),
        }
    }
}

impl ErrorPayload for GenerateKeyError {
    fn payload(&self) -> serde_json::Map<String, serde_json::Value> {
        match self {
            Self::RequestFailed(error) => request_payload(error),
            Self::InvalidNumberOfKeys { expected, received } => count_payload(*expected, *received),
            Self::InvalidKeyMaterial(error) => error.payload(),
            Self::Unauthorized | Self::Forbidden | Self::GenerateIv(_) => serde_json::Map::new(),
        }
    }
}

impl From<ViturRequestError> for GenerateKeyError {
    fn from(err: ViturRequestError) -> Self {
        match err.kind {
            ViturRequestErrorKind::Forbidden => Self::Forbidden,
            ViturRequestErrorKind::Unauthorized => Self::Unauthorized,
            _ => Self::RequestFailed(err),
        }
    }
}

#[derive(Diagnostic, Error, Debug)]
pub enum LoadKeysetError {
    // `Unauthorized` / `Forbidden` carry the underlying request error (unlike
    // `GenerateKeyError`'s unit variants) because `load-keyset` has 403
    // responses that mean different things: the server rejects a *disabled*
    // keyset with a 403 whose body says "Keyset disabled: ...". Display stays
    // static (no dynamic data); the distinguishing server response is
    // reachable through `source()`.
    #[error("Request not authorized")]
    #[diagnostic(
        code(stack_kms::load_keyset_unauthorized),
        help("ZeroKMS refused the access token. Refresh the credential and retry.")
    )]
    Unauthorized(#[source] ViturRequestError),
    /// ZeroKMS refused to load the keyset: it answers 403 for a disabled
    /// keyset, and for an access token without the scope to use keys. A
    /// keyset not granted to this client is answered 404, as
    /// [`KeysetNotFound`](Self::KeysetNotFound). The message and help name
    /// the keyset the load asked for: a keyset id or name is a detail the
    /// [`ErrorPayload`] policy allows.
    #[error("Request forbidden due to insufficient permissions: {}", requested_keyset(.keyset.as_ref()))]
    #[diagnostic(
        code(stack_kms::load_keyset_forbidden),
        help("ZeroKMS refused to load {}. The keyset is disabled, or the access token lacks the scope to use keys. Enable the keyset in ZeroKMS, or use a credential with that scope.", requested_keyset(.keyset.as_ref()))
    )]
    Forbidden {
        /// The keyset the load asked for. `None` is the client's default.
        keyset: Option<IdentifiedBy>,
        /// ZeroKMS's answer.
        #[source]
        source: ViturRequestError,
    },
    // `load-keyset` uniquely takes a caller-supplied keyset id or name, so a
    // server 404 is an expected, user-actionable outcome — e.g. a typo'd
    // name — not an "unexpected error". Note the server also responds 404
    // when the keyset exists but is not granted to this client, and when the
    // *client* is unknown or has no default keyset, so a 404 does not prove
    // the named keyset is missing: inspect `source()` for the server's
    // response body before treating this as "create the keyset".
    /// ZeroKMS has no keyset this client may load under the id or name the
    /// load asked for. The message names the keyset.
    #[error("Keyset not found: {}", not_found(.keyset.as_ref()))]
    #[diagnostic(
        code(stack_kms::keyset_not_found),
        help("ZeroKMS answers 404 when no keyset has this id or name, when the keyset exists but is not granted to this client, and when the client is unknown or has no default keyset. Check the keyset's name, the client ID, and the keyset's grants in ZeroKMS before creating a keyset.")
    )]
    KeysetNotFound {
        /// The keyset the load asked for. `None` is the client's default.
        keyset: Option<IdentifiedBy>,
        /// ZeroKMS's answer.
        #[source]
        source: ViturRequestError,
    },
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidKeyMaterial(#[from] InvalidKeyMaterialError),
    // Same shape as `GenerateKeyError::RequestFailed`: Display carries only the
    // static kind/message; the dynamic error stays behind `source()`.
    #[error("Unexpected error ({}: {})", .0.kind, .0.message)]
    #[diagnostic(code(stack_kms::load_keyset_failed))]
    RequestFailed(#[source] ViturRequestError),
}

impl ErrorPayload for LoadKeysetError {
    fn payload(&self) -> serde_json::Map<String, serde_json::Value> {
        match self {
            Self::Unauthorized(error) | Self::RequestFailed(error) => request_payload(error),
            Self::Forbidden { keyset, source } | Self::KeysetNotFound { keyset, source } => {
                keyset_request_payload(keyset.as_ref(), source)
            }
            Self::InvalidKeyMaterial(error) => error.payload(),
        }
    }
}

impl LoadKeysetError {
    /// The error for a failed request to load `keyset` (`None` is the
    /// client's default keyset), by the request's kind. A refusal and a
    /// missing keyset name the keyset they are about.
    pub fn from_request(keyset: Option<IdentifiedBy>, error: ViturRequestError) -> Self {
        match error.kind {
            ViturRequestErrorKind::Forbidden => Self::Forbidden {
                keyset,
                source: error,
            },
            ViturRequestErrorKind::Unauthorized => Self::Unauthorized(error),
            ViturRequestErrorKind::NotFound => Self::KeysetNotFound {
                keyset,
                source: error,
            },
            _ => Self::RequestFailed(error),
        }
    }
}

#[cfg(test)]
mod codes {
    use stack_auth::diagnostic::is_code_of;

    use super::*;
    use crate::connection::{BaseUrlUnresolved, FailureResponse, UnexpectedContentType};
    use crate::endpoint::InvalidEndpoint;
    use crate::key_provider::KeyProviderError;

    fn vitur(kind: ViturRequestErrorKind) -> ViturRequestError {
        ViturRequestError::new(kind, "boom", std::io::Error::other("detail"))
    }

    fn material() -> InvalidKeyMaterialError {
        zerokms_keyset::Error::InvalidInputLength {
            expected: 32,
            received: 3,
        }
        .into()
    }

    /// One row per variant of an enum, written `pattern => value`. The
    /// patterns are the arms of a match with no wildcard, so a variant with
    /// no row fails to compile, and each value must match its own pattern.
    macro_rules! variants {
        ($($pattern:pat => $value:expr),+ $(,)?) => {{
            let rows = vec![$({
                let value = $value;
                assert!(matches!(value, $pattern), "{value:?} is not {}", stringify!($pattern));
                value
            }),+];
            for row in &rows {
                match row {
                    $($pattern => {})+
                }
            }
            rows
        }};
    }

    /// A test's row: an error, boxed with its type's name.
    type Row = (&'static str, Box<dyn Diagnostic>);

    fn boxed<E: Diagnostic + 'static>(rows: Vec<E>) -> impl Iterator<Item = Row> {
        rows.into_iter().map(stack_auth::diagnostic::named)
    }

    /// One of every variant of every error type here.
    fn every_variant() -> Vec<Row> {
        let mut errors: Vec<Row> = vec![
            stack_auth::diagnostic::named(material()),
            stack_auth::diagnostic::named(BaseUrlUnresolved),
            stack_auth::diagnostic::named(UnexpectedContentType {
                received: Some("text/html".into()),
                expected: "application/json",
                body: None,
                headers: Default::default(),
            }),
            stack_auth::diagnostic::named(FailureResponse {
                status: 500,
                body: None,
                headers: Default::default(),
            }),
        ];
        errors.extend(boxed(variants![
            RetrieveKeyError::RequestFailed(_) => {
                RetrieveKeyError::RequestFailed(vitur(ViturRequestErrorKind::SendRequest))
            },
            RetrieveKeyError::InvalidNumberOfKeys { .. } => RetrieveKeyError::InvalidNumberOfKeys {
                expected: 2,
                received: 1,
            },
            RetrieveKeyError::FailedRetrieval(_) => {
                RetrieveKeyError::FailedRetrieval("no key".into())
            },
            RetrieveKeyError::InvalidKeyMaterial(_) => {
                RetrieveKeyError::InvalidKeyMaterial(material())
            },
        ]));
        errors.extend(boxed(variants![
            GenerateKeyError::Unauthorized => GenerateKeyError::Unauthorized,
            GenerateKeyError::Forbidden => GenerateKeyError::Forbidden,
            GenerateKeyError::GenerateIv(_) => {
                GenerateKeyError::GenerateIv(RandomError::GenerationFailed)
            },
            GenerateKeyError::InvalidNumberOfKeys { .. } => GenerateKeyError::InvalidNumberOfKeys {
                expected: 2,
                received: 1,
            },
            GenerateKeyError::InvalidKeyMaterial(_) => {
                GenerateKeyError::InvalidKeyMaterial(material())
            },
            GenerateKeyError::RequestFailed(_) => {
                GenerateKeyError::RequestFailed(vitur(ViturRequestErrorKind::Other))
            },
        ]));
        errors.extend(boxed(variants![
            LoadKeysetError::Unauthorized(_) => {
                LoadKeysetError::Unauthorized(vitur(ViturRequestErrorKind::Unauthorized))
            },
            LoadKeysetError::Forbidden { .. } => LoadKeysetError::Forbidden {
                keyset: None,
                source: vitur(ViturRequestErrorKind::Forbidden),
            },
            LoadKeysetError::KeysetNotFound { .. } => LoadKeysetError::KeysetNotFound {
                keyset: None,
                source: vitur(ViturRequestErrorKind::NotFound),
            },
            LoadKeysetError::InvalidKeyMaterial(_) => {
                LoadKeysetError::InvalidKeyMaterial(material())
            },
            LoadKeysetError::RequestFailed(_) => {
                LoadKeysetError::RequestFailed(vitur(ViturRequestErrorKind::Conflict))
            },
        ]));
        // A variant that wraps another of this crate's errors, or a
        // stack-auth error, forwards that error's code.
        errors.extend(boxed(variants![
            Error::GenerateKey(_) => Error::GenerateKey(GenerateKeyError::Forbidden),
            Error::RetrieveKey(_) => {
                Error::RetrieveKey(RetrieveKeyError::FailedRetrieval("no key".into()))
            },
            Error::LoadKeyset(_) => Error::LoadKeyset(LoadKeysetError::from_request(
                None,
                vitur(ViturRequestErrorKind::NotFound),
            )),
            Error::Auth(_) => {
                Error::Auth(stack_auth::AuthError::TokenExpired(stack_auth::TokenExpired))
            },
            Error::ConnectionInit(_) => {
                Error::ConnectionInit(Box::new(std::io::Error::other("no")))
            },
            Error::InvalidEndpoint(_) => Error::InvalidEndpoint(InvalidEndpoint::Userinfo),
            Error::Unexpected(_) => Error::Unexpected("unexpected".into()),
        ]));
        errors.extend(boxed(variants![
            InvalidEndpoint::Parse(_) => InvalidEndpoint::Parse(url::ParseError::EmptyHost),
            InvalidEndpoint::NoHost(_) => InvalidEndpoint::NoHost("localhost:8080".into()),
            InvalidEndpoint::Scheme(_) => InvalidEndpoint::Scheme("ftp".into()),
            InvalidEndpoint::QueryOrFragment(_) => {
                InvalidEndpoint::QueryOrFragment("https://x/?q".into())
            },
            InvalidEndpoint::Userinfo => InvalidEndpoint::Userinfo,
        ]));
        errors.extend(boxed(variants![
            KeyProviderError::NotConfigured(_) => KeyProviderError::NotConfigured("unset".into()),
            KeyProviderError::InvalidKey(_) => KeyProviderError::InvalidKey("not hex".into()),
            KeyProviderError::LoadError(_) => KeyProviderError::LoadError("disk".into()),
        ]));
        if let Err(error) = crate::ClientOpts::new(()).with_max_keys_per_req(0) {
            errors.push(stack_auth::diagnostic::named(error));
        }
        // The auth error the two `Auth` wrappers carry, as a row of its own:
        // a wrapper counts as the error it forwards.
        errors.push(stack_auth::diagnostic::named(
            stack_auth::AuthError::TokenExpired(stack_auth::TokenExpired),
        ));
        #[cfg(feature = "http")]
        {
            use crate::builder::StackKmsBuilderError;
            let reqwest_error = reqwest::Client::new()
                .get("not a url")
                .build()
                .expect_err("not a URL");
            errors.push(stack_auth::diagnostic::named(
                crate::ConnectionInitError::from(reqwest_error),
            ));
            errors.extend(boxed(variants![
                StackKmsBuilderError::InvalidEndpoint { .. } => {
                    StackKmsBuilderError::InvalidEndpoint {
                        env_var: "CS_ZEROKMS_HOST",
                        source: InvalidEndpoint::Userinfo,
                    }
                },
                StackKmsBuilderError::ClientInit(_) => {
                    StackKmsBuilderError::ClientInit(Error::Unexpected("unexpected".into()))
                },
                StackKmsBuilderError::Auth(_) => StackKmsBuilderError::Auth(
                    stack_auth::AuthError::TokenExpired(stack_auth::TokenExpired)
                ),
                StackKmsBuilderError::InvalidConfig(_) => StackKmsBuilderError::InvalidConfig(
                    crate::ClientOpts::new(())
                        .with_max_keys_per_req(0)
                        .err()
                        .expect("zero keys per request is refused"),
                ),
                StackKmsBuilderError::KeyProvider(_) => StackKmsBuilderError::KeyProvider(
                    KeyProviderError::NotConfigured("unset".into()),
                ),
            ]));
        }
        errors
    }

    /// Every variant has a code in this crate's namespace and `snake_case`,
    /// save one that carries a stack-auth error, whose code is that error's.
    #[test]
    fn every_variant_has_a_code_of_this_crate() {
        for (_, error) in every_variant() {
            let code = error
                .code()
                .unwrap_or_else(|| panic!("{error:?} has no code"))
                .to_string();
            assert!(
                is_code_of("stack_kms", &code) || is_code_of("stack_auth", &code),
                "{code}"
            );
        }
    }

    /// No two variants share a code by mistake: callers branch on it.
    /// `invalid_endpoint` is shared on purpose: an endpoint from
    /// `CS_ZEROKMS_HOST` (the builder's) and one from the token's services
    /// claim (the client's) are refused for the same reasons, and the message
    /// says which source it was. The builder exists only with `http`, so
    /// without it nothing is shared.
    #[test]
    fn no_two_variants_share_a_code_by_mistake() {
        let errors = every_variant();
        let shared = stack_auth::diagnostic::shared_codes(
            errors.iter().map(|(name, error)| (*name, error.as_ref())),
        );
        let codes: Vec<&str> = shared.keys().map(String::as_str).collect();
        let intended: &[&str] = if cfg!(feature = "http") {
            &["stack_kms::invalid_endpoint"]
        } else {
            &[]
        };
        assert_eq!(codes, intended, "{shared:#?}");
    }

    /// A ZeroKMS failure gives its request kind, never the response it
    /// carried: the detail behind `source()` stays out of the payload too.
    #[test]
    fn a_request_failure_gives_the_kind_and_not_the_response() {
        let error = Error::LoadKeyset(LoadKeysetError::from_request(
            None,
            vitur(ViturRequestErrorKind::NotFound),
        ));
        let fields = error.payload();
        assert_eq!(fields["request_kind"], "NotFound");
        assert!(!format!("{fields:?}").contains("detail"), "{fields:?}");
        assert!(error
            .help()
            .is_some_and(|help| help.to_string().contains("client is unknown")));
    }

    fn name(name: &str) -> Option<IdentifiedBy> {
        Some(IdentifiedBy::Name(zerokms_protocol::Name::new_untrusted(
            name,
        )))
    }

    const ID: uuid::Uuid = uuid::uuid!("6a70bd18-99ac-4650-b104-37eec3a15b09");

    fn help_of(error: &dyn Diagnostic) -> String {
        error
            .help()
            .map(|help| help.to_string())
            .unwrap_or_default()
    }

    /// A keyset ZeroKMS did not find is named in the message and the
    /// payload, by name or by id, and the help says that a keyset which
    /// exists but is not granted to this client is answered the same way.
    #[test]
    fn a_keyset_not_found_names_the_keyset_and_says_it_may_not_be_granted() {
        let cases = [
            (
                name("tenant-42"),
                r#"Keyset not found: keyset name "tenant-42" does not exist, is not granted to this client, or the client is unknown"#,
                Some(("keyset_name", "tenant-42")),
            ),
            (
                Some(IdentifiedBy::Uuid(ID)),
                "Keyset not found: keyset id 6a70bd18-99ac-4650-b104-37eec3a15b09 does not exist, is not granted to this client, or the client is unknown",
                Some(("keyset_id", "6a70bd18-99ac-4650-b104-37eec3a15b09")),
            ),
            (
                None,
                "Keyset not found: the client is unknown, or has no default keyset",
                None,
            ),
        ];
        for (keyset, message, field) in cases {
            let error =
                LoadKeysetError::from_request(keyset, vitur(ViturRequestErrorKind::NotFound));
            assert!(matches!(error, LoadKeysetError::KeysetNotFound { .. }));
            assert_eq!(error.to_string(), message);
            assert_eq!(
                error.code().map(|code| code.to_string()).as_deref(),
                Some("stack_kms::keyset_not_found")
            );
            let help = help_of(&error);
            assert!(help.contains("not granted to this client"), "{help}");
            let fields = error.payload();
            assert_eq!(fields["request_kind"], "NotFound");
            match field {
                Some((key, value)) => assert_eq!(fields[key], value, "{fields:?}"),
                None => assert!(
                    !fields.contains_key("keyset_id") && !fields.contains_key("keyset_name"),
                    "{fields:?}"
                ),
            }
        }
    }

    /// A refused keyset load names the keyset in its message and help.
    #[test]
    fn a_refused_keyset_load_names_the_keyset() {
        let error = LoadKeysetError::from_request(
            name("tenant-42"),
            vitur(ViturRequestErrorKind::Forbidden),
        );
        assert!(matches!(error, LoadKeysetError::Forbidden { .. }));
        assert_eq!(
            error.to_string(),
            r#"Request forbidden due to insufficient permissions: keyset name "tenant-42""#
        );
        assert_eq!(
            help_of(&error),
            r#"ZeroKMS refused to load keyset name "tenant-42". The keyset is disabled, or the access token lacks the scope to use keys. Enable the keyset in ZeroKMS, or use a credential with that scope."#
        );
        assert_eq!(error.payload()["keyset_name"], "tenant-42");
        let default = LoadKeysetError::from_request(None, vitur(ViturRequestErrorKind::Forbidden));
        assert!(
            help_of(&default).starts_with("ZeroKMS refused to load the client's default keyset."),
            "{}",
            help_of(&default)
        );
    }

    /// Every request kind a data-key request can fail with has a help. A
    /// refusal (HTTP 403) names its three causes, and does not name a
    /// missing grant, which ZeroKMS answers with 404. A 404 names the grant.
    #[test]
    fn every_data_key_request_failure_has_a_help() {
        use ViturRequestErrorKind as K;
        for kind in [
            K::PrepareRequest,
            K::SendRequest,
            K::NotFound,
            K::Conflict,
            K::FailureResponse,
            K::ParseResponse,
            K::Unauthorized,
            K::Forbidden,
            K::Other,
        ] {
            let shown = format!("{kind:?}");
            let help = help_of(&RetrieveKeyError::RequestFailed(vitur(kind)));
            assert!(!help.is_empty(), "{shown} has no help");
            assert!(!help.contains("detail"), "{shown}: {help}");
        }
        let help = help_of(&RetrieveKeyError::RequestFailed(vitur(K::Forbidden)));
        assert!(help.contains("another context"), "{help}");
        assert!(help.contains("keyset is disabled"), "{help}");
        assert!(help.contains("scope to retrieve keys"), "{help}");
        assert!(!help.contains("grant"), "{help}");
        let help = help_of(&RetrieveKeyError::RequestFailed(vitur(K::NotFound)));
        assert!(help.contains("no grant"), "{help}");
    }

    /// Every structured field this crate adds. A binding passes these on as
    /// they are, so a renamed key breaks the callers that read it.
    #[test]
    fn every_payload_carries_its_fields() {
        use serde_json::json;
        #[cfg_attr(not(feature = "http"), allow(unused_mut))]
        let mut rows: Vec<(Box<dyn ErrorPayload>, serde_json::Value)> = vec![
            (
                Box::new(InvalidEndpoint::Scheme("ftp".into())),
                json!({ "scheme": "ftp" }),
            ),
            (
                Box::new(InvalidEndpoint::QueryOrFragment("https://x/?q".into())),
                json!({}),
            ),
            (
                Box::new(FailureResponse {
                    status: 503,
                    body: Some("marker-body".into()),
                    headers: Default::default(),
                }),
                json!({ "status": 503 }),
            ),
            (
                Box::new(RetrieveKeyError::InvalidNumberOfKeys {
                    expected: 2,
                    received: 1,
                }),
                json!({ "expected": 2, "received": 1 }),
            ),
        ];
        #[cfg(feature = "http")]
        rows.push((
            Box::new(crate::builder::StackKmsBuilderError::InvalidEndpoint {
                env_var: "CS_ZEROKMS_HOST",
                source: InvalidEndpoint::Userinfo,
            }),
            json!({ "env_var": "CS_ZEROKMS_HOST" }),
        ));
        for (error, expected) in rows {
            assert_eq!(
                serde_json::Value::Object(error.payload()),
                expected,
                "{error:?}"
            );
        }
    }

    /// The builder's help names the variable that is wrong.
    #[cfg(feature = "http")]
    #[test]
    fn an_invalid_endpoint_help_names_its_variable() {
        let error = crate::builder::StackKmsBuilderError::InvalidEndpoint {
            env_var: "CS_ZEROKMS_HOST",
            source: InvalidEndpoint::Userinfo,
        };
        let help = error
            .help()
            .map(|help| help.to_string())
            .unwrap_or_default();
        assert!(help.starts_with("Set CS_ZEROKMS_HOST to "), "{help}");
    }

    /// The written-out kinds are the spellings callers already compare.
    #[test]
    fn every_request_kind_keeps_its_spelling() {
        use ViturRequestErrorKind as K;
        for kind in [
            K::PrepareRequest,
            K::SendRequest,
            K::NotFound,
            K::Conflict,
            K::FailureResponse,
            K::ParseResponse,
            K::Unauthorized,
            K::Forbidden,
            K::Other,
        ] {
            assert_eq!(request_kind(&kind), format!("{kind:?}"));
        }
    }

    #[test]
    fn no_endpoint_message_repeats_the_url() {
        for error in [
            InvalidEndpoint::NoHost("marker://user:pass@".into()),
            InvalidEndpoint::QueryOrFragment("https://x/?marker".into()),
        ] {
            assert!(!error.to_string().contains("marker"), "{error}");
        }
    }
}

/// Shared scaffolding for the `From<ViturRequestError>` mapping tests below:
/// one place for the fixture error and the assertions both mappings need, so
/// a new error type doesn't copy another 80 lines.
#[cfg(test)]
mod vitur_error_mapping_support {
    use super::*;

    pub(super) const SOURCE_DETAIL: &str = "transport-detail-7f3a";

    pub(super) fn err(kind: ViturRequestErrorKind) -> ViturRequestError {
        ViturRequestError::new(kind, "boom", std::io::Error::other(SOURCE_DETAIL))
    }

    /// Every kind in `kinds` must map to the catch-all RequestFailed variant
    /// carrying the same kind (checked via `is_request_failed_with_kind`).
    pub(super) fn assert_kinds_map_to_request_failed<E: std::fmt::Debug>(
        kinds: impl IntoIterator<Item = ViturRequestErrorKind>,
        from: impl Fn(ViturRequestError) -> E,
        is_request_failed_with_kind: impl Fn(&E, &str) -> bool,
    ) {
        for kind in kinds {
            // `ViturRequestErrorKind` has no `PartialEq`; compare by Debug name.
            let name = format!("{kind:?}");
            let mapped = from(err(kind));
            assert!(
                is_request_failed_with_kind(&mapped, &name),
                "{name} must map to RequestFailed carrying the same kind, got: {mapped:?}"
            );
        }
    }

    /// The catch-all's Display must name the kind and static message while
    /// keeping the dynamic source out; the source stays reachable through the
    /// error chain.
    pub(super) fn assert_request_failed_display(mapped: &impl std::error::Error) {
        let shown = mapped.to_string();
        assert!(shown.contains("SendRequest"), "{shown}");
        assert!(shown.contains("boom"), "{shown}");
        assert!(
            !shown.contains(SOURCE_DETAIL),
            "the dynamic source error must stay out of Display: {shown}"
        );
        assert!(
            mapped.source().is_some(),
            "the source must still be reachable through the error chain"
        );
    }
}

#[cfg(test)]
mod generate_key_error_from_vitur_request_error {
    use super::vitur_error_mapping_support::*;
    use super::*;

    #[test]
    fn forbidden_maps_to_forbidden() {
        assert!(matches!(
            GenerateKeyError::from(err(ViturRequestErrorKind::Forbidden)),
            GenerateKeyError::Forbidden
        ));
    }

    #[test]
    fn unauthorized_maps_to_unauthorized() {
        assert!(matches!(
            GenerateKeyError::from(err(ViturRequestErrorKind::Unauthorized)),
            GenerateKeyError::Unauthorized
        ));
    }

    #[test]
    fn every_other_kind_maps_to_request_failed_keeping_the_kind() {
        assert_kinds_map_to_request_failed(
            [
                ViturRequestErrorKind::PrepareRequest,
                ViturRequestErrorKind::SendRequest,
                ViturRequestErrorKind::NotFound,
                ViturRequestErrorKind::Conflict,
                ViturRequestErrorKind::FailureResponse,
                ViturRequestErrorKind::ParseResponse,
                ViturRequestErrorKind::Other,
            ],
            GenerateKeyError::from,
            |mapped, name| matches!(mapped, GenerateKeyError::RequestFailed(e) if format!("{:?}", e.kind) == name),
        );
    }

    #[test]
    fn request_failed_display_names_the_kind_and_message_but_not_the_source() {
        assert_request_failed_display(&GenerateKeyError::from(err(
            ViturRequestErrorKind::SendRequest,
        )));
    }
}

#[cfg(test)]
mod load_keyset_error_from_vitur_request_error {
    use super::vitur_error_mapping_support::*;
    use super::*;

    /// A failed load of the keyset named "tenant-42".
    fn load(error: ViturRequestError) -> LoadKeysetError {
        LoadKeysetError::from_request(
            Some(IdentifiedBy::Name(zerokms_protocol::Name::new_untrusted(
                "tenant-42",
            ))),
            error,
        )
    }

    #[test]
    fn forbidden_maps_to_forbidden_keeping_the_source() {
        let mapped = load(err(ViturRequestErrorKind::Forbidden));
        assert!(matches!(mapped, LoadKeysetError::Forbidden { .. }));
        assert!(
            std::error::Error::source(&mapped).is_some(),
            "the server response (e.g. 'Keyset disabled') must stay reachable"
        );
    }

    #[test]
    fn unauthorized_maps_to_unauthorized_keeping_the_source() {
        let mapped = load(err(ViturRequestErrorKind::Unauthorized));
        assert!(matches!(mapped, LoadKeysetError::Unauthorized(_)));
        assert!(std::error::Error::source(&mapped).is_some());
    }

    #[test]
    fn not_found_maps_to_keyset_not_found() {
        let mapped = load(err(ViturRequestErrorKind::NotFound));
        assert!(matches!(mapped, LoadKeysetError::KeysetNotFound { .. }));
        assert!(std::error::Error::source(&mapped).is_some());
    }

    #[test]
    fn every_other_kind_maps_to_request_failed_keeping_the_kind() {
        assert_kinds_map_to_request_failed(
            [
                ViturRequestErrorKind::PrepareRequest,
                ViturRequestErrorKind::SendRequest,
                ViturRequestErrorKind::Conflict,
                ViturRequestErrorKind::FailureResponse,
                ViturRequestErrorKind::ParseResponse,
                ViturRequestErrorKind::Other,
            ],
            load,
            |mapped, name| matches!(mapped, LoadKeysetError::RequestFailed(e) if format!("{:?}", e.kind) == name),
        );
    }

    #[test]
    fn display_never_leaks_the_dynamic_source() {
        for kind in [
            ViturRequestErrorKind::Forbidden,
            ViturRequestErrorKind::Unauthorized,
            ViturRequestErrorKind::NotFound,
            ViturRequestErrorKind::SendRequest,
        ] {
            let mapped = load(err(kind));
            let shown = mapped.to_string();
            assert!(
                !shown.contains(SOURCE_DETAIL),
                "the dynamic source error must stay out of Display: {shown}"
            );
        }
    }

    #[test]
    fn request_failed_display_names_the_kind_and_message() {
        assert_request_failed_display(&load(err(ViturRequestErrorKind::SendRequest)));
    }
}

/// Top-level error for high-level [`StackKms`](crate::StackKms) key operations.
#[derive(Error, Debug, Diagnostic)]
pub enum Error {
    #[error(transparent)]
    #[diagnostic(transparent)]
    GenerateKey(#[from] GenerateKeyError),

    #[error(transparent)]
    #[diagnostic(transparent)]
    RetrieveKey(#[from] RetrieveKeyError),

    #[error(transparent)]
    #[diagnostic(transparent)]
    LoadKeyset(#[from] LoadKeysetError),

    #[error(transparent)]
    #[diagnostic(transparent)]
    Auth(#[from] stack_auth::AuthError),

    /// The [`ZeroKMSConnection`](crate::ZeroKMSConnection) failed to
    /// initialise. Boxed because the error type belongs to whichever
    /// connection the client was built over.
    #[error("Failed to initialize the ZeroKMS connection")]
    #[diagnostic(code(stack_kms::connection_init))]
    ConnectionInit(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    /// The ZeroKMS endpoint named by the token's `services` claim is unusable.
    #[error("Invalid ZeroKMS endpoint in the token's services claim: {0}")]
    #[diagnostic(
        code(stack_kms::invalid_endpoint),
        help("Configure the ZeroKMS endpoint explicitly (`CS_ZEROKMS_HOST`), or use a token whose services claim names a usable one.")
    )]
    InvalidEndpoint(
        #[from]
        #[diagnostic_source]
        crate::endpoint::InvalidEndpoint,
    ),

    #[error("Unexpected error: {0}")]
    #[diagnostic(code(stack_kms::unexpected))]
    Unexpected(String),
}

impl ErrorPayload for Error {
    fn payload(&self) -> serde_json::Map<String, serde_json::Value> {
        match self {
            Self::GenerateKey(error) => error.payload(),
            Self::RetrieveKey(error) => error.payload(),
            Self::LoadKeyset(error) => error.payload(),
            Self::Auth(error) => error.payload(),
            Self::ConnectionInit(_) | Self::InvalidEndpoint(_) | Self::Unexpected(_) => {
                serde_json::Map::new()
            }
        }
    }
}
