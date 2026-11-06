//! Keyset records for the key vendor backends: the native half of
//! `stash keyset create` and `stash keyset rewrap` (CIP-5312).
//!
//! A ZeroKMS user never needs these functions. They exist for a keyset held
//! by a key vendor backend (AWS KMS, Google Cloud KMS, Azure Key Vault,
//! HashiCorp Vault Transit, or the static key backend), which the Rust and Go
//! SDKs load from a keyset record.
//!
//! Each vendor client is the Rust one, configured from the environment the
//! way the SDKs configure it (`AwsKms::from_env` and its peers), so the
//! request signing code exists once, in Rust. No credential crosses this
//! boundary as an argument. The one secret that can come back is a static
//! key that this module generated, because the caller must store it.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use miette::Diagnostic;
use napi::Status;
use napi_derive::napi;
use stack_kms::{KeyMode, KeyVendor};
use stack_kms_vendor::{
    HttpVendorTransport, HttpVendorTransportOptions, KeyBytes, KeyVendorBackend, KeysetRecord,
    RecordError, StaticKeyVendor,
};
use vitaminc::protected::{Controlled, Protected};
use vitaminc::random::{Generatable, SafeRand};
use vitaminc_protected::OpaqueDebug;
use zeroize::Zeroizing;

use crate::FAILURE_SENTINEL;

/// The length of a static key, in bytes.
const STATIC_KEY_LEN: usize = 32;

// ---------------------------------------------------------------------------
// The napi surface
// ---------------------------------------------------------------------------

/// The options of [`keyset_create`].
#[napi(object)]
#[derive(Debug, Clone)]
pub struct KeysetCreateOptions {
    /// The key backend: `aws`, `gcp`, `azure`, `vault` or `static`.
    pub backend: String,
    /// The vendor key that wraps the keyset's key: an AWS KMS key ARN, a
    /// Cloud KMS crypto key name, an Azure Key Vault key identifier, a Vault
    /// Transit key name, or the reference of a static key.
    pub vendor_key: String,
    /// The key mode: `wrapped` or `derived`. The static key backend offers
    /// `derived` only.
    pub mode: String,
    /// An optional local name for the keyset.
    pub name: Option<String>,
    /// Static key backend only: the name of the environment variable that
    /// holds the static key (32 bytes, as base64, base64url or hex). When it
    /// is not given, a new static key is generated and returned.
    pub static_key_env: Option<String>,
}

/// The options of [`keyset_rewrap`].
#[napi(object)]
#[derive(Debug, Clone)]
pub struct KeysetRewrapOptions {
    /// The keyset record text (`stack-keyset:…`).
    pub record: String,
    /// The vendor key to wrap under. When it is not given, the record's own
    /// vendor key is used, which moves the record to that key's current
    /// version.
    pub vendor_key: Option<String>,
    /// Static key backend only: the environment variable that holds the
    /// static key the record names now.
    pub static_key_env: Option<String>,
    /// Static key backend only: the environment variable that holds the
    /// static key of `vendor_key`, when that is another reference. When it is
    /// not given, a new static key is generated and returned.
    pub new_static_key_env: Option<String>,
}

/// A keyset record that [`keyset_create`] or [`keyset_rewrap`] made.
#[derive(OpaqueDebug)]
#[napi(object)]
pub struct KeysetResult {
    /// The keyset record text (`stack-keyset:…`). It is not secret.
    pub record: String,
    /// The keyset id (a UUID).
    pub keyset_id: String,
    /// The keyset name, if it has one.
    pub name: Option<String>,
    /// The key backend, as the SDKs name it (`aws-kms`, `gcp-kms`,
    /// `azure-key-vault`, `vault-transit` or `static`).
    pub backend: String,
    /// The key mode: `wrapped` or `derived`.
    pub mode: String,
    /// The vendor key that wraps the keyset's key.
    pub vendor_key: String,
    /// Static key backend only: a static key this call generated, as padded
    /// standard base64. **This is a secret.** It is the only copy.
    pub generated_static_key: Option<String>,
}

/// Create a keyset in a key vendor backend and return its keyset record.
///
/// One vendor call. The vendor's credentials come from its environment
/// chain, as in the SDKs.
#[napi]
pub async fn keyset_create(options: KeysetCreateOptions) -> napi::Result<KeysetResult> {
    create(options).await.map_err(KeysetError::into_napi)
}

/// Wrap a keyset record's key under a vendor key again (after a rotation in
/// the vendor, or to move it to another vendor key of the same backend). The
/// keyset id, name and mode stay the same. Stored data is not re-keyed, so a
/// record in the wrapped key mode may move only to a new version of its own
/// vendor key; a move to another key fails with `REWRAP_REFUSED`, before any
/// vendor call.
///
/// Two vendor calls: an unwrap and a wrap.
#[napi]
pub async fn keyset_rewrap(options: KeysetRewrapOptions) -> napi::Result<KeysetResult> {
    rewrap(options).await.map_err(KeysetError::into_napi)
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A failure of a keyset operation. No message carries key material or a
/// credential: the vendor crates build their messages from fixed text, the
/// HTTP status and the vendor's error code (see CIP-5311 in the decision
/// log), and this module never puts a key in one.
#[derive(Debug)]
pub(crate) enum KeysetError {
    /// An option is missing or has a value this module does not accept.
    Options(String),
    /// A static key could not be read or generated.
    StaticKey(String),
    /// The vendor client could not be configured from the environment.
    VendorConfig { vendor: KeyVendor, message: String },
    /// The record could not be parsed, created or rewrapped.
    Record(RecordError),
}

impl KeysetError {
    /// The stable code the TypeScript side narrows on.
    fn code(&self) -> &'static str {
        match self {
            Self::Options(_) => "INVALID_OPTIONS",
            Self::StaticKey(_) => "STATIC_KEY",
            Self::VendorConfig { .. } => "VENDOR_CONFIG",
            Self::Record(RecordError::Kms(_)) => "VENDOR_ERROR",
            Self::Record(RecordError::RewrapToAnotherKey { .. }) => "REWRAP_REFUSED",
            Self::Record(_) => "INVALID_RECORD",
        }
    }

    /// The failure envelope: `{ type, message, help?, vendor?, kind?, diagnostic? }`.
    pub(crate) fn envelope(&self) -> serde_json::Value {
        let mut fields = serde_json::Map::new();
        let _ = fields.insert("type".into(), self.code().into());
        let _ = fields.insert("message".into(), self.message().into());
        match self {
            Self::VendorConfig { vendor, .. } => {
                let _ = fields.insert("vendor".into(), vendor.name().into());
            }
            Self::Record(error) => {
                if let Some(code) = error.code() {
                    let _ = fields.insert("diagnostic".into(), code.to_string().into());
                }
                if let Some(help) = error.help() {
                    let _ = fields.insert("help".into(), help.to_string().into());
                }
                if let RecordError::Kms(stack_kms::Error::Backend { vendor, kind, .. }) = error {
                    let _ = fields.insert("vendor".into(), (*vendor).into());
                    let _ = fields.insert("kind".into(), kind.as_str().into());
                }
            }
            Self::Options(_) | Self::StaticKey(_) => {}
        }
        serde_json::Value::Object(fields)
    }

    fn message(&self) -> String {
        match self {
            Self::Options(message) | Self::StaticKey(message) => message.clone(),
            Self::VendorConfig { vendor, message } => {
                format!("Could not configure the {vendor} client from the environment: {message}")
            }
            Self::Record(error) => error_chain(error),
        }
    }

    fn into_napi(self) -> napi::Error {
        napi::Error::new(
            Status::GenericFailure,
            format!("{FAILURE_SENTINEL}{}", self.envelope()),
        )
    }
}

impl From<RecordError> for KeysetError {
    fn from(error: RecordError) -> Self {
        Self::Record(error)
    }
}

/// An error and its sources, joined with `: `, without repeats (a
/// `#[error(transparent)]` wrapper prints its source's text).
fn error_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        let next = cause.to_string();
        if !text.ends_with(&next) {
            text.push_str(": ");
            text.push_str(&next);
        }
        source = cause.source();
    }
    text
}

fn vendor_config(vendor: KeyVendor, error: impl std::error::Error + 'static) -> KeysetError {
    KeysetError::VendorConfig {
        vendor,
        message: error_chain(&error),
    }
}

// ---------------------------------------------------------------------------
// Parsing the options
// ---------------------------------------------------------------------------

/// The `--backend` values, in the order the help text lists them.
pub(crate) const BACKENDS: [(&str, KeyVendor); 5] = [
    ("aws", KeyVendor::Aws),
    ("gcp", KeyVendor::Gcp),
    ("azure", KeyVendor::Azure),
    ("vault", KeyVendor::Vault),
    ("static", KeyVendor::Static),
];

fn parse_backend(text: &str) -> Result<KeyVendor, KeysetError> {
    BACKENDS
        .iter()
        .find(|(name, _)| *name == text)
        .map(|(_, vendor)| *vendor)
        .ok_or_else(|| {
            KeysetError::Options(format!(
                "Unknown key backend {text:?}. Use one of: aws, gcp, azure, vault, static."
            ))
        })
}

fn parse_mode(text: &str) -> Result<KeyMode, KeysetError> {
    KeyMode::ALL
        .into_iter()
        .find(|mode| mode.name() == text)
        .ok_or_else(|| {
            KeysetError::Options(format!(
                "Unknown key mode {text:?}. Use wrapped or derived."
            ))
        })
}

fn non_empty(field: &str, value: Option<String>) -> Result<Option<String>, KeysetError> {
    match value {
        Some(value) if value.is_empty() => Err(KeysetError::Options(format!(
            "The {field} must not be empty."
        ))),
        other => Ok(other),
    }
}

/// Refuse a static key option on a vendor that has no static key.
fn refuse_static_options(
    vendor: KeyVendor,
    options: &[&Option<String>],
) -> Result<(), KeysetError> {
    if vendor != KeyVendor::Static && options.iter().any(|option| option.is_some()) {
        return Err(KeysetError::Options(format!(
            "A static key option is only for the static key backend, not {vendor}."
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Static keys
// ---------------------------------------------------------------------------

/// Read a static key from the environment variable `var`. The variable holds
/// 32 bytes as base64 (standard or URL-safe, padded or not) or as 64
/// hexadecimal characters.
pub(crate) fn read_static_key(var: &str) -> Result<KeyBytes, KeysetError> {
    let text = Zeroizing::new(std::env::var(var).map_err(|_| {
        KeysetError::StaticKey(format!(
            "The environment variable {var} is not set (it must hold the static key)."
        ))
    })?);
    decode_static_key(text.trim()).ok_or_else(|| {
        KeysetError::StaticKey(format!(
            "The environment variable {var} does not hold a static key: \
             use 32 bytes as base64 or as 64 hexadecimal characters."
        ))
    })
}

/// Decode a static key, or `None` when `text` is not 32 bytes in one of the
/// accepted encodings. Never returns the text in an error.
pub(crate) fn decode_static_key(text: &str) -> Option<KeyBytes> {
    let bytes: Zeroizing<Vec<u8>> =
        if text.len() == 2 * STATIC_KEY_LEN && text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            Zeroizing::new(
                (0..STATIC_KEY_LEN)
                    .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16))
                    .collect::<std::result::Result<Vec<u8>, _>>()
                    .ok()?,
            )
        } else {
            Zeroizing::new(
                [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
                    .iter()
                    .find_map(|engine| engine.decode(text).ok())?,
            )
        };
    let array: [u8; STATIC_KEY_LEN] = bytes.as_slice().try_into().ok()?;
    Some(Protected::new(array))
}

/// A new static key from the CSPRNG, and its padded standard base64.
fn generate_static_key() -> Result<(KeyBytes, String), KeysetError> {
    let failed = |_| KeysetError::StaticKey("Could not generate a static key.".into());
    let mut rng = SafeRand::from_entropy().map_err(failed)?;
    let key = KeyBytes::random(&mut rng).map_err(failed)?;
    let text = STANDARD.encode(key.risky_ref());
    Ok((key, text))
}

// ---------------------------------------------------------------------------
// The operations
// ---------------------------------------------------------------------------

/// What to do with the backend, once it is built.
enum Operation {
    Create {
        vendor_key: String,
        mode: KeyMode,
        name: Option<String>,
    },
    Rewrap {
        record: KeysetRecord,
        vendor_key: String,
    },
}

impl Operation {
    async fn run<B: KeyVendorBackend>(self, backend: &B) -> Result<KeysetRecord, KeysetError> {
        Ok(match self {
            Self::Create {
                vendor_key,
                mode,
                name,
            } => KeysetRecord::create(backend, vendor_key, mode, name).await?,
            Self::Rewrap { record, vendor_key } => record.rewrap(backend, vendor_key).await?,
        })
    }
}

pub(crate) async fn create(options: KeysetCreateOptions) -> Result<KeysetResult, KeysetError> {
    let vendor = parse_backend(&options.backend)?;
    let mode = parse_mode(&options.mode)?;
    let name = non_empty("keyset name", options.name)?;
    let static_key_env = non_empty("static key variable", options.static_key_env)?;
    refuse_static_options(vendor, &[&static_key_env])?;
    if options.vendor_key.is_empty() {
        return Err(KeysetError::Options(
            "The vendor key must not be empty.".into(),
        ));
    }
    // Refused here too, so that a static key is not generated for nothing.
    if vendor == KeyVendor::Static && mode != KeyMode::Derived {
        return Err(RecordError::ModeUnsupported { vendor, mode }.into());
    }
    let operation = Operation::Create {
        vendor_key: options.vendor_key,
        mode,
        name,
    };
    let (record, generated) = if vendor == KeyVendor::Static {
        let key_ref = options_vendor_key_of(&operation);
        let (key, generated) = match &static_key_env {
            Some(var) => (read_static_key(var)?, None),
            None => {
                let (key, text) = generate_static_key()?;
                (key, Some(text))
            }
        };
        let backend = StaticKeyVendor::new(key_ref, key);
        (operation.run(&backend).await?, generated)
    } else {
        (run_vendor(vendor, operation).await?, None)
    };
    Ok(result(&record, generated))
}

pub(crate) async fn rewrap(options: KeysetRewrapOptions) -> Result<KeysetResult, KeysetError> {
    let record = KeysetRecord::parse(options.record.trim())?;
    let vendor = record.vendor();
    let vendor_key =
        non_empty("vendor key", options.vendor_key)?.unwrap_or_else(|| record.key_ref().to_owned());
    let static_key_env = non_empty("static key variable", options.static_key_env)?;
    let new_static_key_env = non_empty("new static key variable", options.new_static_key_env)?;
    refuse_static_options(vendor, &[&static_key_env, &new_static_key_env])?;

    if vendor != KeyVendor::Static {
        let record = run_vendor(vendor, Operation::Rewrap { record, vendor_key }).await?;
        return Ok(result(&record, None));
    }

    let var = static_key_env.ok_or_else(|| {
        KeysetError::Options(
            "The record is in the static key backend: name the variable that holds its \
             static key with --key-env."
                .into(),
        )
    })?;
    let current = read_static_key(&var)?;
    let mut backend = StaticKeyVendor::new(record.key_ref(), current);
    let mut generated = None;
    if vendor_key != record.key_ref() {
        let key = match &new_static_key_env {
            Some(var) => read_static_key(var)?,
            None => {
                let (key, text) = generate_static_key()?;
                generated = Some(text);
                key
            }
        };
        backend = backend.with_key(vendor_key.clone(), key);
    } else if new_static_key_env.is_some() {
        return Err(KeysetError::Options(
            "--new-key-env needs --vendor-key with another static key reference.".into(),
        ));
    }
    let record = Operation::Rewrap { record, vendor_key }
        .run(&backend)
        .await?;
    Ok(result(&record, generated))
}

fn options_vendor_key_of(operation: &Operation) -> String {
    match operation {
        Operation::Create { vendor_key, .. } | Operation::Rewrap { vendor_key, .. } => {
            vendor_key.clone()
        }
    }
}

fn result(record: &KeysetRecord, generated_static_key: Option<String>) -> KeysetResult {
    KeysetResult {
        record: record.to_string(),
        keyset_id: record.id().to_string(),
        name: record.name().map(str::to_owned),
        backend: record.vendor().name().to_owned(),
        mode: record.mode().name().to_owned(),
        vendor_key: record.key_ref().to_owned(),
        generated_static_key,
    }
}

/// Build the vendor's client from the environment and run `operation` on it.
async fn run_vendor(vendor: KeyVendor, operation: Operation) -> Result<KeysetRecord, KeysetError> {
    match vendor {
        KeyVendor::Aws => {
            let kms = stack_kms_aws::DefaultAwsKms::from_env()
                .map_err(|error| vendor_config(vendor, error))?;
            operation.run(&kms).await
        }
        KeyVendor::Vault => {
            let vault = stack_kms_vault::DefaultVaultTransit::from_env()
                .map_err(|error| vendor_config(vendor, error))?;
            operation.run(&vault).await
        }
        KeyVendor::Azure => {
            let azure = stack_kms_azure::DefaultAzureKeyVault::from_env()
                .map_err(|error| vendor_config(vendor, error))?;
            operation.run(&azure).await
        }
        KeyVendor::Gcp => run_gcp(operation).await,
        // The callers handle the static key backend before this point, and
        // `KeyVendor` is non-exhaustive.
        _ => Err(KeysetError::Options(format!(
            "stash keyset cannot reach the {vendor} key backend."
        ))),
    }
}

/// Google Cloud KMS, with the credentials this binding supports.
///
/// The binding builds `stack-kms-gcp` without its `service-account` feature,
/// so it has no RSA code (RUSTSEC-2023-0071). It therefore takes a token from
/// `GOOGLE_OAUTH_ACCESS_TOKEN` (for example from `gcloud auth
/// print-access-token`), else the metadata server on Google Cloud. A service
/// account key file (`GOOGLE_APPLICATION_CREDENTIALS`) is refused with that
/// remedy, so it is never ignored.
async fn run_gcp(operation: Operation) -> Result<KeysetRecord, KeysetError> {
    use stack_kms_gcp::{
        AccessToken, CachedToken, GcpKms, GcpKmsConfig, MetadataServerLogin, ACCESS_TOKEN_VARIABLE,
    };

    let vendor = KeyVendor::Gcp;
    let env = stack_kms_gcp::process_env();
    let transport = HttpVendorTransport::new().map_err(|error| vendor_config(vendor, error))?;
    if let Some(token) = env(ACCESS_TOKEN_VARIABLE).map(AccessToken::new) {
        let kms = GcpKms::new(GcpKmsConfig::new(), transport, token);
        return operation.run(&kms).await;
    }
    if env("GOOGLE_APPLICATION_CREDENTIALS").is_some() {
        return Err(KeysetError::VendorConfig {
            vendor,
            message: "stash keyset does not read service account key files \
                      (GOOGLE_APPLICATION_CREDENTIALS). Set GOOGLE_OAUTH_ACCESS_TOKEN, \
                      for example to the output of `gcloud auth print-access-token`, \
                      or run on Google Cloud with an attached service account."
                .into(),
        });
    }
    // A 1 second connect limit, as in `GcpKms::from_env`, so that off Google
    // Cloud the metadata server probe fails fast.
    let credentials_transport = HttpVendorTransport::with_options(HttpVendorTransportOptions {
        timeout: std::time::Duration::from_secs(10),
        connect_timeout: Some(std::time::Duration::from_secs(1)),
    })
    .map_err(|error| vendor_config(vendor, error))?;
    let login = MetadataServerLogin::from_env_lookup(credentials_transport, &env)
        .map_err(|error| vendor_config(vendor, error))?;
    let kms = GcpKms::new(GcpKmsConfig::new(), transport, CachedToken::new(login));
    operation.run(&kms).await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const KEY_A: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    const KEY_A_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const KEY_B: &str = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=";

    fn create_options(backend: &str, mode: &str) -> KeysetCreateOptions {
        KeysetCreateOptions {
            backend: backend.into(),
            vendor_key: "key-a".into(),
            mode: mode.into(),
            name: Some("users".into()),
            static_key_env: None,
        }
    }

    /// Each test uses its own variable names, because tests run in parallel
    /// threads of one process.
    fn set(var: &str, value: &str) {
        std::env::set_var(var, value);
    }

    fn envelope(error: KeysetError) -> serde_json::Value {
        error.envelope()
    }

    #[test]
    fn decodes_every_accepted_static_key_encoding() {
        let expected: Vec<u8> = (0u8..32).collect();
        for text in [
            KEY_A,
            KEY_A.trim_end_matches('='),
            KEY_A_HEX,
            &KEY_A_HEX.to_uppercase(),
            // base64url of the same bytes (no `+` or `/` in it, so it is
            // also the standard form; check a key with them below).
        ] {
            let key = decode_static_key(text).unwrap();
            assert_eq!(key.risky_ref().as_slice(), expected.as_slice(), "{text}");
        }
        let all_ones = [0xfbu8; 32];
        let standard = STANDARD.encode(all_ones);
        let url = URL_SAFE_NO_PAD.encode(all_ones);
        assert!(standard.contains('+') || standard.contains('/'));
        for text in [standard.as_str(), url.as_str()] {
            assert_eq!(decode_static_key(text).unwrap().risky_ref(), &all_ones);
        }
    }

    #[test]
    fn refuses_a_static_key_that_is_not_32_bytes() {
        for text in [
            "",
            "abcd",
            &STANDARD.encode([0u8; 31]),
            &STANDARD.encode([0u8; 33]),
            &"0".repeat(63),
            "not base64 at all!",
        ] {
            assert!(decode_static_key(text).is_none(), "{text:?}");
        }
    }

    #[test]
    fn a_static_key_error_does_not_name_the_value() {
        set("CIP5312_TEST_BAD_KEY", "secret-looking-value");
        let error = read_static_key("CIP5312_TEST_BAD_KEY").err().unwrap();
        let text = envelope(error).to_string();
        assert!(text.contains("CIP5312_TEST_BAD_KEY"));
        assert!(!text.contains("secret-looking-value"));
        assert!(text.contains("\"type\":\"STATIC_KEY\""));
    }

    #[test]
    fn a_missing_static_key_variable_is_refused() {
        let error = read_static_key("CIP5312_TEST_UNSET_KEY").err().unwrap();
        assert!(envelope(error).to_string().contains("is not set"));
    }

    #[tokio::test]
    async fn creates_a_static_record_with_a_generated_key() {
        let created = create(create_options("static", "derived")).await.unwrap();
        assert!(created.record.starts_with("stack-keyset:"));
        assert_eq!(created.backend, "static");
        assert_eq!(created.mode, "derived");
        assert_eq!(created.name.as_deref(), Some("users"));
        assert_eq!(created.vendor_key, "key-a");
        let record = KeysetRecord::parse(&created.record).unwrap();
        assert_eq!(record.id().to_string(), created.keyset_id);

        // The generated key opens the record: rewrap under it.
        let key = created.generated_static_key.unwrap();
        assert!(decode_static_key(&key).is_some());
        set("CIP5312_TEST_GENERATED", &key);
        let rewrapped = rewrap(KeysetRewrapOptions {
            record: created.record.clone(),
            vendor_key: None,
            static_key_env: Some("CIP5312_TEST_GENERATED".into()),
            new_static_key_env: None,
        })
        .await
        .unwrap();
        assert_eq!(rewrapped.keyset_id, created.keyset_id);
        assert!(rewrapped.generated_static_key.is_none());
        // A new nonce, so the record text changes.
        assert_ne!(rewrapped.record, created.record);
    }

    #[tokio::test]
    async fn creates_a_static_record_with_a_key_from_the_environment() {
        set("CIP5312_TEST_KEY_ENV", KEY_A);
        let created = create(KeysetCreateOptions {
            static_key_env: Some("CIP5312_TEST_KEY_ENV".into()),
            ..create_options("static", "derived")
        })
        .await
        .unwrap();
        assert!(created.generated_static_key.is_none());

        // The record opens with that key and not with another one.
        let record = KeysetRecord::parse(&created.record).unwrap();
        let right = StaticKeyVendor::new("key-a", decode_static_key(KEY_A).unwrap());
        let wrong = StaticKeyVendor::new("key-a", decode_static_key(KEY_B).unwrap());
        assert!(record.rewrap(&right, "key-a").await.is_ok());
        assert!(record.rewrap(&wrong, "key-a").await.is_err());
    }

    #[tokio::test]
    async fn rewraps_a_static_record_to_another_key() {
        set("CIP5312_TEST_OLD", KEY_A);
        set("CIP5312_TEST_NEW", KEY_B);
        let created = create(KeysetCreateOptions {
            static_key_env: Some("CIP5312_TEST_OLD".into()),
            ..create_options("static", "derived")
        })
        .await
        .unwrap();
        let rewrapped = rewrap(KeysetRewrapOptions {
            record: format!("  {}\n", created.record),
            vendor_key: Some("key-b".into()),
            static_key_env: Some("CIP5312_TEST_OLD".into()),
            new_static_key_env: Some("CIP5312_TEST_NEW".into()),
        })
        .await
        .unwrap();
        assert_eq!(rewrapped.keyset_id, created.keyset_id);
        assert_eq!(rewrapped.name, created.name);
        assert_eq!(rewrapped.mode, "derived");
        assert_eq!(rewrapped.vendor_key, "key-b");

        // Only the new key opens it now.
        let record = KeysetRecord::parse(&rewrapped.record).unwrap();
        let new = StaticKeyVendor::new("key-b", decode_static_key(KEY_B).unwrap());
        let old = StaticKeyVendor::new("key-b", decode_static_key(KEY_A).unwrap());
        assert!(record.rewrap(&new, "key-b").await.is_ok());
        assert!(record.rewrap(&old, "key-b").await.is_err());
    }

    #[tokio::test]
    async fn rewrap_with_a_wrong_static_key_is_a_vendor_error() {
        set("CIP5312_TEST_RIGHT", KEY_A);
        set("CIP5312_TEST_WRONG", KEY_B);
        let created = create(KeysetCreateOptions {
            static_key_env: Some("CIP5312_TEST_RIGHT".into()),
            ..create_options("static", "derived")
        })
        .await
        .unwrap();
        let error = rewrap(KeysetRewrapOptions {
            record: created.record,
            vendor_key: None,
            static_key_env: Some("CIP5312_TEST_WRONG".into()),
            new_static_key_env: None,
        })
        .await
        .err()
        .unwrap();
        let envelope = envelope(error);
        assert_eq!(envelope["type"], "VENDOR_ERROR");
        assert_eq!(envelope["vendor"], "static");
        assert_eq!(envelope["kind"], "InvalidCiphertext");
    }

    #[tokio::test]
    async fn refuses_wrapped_data_keys_on_the_static_backend() {
        let error = create(create_options("static", "wrapped"))
            .await
            .err()
            .unwrap();
        let envelope = envelope(error);
        assert_eq!(envelope["type"], "INVALID_RECORD");
        assert_eq!(envelope["diagnostic"], "stack_kms_vendor::mode_unsupported");
        assert!(envelope["help"].as_str().unwrap().contains("derived"));
    }

    #[tokio::test]
    async fn refuses_bad_options() {
        let cases = [
            create_options("zerokms", "derived"),
            create_options("aws", "both"),
            KeysetCreateOptions {
                vendor_key: String::new(),
                ..create_options("aws", "wrapped")
            },
            KeysetCreateOptions {
                name: Some(String::new()),
                ..create_options("aws", "wrapped")
            },
            KeysetCreateOptions {
                static_key_env: Some("CIP5312_TEST_ANY".into()),
                ..create_options("aws", "wrapped")
            },
        ];
        for options in cases {
            let error = create(options.clone()).await.err().unwrap();
            assert_eq!(envelope(error)["type"], "INVALID_OPTIONS", "{options:?}");
        }
    }

    #[tokio::test]
    async fn rewrap_refuses_a_bad_record_and_missing_static_options() {
        let error = rewrap(KeysetRewrapOptions {
            record: "not-a-record".into(),
            vendor_key: None,
            static_key_env: None,
            new_static_key_env: None,
        })
        .await
        .err()
        .unwrap();
        let envelope_value = envelope(error);
        assert_eq!(envelope_value["type"], "INVALID_RECORD");
        assert_eq!(
            envelope_value["diagnostic"],
            "stack_kms_vendor::record_prefix"
        );

        let created = create(create_options("static", "derived")).await.unwrap();
        let error = rewrap(KeysetRewrapOptions {
            record: created.record.clone(),
            vendor_key: None,
            static_key_env: None,
            new_static_key_env: None,
        })
        .await
        .err()
        .unwrap();
        assert!(envelope(error)["message"]
            .as_str()
            .unwrap()
            .contains("--key-env"));

        set(
            "CIP5312_TEST_SAME",
            created.generated_static_key.as_deref().unwrap(),
        );
        let error = rewrap(KeysetRewrapOptions {
            record: created.record,
            vendor_key: None,
            static_key_env: Some("CIP5312_TEST_SAME".into()),
            new_static_key_env: Some("CIP5312_TEST_SAME".into()),
        })
        .await
        .err()
        .unwrap();
        assert_eq!(envelope(error)["type"], "INVALID_OPTIONS");
    }

    /// The hand-written `KeysetFailure` union in `index.d.ts` lists every
    /// code `KeysetError` emits.
    #[test]
    fn index_dts_lists_every_keyset_failure_code() {
        let dts = include_str!("../index.d.ts");
        let errors = [
            KeysetError::Options(String::new()),
            KeysetError::StaticKey(String::new()),
            KeysetError::VendorConfig {
                vendor: KeyVendor::Aws,
                message: String::new(),
            },
            KeysetError::Record(RecordError::NotARecord),
            KeysetError::Record(RecordError::RewrapToAnotherKey {
                keyset: Default::default(),
                from: "a".into(),
                to: "b".into(),
            }),
            KeysetError::Record(RecordError::Kms(stack_kms::Error::Backend {
                vendor: "static",
                kind: stack_kms::BackendErrorKind::NotFound,
                source: "none".into(),
            })),
        ];
        for error in errors {
            let code = error.code();
            assert!(
                dts.contains(&format!("\"{code}\"")),
                "index.d.ts KeysetFailure lacks {code}"
            );
        }
        assert!(dts.contains("export type KeysetFailure"));
    }

    #[test]
    fn a_rewrap_to_another_key_has_its_own_code() {
        let error = KeysetError::Record(RecordError::RewrapToAnotherKey {
            keyset: Default::default(),
            from: "arn:aws:kms:us-east-1:111122223333:key/a".into(),
            to: "arn:aws:kms:us-east-1:111122223333:key/b".into(),
        });
        let value = error.envelope();
        assert_eq!(value["type"], "REWRAP_REFUSED");
        assert_eq!(value["diagnostic"], "stack_kms_vendor::rewrap_another_key");
        assert!(value["help"]
            .as_str()
            .is_some_and(|help| help.contains("new version of the same key")));
    }

    #[test]
    fn the_backend_names_are_the_cli_names() {
        let names: Vec<_> = BACKENDS.iter().map(|(name, _)| *name).collect();
        assert_eq!(names, ["aws", "gcp", "azure", "vault", "static"]);
        for (name, vendor) in BACKENDS {
            assert_eq!(parse_backend(name).unwrap(), vendor);
        }
    }

    #[test]
    fn a_vendor_config_error_names_the_vendor() {
        let envelope = envelope(KeysetError::VendorConfig {
            vendor: KeyVendor::Aws,
            message: "no region".into(),
        });
        assert_eq!(envelope["type"], "VENDOR_CONFIG");
        assert_eq!(envelope["vendor"], "aws-kms");
        assert!(envelope["message"].as_str().unwrap().contains("no region"));
    }

    #[test]
    fn the_result_debug_hides_the_generated_key() {
        let result = KeysetResult {
            record: "stack-keyset:x".into(),
            keyset_id: "id".into(),
            name: None,
            backend: "static".into(),
            mode: "derived".into(),
            vendor_key: "key-a".into(),
            generated_static_key: Some("the-secret-key".into()),
        };
        assert!(!format!("{result:?}").contains("the-secret-key"));
    }
}
