//! The key vendor backend of this guest (ADR-0009, ADR-0011, CIP-5311).
//!
//! A client holds ZeroKMS and at most one key vendor backend. The host
//! names the backend and gives its keyset records in the `se_cipher_init`
//! config ([`crate::config`]); this module builds it:
//!
//! * [`GuestVendor`] is one enum over the four vendor clients and the static
//!   key backend, so the cipher has one key source type whatever the host
//!   chose: `KeyRouter<ZeroKMS, GuestVendor>`. With no backend configured it
//!   is [`GuestVendor::None`] with no keyset records, and the router sends
//!   every request to ZeroKMS, as before.
//! * The vendor clients send through the host's HTTP client
//!   (`HostVendorTransport`, the `transport_send` import) and sign each
//!   request here, in the guest.
//! * The credentials they sign with come from the host through the
//!   `vendor_credential_get` import ([`CredentialImport`]): short-lived
//!   credentials only, never a long-lived signing key. AWS temporary
//!   credentials, a Google OAuth access token, an Azure access token for the
//!   requested scope, a Vault client token. The guest asks before each
//!   request and keeps nothing between requests, so the host's own
//!   credential chain decides when to refresh.
//!
//! What this module owns is pure logic over those seams, and it is tested
//! natively with a fake transport and a fake import. The wasm32 import itself
//! is [`crate::host`]'s.
//!
//! # The credential the host returns
//!
//! One value in the transport codec, an object of string values plus an
//! optional `expires_at` (`i64`, Unix seconds):
//!
//! | vendor          | keys |
//! |-----------------|------|
//! | `aws-kms`       | `access_key_id`, `secret_access_key`, optional `session_token` |
//! | `vault-transit` | `token` |
//! | `gcp-kms`       | `token` |
//! | `azure-key-vault` | `token` (for the requested scope) |
//!
//! A credential whose `expires_at` has passed is refused before the
//! request is signed. Every secret is held in `Zeroizing` or the vendor
//! crate's own wiped type, and none is ever put in an error message.

use std::num::NonZeroUsize;
use std::time::{Duration, SystemTime};

use stack_kms::{BackendErrorKind, Error, KeyMode, KeyVendor};
use stack_kms_vendor::{
    KeyBytes, KeyVendorBackend, KeysetRecord, RecordError, StaticKeyVendor, UnwrapItem,
    VendorKeySource, VendorTransport, WrapItem,
};
use vitaminc_aead_value::FfiValue;
use zeroize::Zeroizing;

/// What the host configured: one key vendor backend and its settings.
pub enum VendorSettings {
    /// AWS KMS in `region`; `endpoint` overrides the regional endpoint
    /// (LocalStack, a VPC endpoint).
    Aws {
        region: String,
        endpoint: Option<String>,
    },
    /// HashiCorp Vault Transit at `address`.
    Vault {
        address: String,
        namespace: Option<String>,
        mount: Option<String>,
    },
    /// Google Cloud KMS; `endpoint` overrides the global endpoint.
    Gcp { endpoint: Option<String> },
    /// Azure Key Vault or Managed HSM: the key identifier in each keyset
    /// record names the vault, so there is nothing to configure.
    Azure,
    /// The static key backend: one key, held in guest memory for the life
    /// of the client. Derived data keys only.
    Static { key_ref: String, key: KeyBytes },
}

impl VendorSettings {
    /// The backend these settings build.
    pub fn vendor(&self) -> KeyVendor {
        match self {
            Self::Aws { .. } => KeyVendor::Aws,
            Self::Vault { .. } => KeyVendor::Vault,
            Self::Gcp { .. } => KeyVendor::Gcp,
            Self::Azure => KeyVendor::Azure,
            Self::Static { .. } => KeyVendor::Static,
        }
    }
}

impl std::fmt::Debug for VendorSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The static key never prints.
        f.debug_tuple("VendorSettings")
            .field(&self.vendor().name())
            .finish()
    }
}

/// The key vendor backend part of the config: the backend, the keyset
/// record texts, and the adapter's settings.
#[derive(Debug)]
pub struct VendorConfig {
    pub settings: VendorSettings,
    pub records: Vec<String>,
    /// The default keyset of a client with no ZeroKMS. `None` is the only
    /// record, when there is one.
    pub default_keyset: Option<DefaultKeyset>,
    /// How long a root key stays unwrapped. `None` is the adapter's default
    /// (`DEFAULT_ROOT_KEY_TTL`).
    pub root_key_ttl: Option<Duration>,
}

/// A keyset named by one of the keyset records, by its id or its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefaultKeyset {
    Id(uuid::Uuid),
    Name(String),
}

/// The host could not supply a credential, or supplied one the guest
/// refuses. The message never holds a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialError {
    pub kind: BackendErrorKind,
    pub message: String,
}

impl CredentialError {
    fn denied(message: impl Into<String>) -> Self {
        Self {
            kind: BackendErrorKind::AccessDenied,
            message: message.into(),
        }
    }
}

/// The `vendor_credential_get` host import, as a seam: one short-lived
/// credential for `vendor` and `scope`, as a decoded codec value. `scope` is
/// the OAuth scope for Google Cloud and Azure, and empty for AWS and Vault.
///
/// The guest asks before each vendor request and keeps nothing, so a host
/// source that refreshes needs no notice from the guest.
pub trait CredentialImport: Send + Sync {
    /// The current credential, or why the host has none.
    fn credential(&self, vendor: KeyVendor, scope: &str) -> Result<FfiValue, CredentialError>;
}

/// A credential's fields, read out of the host's value.
struct CredentialFields {
    strings: Vec<(String, Zeroizing<String>)>,
    /// What is left of its life. `None` when the host gave no expiry.
    remaining: Option<Duration>,
}

impl CredentialFields {
    /// Read `value`, the host's credential for `vendor`, at `now`.
    fn read(vendor: KeyVendor, value: FfiValue, now: SystemTime) -> Result<Self, CredentialError> {
        let not_valid = || {
            CredentialError::denied(format!(
                "the host's {} credential is not an object of string values",
                vendor.name()
            ))
        };
        let FfiValue::Object(entries) = value else {
            return Err(not_valid());
        };
        let mut strings = Vec::with_capacity(entries.len());
        let mut remaining = None;
        for (key, value) in entries {
            match (key.as_str(), value) {
                ("expires_at", FfiValue::Int64(seconds)) => {
                    let expires = u64::try_from(seconds)
                        .ok()
                        .and_then(|s| SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(s)))
                        .ok_or_else(not_valid)?;
                    let left = expires.duration_since(now).ok().filter(|d| !d.is_zero());
                    remaining = Some(left.ok_or_else(|| {
                        CredentialError::denied(format!(
                            "the host's {} credential has expired",
                            vendor.name()
                        ))
                    })?);
                }
                (_, FfiValue::String(text)) => {
                    let text = std::str::from_utf8(text.risky_ref()).map_err(|_| not_valid())?;
                    // A value read from a file keeps its newline; no secret
                    // here has meaningful surrounding whitespace. An interior
                    // control character is refused: it would split a header.
                    let text = Zeroizing::new(text.trim().to_owned());
                    if text.chars().any(char::is_control) {
                        return Err(CredentialError::denied(format!(
                            "the host's {} credential has a control character in `{key}`",
                            vendor.name()
                        )));
                    }
                    strings.push((key, text));
                }
                _ => return Err(not_valid()),
            }
        }
        Ok(Self { strings, remaining })
    }

    /// Take the non-empty string `key`, or `None`.
    fn take(&mut self, key: &str) -> Option<Zeroizing<String>> {
        let at = self.strings.iter().position(|(k, _)| k == key)?;
        let (_, value) = self.strings.swap_remove(at);
        (!value.is_empty()).then_some(value)
    }

    /// Take the required string `key`.
    fn require(
        &mut self,
        vendor: KeyVendor,
        key: &str,
    ) -> Result<Zeroizing<String>, CredentialError> {
        self.take(key).ok_or_else(|| {
            CredentialError::denied(format!(
                "the host's {} credential has no `{key}`",
                vendor.name()
            ))
        })
    }

    /// Refuse a key this vendor's credential does not have: a host that
    /// sends `token` for AWS has the vendor wrong, and must be told.
    fn finish(self, vendor: KeyVendor) -> Result<Option<Duration>, CredentialError> {
        match self.strings.first() {
            Some((key, _)) => Err(CredentialError::denied(format!(
                "the host's {} credential has a key it does not use: `{key}`",
                vendor.name()
            ))),
            None => Ok(self.remaining),
        }
    }
}

/// Read a token credential (Vault, Google Cloud, Azure): the token and what
/// is left of its life.
fn read_token(
    vendor: KeyVendor,
    value: FfiValue,
    now: SystemTime,
) -> Result<(Zeroizing<String>, Option<Duration>), CredentialError> {
    let mut fields = CredentialFields::read(vendor, value, now)?;
    let token = fields.require(vendor, "token")?;
    let remaining = fields.finish(vendor)?;
    Ok((token, remaining))
}

/// The clock the credential expiry is checked against. A seam for tests.
pub type Now = fn() -> SystemTime;

/// The credential and token providers of the vendor clients, over the host
/// import. One type serves AWS (`CredentialsProvider`) and the three token
/// providers.
pub struct HostCredentials<C> {
    import: C,
    now: Now,
}

impl<C> HostCredentials<C> {
    /// Providers over `import`, checking expiry against the system clock.
    pub fn new(import: C) -> Self {
        Self {
            import,
            now: SystemTime::now,
        }
    }

    /// The same, with `now` as the clock.
    pub fn with_now(mut self, now: Now) -> Self {
        self.now = now;
        self
    }
}

impl<C: CredentialImport> HostCredentials<C> {
    fn fetch(&self, vendor: KeyVendor, scope: &str) -> Result<FfiValue, CredentialError> {
        self.import.credential(vendor, scope)
    }

    fn aws(&self) -> Result<stack_kms_aws::Credentials, CredentialError> {
        let vendor = KeyVendor::Aws;
        let mut fields = CredentialFields::read(vendor, self.fetch(vendor, "")?, (self.now)())?;
        let id = fields.require(vendor, "access_key_id")?;
        let secret = fields.require(vendor, "secret_access_key")?;
        let session = fields.take("session_token");
        let remaining = fields.finish(vendor)?;
        // The vendor type takes `String`s and wipes its own copies of the
        // secret and the session token; ours wipe on drop here.
        let credentials = stack_kms_aws::Credentials::new(
            id.as_str(),
            secret.as_str(),
            session.as_ref().map(|token| token.as_str().to_owned()),
        );
        Ok(match remaining {
            Some(left) => credentials.with_expiry((self.now)() + left),
            None => credentials,
        })
    }

    fn token(
        &self,
        vendor: KeyVendor,
        scope: &str,
    ) -> Result<(Zeroizing<String>, Option<Duration>), CredentialError> {
        read_token(vendor, self.fetch(vendor, scope)?, (self.now)())
    }
}

impl<C: CredentialImport> stack_kms_aws::CredentialsProvider for HostCredentials<C> {
    async fn credentials(
        &self,
    ) -> Result<stack_kms_aws::Credentials, stack_kms_aws::CredentialsError> {
        self.aws()
            .map_err(|e| stack_kms_aws::CredentialsError::new(e.kind, e.message))
    }
}

impl<C: CredentialImport> stack_kms_vault::TokenProvider for HostCredentials<C> {
    async fn token(&self) -> Result<stack_kms_vault::VaultToken, stack_kms_vault::AuthError> {
        let (token, remaining) = self
            .token(KeyVendor::Vault, "")
            .map_err(|e| stack_kms_vault::AuthError::new(e.kind, e.message))?;
        let token = stack_kms_vault::VaultToken::new(token.as_str());
        Ok(match remaining {
            Some(left) => token.with_lease(left),
            None => token,
        })
    }
}

impl<C: CredentialImport> stack_kms_gcp::TokenProvider for HostCredentials<C> {
    async fn token(&self) -> Result<stack_kms_gcp::AccessToken, stack_kms_gcp::AuthError> {
        let (token, remaining) = self
            .token(KeyVendor::Gcp, stack_kms_gcp::CLOUD_KMS_SCOPE)
            .map_err(|e| stack_kms_gcp::AuthError::new(e.kind, e.message))?;
        let token = stack_kms_gcp::AccessToken::new(token.as_str());
        Ok(match remaining {
            Some(left) => token.with_expires_in(left),
            None => token,
        })
    }
}

impl<C: CredentialImport> stack_kms_azure::TokenProvider for HostCredentials<C> {
    async fn token(
        &self,
        scope: &str,
    ) -> Result<stack_kms_azure::AccessToken, stack_kms_azure::AuthError> {
        let (token, remaining) = self
            .token(KeyVendor::Azure, scope)
            .map_err(|e| stack_kms_azure::AuthError::new(e.kind, e.message))?;
        let token = stack_kms_azure::AccessToken::new(token.as_str());
        Ok(match remaining {
            Some(left) => token.with_expires_in(left),
            None => token,
        })
    }
}

/// The guest's one key vendor backend: whichever the host configured.
///
/// One enum, not a type parameter, so that the instance's cipher has one
/// type whatever the host chose at run time.
pub enum GuestVendor<T, C> {
    /// No key vendor backend. It holds no keyset records, so the router
    /// never calls it, and every method refuses.
    None,
    Aws(stack_kms_aws::AwsKms<T, HostCredentials<C>>),
    Vault(stack_kms_vault::VaultTransit<T, HostCredentials<C>>),
    Gcp(stack_kms_gcp::GcpKms<T, HostCredentials<C>>),
    Azure(stack_kms_azure::AzureKeyVault<T, HostCredentials<C>>),
    Static(StaticKeyVendor),
}

impl<T, C> std::fmt::Debug for GuestVendor<T, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::None => "none",
            Self::Aws(_) => KeyVendor::Aws.name(),
            Self::Vault(_) => KeyVendor::Vault.name(),
            Self::Gcp(_) => KeyVendor::Gcp.name(),
            Self::Azure(_) => KeyVendor::Azure.name(),
            Self::Static(_) => KeyVendor::Static.name(),
        };
        f.debug_tuple("GuestVendor").field(&name).finish()
    }
}

/// Every method of [`GuestVendor::None`]: it holds no keyset, so a call is
/// a routing bug, refused rather than answered. It is not a backend
/// failure, because there is no backend to name.
fn no_vendor() -> Error {
    Error::Unexpected("no key vendor backend is configured".into())
}

/// Dispatch one `KeyVendorBackend` method to the configured client.
macro_rules! dispatch {
    ($self:expr, $backend:ident => $call:expr, none => $none:expr) => {
        match $self {
            GuestVendor::None => $none,
            GuestVendor::Aws($backend) => $call,
            GuestVendor::Vault($backend) => $call,
            GuestVendor::Gcp($backend) => $call,
            GuestVendor::Azure($backend) => $call,
            GuestVendor::Static($backend) => $call,
        }
    };
}

impl<T, C> KeyVendorBackend for GuestVendor<T, C>
where
    T: VendorTransport + Send + Sync,
    C: CredentialImport,
{
    /// The configured vendor. [`GuestVendor::None`] answers `Static`: it is
    /// never asked, because it holds no keyset (the router asks a backend
    /// only for a keyset one of its records names).
    fn vendor(&self) -> KeyVendor {
        dispatch!(self, b => b.vendor(), none => KeyVendor::Static)
    }

    fn supports_mode(&self, mode: KeyMode) -> bool {
        dispatch!(self, b => b.supports_mode(mode), none => false)
    }

    async fn wrap(&self, key_ref: &str, key: &KeyBytes, aad: &[u8]) -> Result<Vec<u8>, Error> {
        dispatch!(self, b => b.wrap(key_ref, key, aad).await, none => Err(no_vendor()))
    }

    async fn unwrap(&self, key_ref: &str, wrapped: &[u8], aad: &[u8]) -> Result<KeyBytes, Error> {
        dispatch!(self, b => b.unwrap(key_ref, wrapped, aad).await, none => Err(no_vendor()))
    }

    async fn generate_wrapped(
        &self,
        key_ref: &str,
        aad: &[u8],
    ) -> Result<(KeyBytes, Vec<u8>), Error> {
        dispatch!(self, b => b.generate_wrapped(key_ref, aad).await, none => Err(no_vendor()))
    }

    fn batch_limit(&self) -> Option<NonZeroUsize> {
        dispatch!(self, b => b.batch_limit(), none => None)
    }

    async fn wrap_batch(
        &self,
        key_ref: &str,
        items: &[WrapItem<'_>],
    ) -> Result<Vec<Vec<u8>>, Error> {
        dispatch!(self, b => b.wrap_batch(key_ref, items).await, none => Err(no_vendor()))
    }

    async fn unwrap_batch(
        &self,
        key_ref: &str,
        items: &[UnwrapItem<'_>],
    ) -> Result<Vec<KeyBytes>, Error> {
        dispatch!(self, b => b.unwrap_batch(key_ref, items).await, none => Err(no_vendor()))
    }

    async fn sleep(&self, duration: Duration) {
        dispatch!(self, b => b.sleep(duration).await, none => ())
    }
}

/// Why the configured backend could not be built: a setting the vendor
/// client refused (`STATUS_ENCODING`, naming the config key), or a keyset
/// record ([`RecordError`]).
#[derive(Debug)]
pub enum BuildError {
    /// The config key whose value the vendor client refused.
    Setting(&'static str),
    /// A keyset record was refused.
    Record(RecordError),
}

impl From<RecordError> for BuildError {
    fn from(error: RecordError) -> Self {
        Self::Record(error)
    }
}

/// Build the key source of the configured backend: the client over
/// `transport` and `import`, and the adapter over the keyset records. With
/// no config, [`GuestVendor::None`] and no records.
pub fn build<T, C>(
    config: Option<VendorConfig>,
    transport: T,
    import: C,
) -> Result<VendorKeySource<GuestVendor<T, C>>, BuildError>
where
    T: VendorTransport + Send + Sync,
    C: CredentialImport,
{
    let Some(VendorConfig {
        settings,
        records,
        default_keyset,
        root_key_ttl,
    }) = config
    else {
        return Ok(VendorKeySource::new(GuestVendor::None, [])?);
    };
    let credentials = HostCredentials::new(import);
    let backend = match settings {
        VendorSettings::Aws { region, endpoint } => {
            let mut config = stack_kms_aws::AwsKmsConfig::new(region)
                .map_err(|_| BuildError::Setting("aws_region"))?;
            if let Some(endpoint) = endpoint {
                config = config
                    .with_endpoint(endpoint)
                    .map_err(|_| BuildError::Setting("aws_endpoint"))?;
            }
            GuestVendor::Aws(stack_kms_aws::AwsKms::new(config, transport, credentials))
        }
        VendorSettings::Vault {
            address,
            namespace,
            mount,
        } => {
            let mut config = stack_kms_vault::VaultConfig::new(address)
                .map_err(|_| BuildError::Setting("vault_address"))?;
            if let Some(namespace) = namespace {
                config = config
                    .with_namespace(namespace)
                    .map_err(|_| BuildError::Setting("vault_namespace"))?;
            }
            if let Some(mount) = mount {
                config = config
                    .with_mount(mount)
                    .map_err(|_| BuildError::Setting("vault_mount"))?;
            }
            GuestVendor::Vault(stack_kms_vault::VaultTransit::new(
                config,
                transport,
                credentials,
            ))
        }
        VendorSettings::Gcp { endpoint } => {
            let mut config = stack_kms_gcp::GcpKmsConfig::new();
            if let Some(endpoint) = endpoint {
                config = config
                    .with_endpoint(endpoint)
                    .map_err(|_| BuildError::Setting("gcp_endpoint"))?;
            }
            GuestVendor::Gcp(stack_kms_gcp::GcpKms::new(config, transport, credentials))
        }
        VendorSettings::Azure => GuestVendor::Azure(stack_kms_azure::AzureKeyVault::new(
            stack_kms_azure::AzureKeyVaultConfig::new(),
            transport,
            credentials,
        )),
        VendorSettings::Static { key_ref, key } => {
            GuestVendor::Static(StaticKeyVendor::new(key_ref, key))
        }
    };
    let records = records
        .iter()
        .map(|text| KeysetRecord::parse(text))
        .collect::<Result<Vec<_>, _>>()?;
    let default = match default_keyset {
        None => None,
        Some(DefaultKeyset::Id(id)) => Some(id),
        Some(DefaultKeyset::Name(name)) => Some(
            records
                .iter()
                .find(|r| r.name() == Some(name.as_str()))
                .map(KeysetRecord::id)
                .ok_or(RecordError::UnknownDefault)?,
        ),
    };
    let mut source = VendorKeySource::new(backend, records)?;
    if let Some(id) = default {
        source = source.with_default_keyset(id)?;
    }
    if let Some(ttl) = root_key_ttl {
        source = source.with_root_key_ttl(ttl);
    }
    Ok(source)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use stack_kms_aws::CredentialsProvider;
    use stack_kms_vendor::{TransportError, VendorRequest, VendorResponse};
    use vitaminc_protected::Controlled;

    /// A fixed clock: 2026-11-06T00:00:00Z.
    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_793_923_200)
    }

    fn object(entries: Vec<(&str, FfiValue)>) -> FfiValue {
        FfiValue::Object(
            entries
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        )
    }

    fn string(text: &str) -> FfiValue {
        FfiValue::String(text.into())
    }

    type Answer = Box<dyn Fn() -> Result<FfiValue, CredentialError> + Send + Sync>;

    /// A fake import: answers each call with a new value from `answer` and
    /// records what it was asked.
    struct FakeImport {
        answer: Answer,
        asked: Mutex<Vec<(KeyVendor, String)>>,
    }

    impl FakeImport {
        fn new(
            answer: impl Fn() -> Result<FfiValue, CredentialError> + Send + Sync + 'static,
        ) -> Self {
            Self {
                answer: Box::new(answer),
                asked: Mutex::new(Vec::new()),
            }
        }

        fn unused() -> Self {
            Self::new(|| Err(CredentialError::denied("unused")))
        }
    }

    impl CredentialImport for FakeImport {
        fn credential(&self, vendor: KeyVendor, scope: &str) -> Result<FfiValue, CredentialError> {
            self.asked.lock().unwrap().push((vendor, scope.to_owned()));
            (self.answer)()
        }
    }

    fn aws_value() -> FfiValue {
        object(vec![
            ("access_key_id", string("AKIDEXAMPLE")),
            ("secret_access_key", string("fixture-secret")),
        ])
    }

    fn block<F: std::future::Future>(f: F) -> F::Output {
        futures::executor::block_on(f)
    }

    #[test]
    fn aws_credentials_are_read_from_the_host_value() {
        let expires = now() + Duration::from_secs(900);
        let seconds = expires
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let provider = HostCredentials::new(FakeImport::new(move || {
            Ok(object(vec![
                ("access_key_id", string("AKIDEXAMPLE")),
                ("secret_access_key", string("fixture-secret\n")),
                ("session_token", string("fixture-session-token")),
                ("expires_at", FfiValue::Int64(seconds as i64)),
            ]))
        }))
        .with_now(now);
        let credentials = block(provider.credentials()).unwrap();
        assert_eq!(credentials.access_key_id(), "AKIDEXAMPLE");
        assert_eq!(credentials.secret_access_key(), "fixture-secret");
        assert_eq!(credentials.session_token(), Some("fixture-session-token"));
        assert_eq!(credentials.expires_at(), Some(expires));
        assert_eq!(
            provider.import.asked.lock().unwrap().as_slice(),
            &[(KeyVendor::Aws, String::new())]
        );
    }

    #[test]
    fn a_missing_session_token_and_expiry_are_allowed() {
        let provider = HostCredentials::new(FakeImport::new(|| Ok(aws_value())));
        let credentials = block(provider.credentials()).unwrap();
        assert_eq!(credentials.session_token(), None);
        assert_eq!(credentials.expires_at(), None);
    }

    #[test]
    fn bad_credentials_are_refused_without_their_secret_in_the_message() {
        fn with(extra: Vec<(&'static str, FfiValue)>) -> FfiValue {
            let mut entries = vec![("access_key_id", string("AKIDEXAMPLE"))];
            entries.extend(extra);
            object(entries)
        }
        fn expired() -> i64 {
            now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
        }
        type Case = (&'static str, fn() -> FfiValue);
        let cases: Vec<Case> = vec![
            ("not an object", || string("fixture-secret")),
            ("no secret", || with(vec![])),
            ("empty secret", || {
                with(vec![("secret_access_key", string(""))])
            }),
            ("expired", || {
                with(vec![
                    ("secret_access_key", string("fixture-secret")),
                    ("expires_at", FfiValue::Int64(expired())),
                ])
            }),
            ("negative expiry", || {
                with(vec![
                    ("secret_access_key", string("fixture-secret")),
                    ("expires_at", FfiValue::Int64(-1)),
                ])
            }),
            ("control character", || {
                with(vec![("secret_access_key", string("fixture\nsecret"))])
            }),
            ("unknown key", || {
                with(vec![
                    ("secret_access_key", string("fixture-secret")),
                    ("token", string("fixture-secret")),
                ])
            }),
            ("not a string", || {
                with(vec![("secret_access_key", FfiValue::Int64(1))])
            }),
        ];
        for (label, value) in cases {
            let provider = HostCredentials::new(FakeImport::new(move || Ok(value()))).with_now(now);
            let error = provider.aws().expect_err(label);
            assert_eq!(error.kind, BackendErrorKind::AccessDenied, "{label}");
            assert!(
                !error.message.contains("fixture"),
                "{label}: {}",
                error.message
            );
        }
    }

    #[test]
    fn a_host_failure_keeps_its_kind() {
        let failure = CredentialError {
            kind: BackendErrorKind::Unavailable,
            message: "the host credential source failed".into(),
        };
        let provider = HostCredentials::new(FakeImport::new(move || Err(failure.clone())));
        let error = block(provider.credentials()).unwrap_err();
        assert_eq!(error.kind(), BackendErrorKind::Unavailable);
    }

    #[test]
    fn token_providers_ask_with_their_vendor_and_scope() {
        let provider = HostCredentials::new(FakeImport::new(|| {
            Ok(object(vec![("token", string("fixture-token"))]))
        }));
        let token = block(stack_kms_vault::TokenProvider::token(&provider)).unwrap();
        assert_eq!(token.token(), "fixture-token");

        let token = block(stack_kms_gcp::TokenProvider::token(&provider)).unwrap();
        assert_eq!(token.token(), "fixture-token");

        let token = block(stack_kms_azure::TokenProvider::token(
            &provider,
            stack_kms_azure::MANAGED_HSM_SCOPE,
        ))
        .unwrap();
        assert_eq!(token.token(), "fixture-token");

        assert_eq!(
            provider.import.asked.lock().unwrap().as_slice(),
            &[
                (KeyVendor::Vault, String::new()),
                (KeyVendor::Gcp, stack_kms_gcp::CLOUD_KMS_SCOPE.to_owned()),
                (
                    KeyVendor::Azure,
                    stack_kms_azure::MANAGED_HSM_SCOPE.to_owned()
                ),
            ]
        );

        // An AWS credential where a token is wanted is refused.
        let provider = HostCredentials::new(FakeImport::new(|| Ok(aws_value())));
        assert!(block(stack_kms_vault::TokenProvider::token(&provider)).is_err());
    }

    /// A transport that answers every request with one response and keeps
    /// the requests.
    #[derive(Default)]
    struct Recording {
        requests: Mutex<Vec<VendorRequest>>,
        response: Mutex<Option<VendorResponse>>,
    }

    impl VendorTransport for &Recording {
        async fn send(&self, request: VendorRequest) -> Result<VendorResponse, TransportError> {
            self.requests.lock().unwrap().push(request);
            self.response
                .lock()
                .unwrap()
                .take()
                .ok_or_else(|| TransportError("no response".into()))
        }

        async fn sleep(&self, _: Duration) {}
    }

    fn aws_settings() -> VendorConfig {
        VendorConfig {
            settings: VendorSettings::Aws {
                region: "us-east-1".into(),
                endpoint: None,
            },
            records: Vec::new(),
            default_keyset: None,
            root_key_ttl: None,
        }
    }

    #[test]
    fn an_aws_request_is_signed_with_the_host_credentials() {
        let transport = Recording::default();
        *transport.response.lock().unwrap() = Some(VendorResponse::new(
            200,
            br#"{"KeyId":"arn:aws:kms:us-east-1:111122223333:key/k","Plaintext":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"#.to_vec(),
        ));
        let import = FakeImport::new(|| {
            Ok(object(vec![
                ("access_key_id", string("AKIDEXAMPLE")),
                ("secret_access_key", string("fixture-secret")),
                ("session_token", string("fixture-session-token")),
            ]))
        });
        let source = build(Some(aws_settings()), &transport, import).unwrap();
        let key = block(source.backend().unwrap(
            "arn:aws:kms:us-east-1:111122223333:key/k",
            b"wrapped",
            b"aad",
        ))
        .unwrap();
        assert_eq!(key.risky_ref(), &[0u8; 32]);

        let requests = transport.requests.lock().unwrap();
        let request = &requests[0];
        assert_eq!(request.url, "https://kms.us-east-1.amazonaws.com/");
        let authorization = request.header_value("authorization").unwrap();
        assert!(authorization.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"));
        assert_eq!(
            request.header_value("x-amz-security-token"),
            Some("fixture-session-token")
        );
        assert_eq!(
            request.header_value("x-amz-target"),
            Some("TrentService.Decrypt")
        );
    }

    #[test]
    fn no_config_builds_no_vendor_and_no_keyset() {
        let transport = Recording::default();
        let source =
            build::<&Recording, FakeImport>(None, &transport, FakeImport::unused()).unwrap();
        assert!(matches!(source.backend(), GuestVendor::None));
        assert!(block(source.backend().unwrap("k", b"w", b"a")).is_err());
        assert!(!source.backend().supports_mode(KeyMode::Derived));
    }

    #[test]
    fn a_bad_setting_names_its_config_key() {
        let config = VendorConfig {
            settings: VendorSettings::Aws {
                region: "us east 1".into(),
                endpoint: None,
            },
            records: Vec::new(),
            default_keyset: None,
            root_key_ttl: None,
        };
        let error = build(Some(config), &Recording::default(), FakeImport::unused()).unwrap_err();
        assert!(matches!(error, BuildError::Setting("aws_region")));

        let config = VendorConfig {
            settings: VendorSettings::Vault {
                address: "not a url".into(),
                namespace: None,
                mount: None,
            },
            records: Vec::new(),
            default_keyset: None,
            root_key_ttl: None,
        };
        let error = build(Some(config), &Recording::default(), FakeImport::unused()).unwrap_err();
        assert!(matches!(error, BuildError::Setting("vault_address")));
    }

    #[test]
    fn a_record_of_another_vendor_is_refused() {
        // The pinned AWS record of stack-kms-vendor's own tests.
        let aws = "stack-keyset:AQEBAQIDBAUGBwgJCgsMDQ4PEARhY21lAChhcm46YXdzOmttczp1cy1lYXN0LTE6MTExMTIyMjIzMzMzOmtleS9rAAMBAgM";
        let config = VendorConfig {
            settings: VendorSettings::Static {
                key_ref: "local".into(),
                key: KeyBytes::new([7; 32]),
            },
            records: vec![aws.to_owned()],
            default_keyset: None,
            root_key_ttl: None,
        };
        let error = build(Some(config), &Recording::default(), FakeImport::unused()).unwrap_err();
        assert!(matches!(
            error,
            BuildError::Record(RecordError::ForeignVendor { .. })
        ));

        let config = VendorConfig {
            records: vec!["stack-keyset:***".to_owned()],
            ..aws_settings()
        };
        assert!(matches!(
            build(Some(config), &Recording::default(), FakeImport::unused(),),
            Err(BuildError::Record(_))
        ));
    }
}
