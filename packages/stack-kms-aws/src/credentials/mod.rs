//! AWS credentials and where they come from.
//!
//! [`CredentialsProvider`] is the seam: the client asks it for
//! [`Credentials`] before it signs each request. This crate provides:
//!
//! * [`Credentials`] itself: static credentials, from explicit values or
//!   from `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and
//!   `AWS_SESSION_TOKEN` ([`Credentials::from_env`]). Everywhere.
//! * [`CachedCredentials`]: keeps the credentials another provider returns
//!   and fetches new ones before they expire. Everywhere.
//! * Workload identity, **native only**: [`WebIdentityCredentials`] (IRSA
//!   on EKS: STS `AssumeRoleWithWebIdentity`), [`EcsCredentials`] (the ECS
//!   and EKS Pod Identity container endpoint) and [`ImdsCredentials`] (the
//!   EC2 instance metadata service, IMDSv2). [`DefaultCredentials`] picks
//!   one from the environment, as the AWS SDKs do.
//!
//! In the WASI guest the host supplies the credentials (ADR-0014): the
//! guest implements [`CredentialsProvider`] over a host import.

use std::fmt;
use std::future::Future;

use stack_kms::MaybeSend;
use stack_kms_vendor::{CredentialError, CredentialKind, Expiring, Expiry, FetchCredential};
use web_time::SystemTime;
use zeroize::Zeroizing;

#[cfg(not(target_arch = "wasm32"))]
mod chain;
#[cfg(not(target_arch = "wasm32"))]
mod ecs;
#[cfg(not(target_arch = "wasm32"))]
mod imds;
#[cfg(not(target_arch = "wasm32"))]
mod response;
#[cfg(not(target_arch = "wasm32"))]
mod web_identity;

#[cfg(not(target_arch = "wasm32"))]
pub use chain::{DefaultCredentials, DefaultCredentialsSource};
#[cfg(not(target_arch = "wasm32"))]
pub use ecs::EcsCredentials;
#[cfg(not(target_arch = "wasm32"))]
pub use imds::{ImdsCredentials, DEFAULT_IMDS_ENDPOINT};
#[cfg(not(target_arch = "wasm32"))]
pub use web_identity::WebIdentityCredentials;

/// How an environment variable is read: the process environment unless a
/// test gives another.
pub type EnvLookup = std::sync::Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// The process environment. An empty variable counts as unset.
pub fn process_env() -> EnvLookup {
    std::sync::Arc::new(|name| std::env::var(name).ok().filter(|value| !value.is_empty()))
}

/// AWS credentials: an access key id, a secret access key and, for
/// temporary credentials, a session token and an expiry time.
///
/// The secret and the session token are wiped on drop and never printed.
#[derive(Clone)]
pub struct Credentials {
    access_key_id: String,
    secret_access_key: Zeroizing<String>,
    session_token: Option<Zeroizing<String>>,
    expires_at: Option<SystemTime>,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl Credentials {
    /// Credentials from explicit values. They do not expire.
    pub fn new(
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
        session_token: Option<String>,
    ) -> Self {
        Self {
            access_key_id: access_key_id.into(),
            secret_access_key: Zeroizing::new(secret_access_key.into()),
            session_token: session_token.map(Zeroizing::new),
            expires_at: None,
        }
    }

    /// The same credentials, expiring at `expires_at`.
    pub fn with_expiry(mut self, expires_at: SystemTime) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Credentials from `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and
    /// (optional) `AWS_SESSION_TOKEN`. `None` unless both of the first two
    /// are set.
    pub fn from_env() -> Option<Self> {
        Self::from_env_lookup(&process_env())
    }

    /// As [`from_env`](Self::from_env), reading the variables with `env`.
    pub fn from_env_lookup(env: &EnvLookup) -> Option<Self> {
        let access_key_id = env("AWS_ACCESS_KEY_ID")?;
        let secret = Zeroizing::new(env("AWS_SECRET_ACCESS_KEY")?);
        Some(Self {
            access_key_id,
            secret_access_key: secret,
            session_token: env("AWS_SESSION_TOKEN").map(Zeroizing::new),
            expires_at: None,
        })
    }

    /// The access key id.
    pub fn access_key_id(&self) -> &str {
        &self.access_key_id
    }

    /// The secret access key.
    pub fn secret_access_key(&self) -> &str {
        &self.secret_access_key
    }

    /// The session token, for temporary credentials.
    pub fn session_token(&self) -> Option<&str> {
        self.session_token.as_ref().map(|token| token.as_str())
    }

    /// When the credentials expire. `None` for credentials that do not.
    pub fn expires_at(&self) -> Option<SystemTime> {
        self.expires_at
    }
}

impl Expiring for Credentials {
    fn expiry(&self) -> Expiry {
        self.expires_at.map_or(Expiry::Never, Expiry::At)
    }
}

/// The credential kind of this crate: [`Credentials`], one set for the
/// client. It names [`CredentialsError`] and [`CachedCredentials`].
#[derive(Debug)]
pub enum AwsCredentials {}

impl CredentialKind for AwsCredentials {
    const LABEL: &'static str = "AWS credentials";
    type Key = ();
    type Credential = Credentials;
}

/// The credentials could not be got. The message starts with "AWS
/// credentials".
pub type CredentialsError = CredentialError<AwsCredentials>;

/// Where a client gets its credentials. The client asks before it signs
/// each request, so a provider that fetches should cache
/// ([`CachedCredentials`]).
///
/// The returned future is bounded by [`MaybeSend`]: `Send` on native
/// targets, unbounded on wasm32.
pub trait CredentialsProvider: Send + Sync {
    /// The current credentials.
    fn credentials(
        &self,
    ) -> impl Future<Output = Result<Credentials, CredentialsError>> + MaybeSend;
}

impl CredentialsProvider for Credentials {
    fn credentials(
        &self,
    ) -> impl Future<Output = Result<Credentials, CredentialsError>> + MaybeSend {
        std::future::ready(Ok(self.clone()))
    }
}

pub use stack_kms_vendor::DEFAULT_REFRESH_BEFORE_EXPIRY;

/// Keeps the credentials `inner` returns, and fetches new ones when they
/// are near their expiry: [`DEFAULT_REFRESH_BEFORE_EXPIRY`] before, or a
/// third of their life before when they live less than three times that.
///
/// One fetch runs at a time: callers that arrive during a fetch wait for
/// it and share its result. If a fetch fails while the cached credentials
/// have not yet expired, they are still returned. Credentials with no
/// expiry are kept for good.
pub type CachedCredentials<P> = stack_kms_vendor::CachedToken<P, AwsCredentials>;

impl<P: CredentialsProvider> FetchCredential<P> for AwsCredentials {
    fn fetch<'a>(
        provider: &'a P,
        _key: &'a (),
    ) -> impl Future<Output = Result<Credentials, CredentialsError>> + MaybeSend + 'a {
        provider.credentials()
    }
}

impl<P: CredentialsProvider> CredentialsProvider for CachedCredentials<P> {
    fn credentials(
        &self,
    ) -> impl Future<Output = Result<Credentials, CredentialsError>> + MaybeSend {
        self.get(&())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use super::*;

    fn env(pairs: &[(&str, &str)]) -> EnvLookup {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        Arc::new(move |name| map.get(name).cloned())
    }

    #[test]
    fn static_credentials_come_from_the_environment() {
        assert!(Credentials::from_env_lookup(&env(&[])).is_none());
        assert!(Credentials::from_env_lookup(&env(&[("AWS_ACCESS_KEY_ID", "AKID")])).is_none());
        let credentials = Credentials::from_env_lookup(&env(&[
            ("AWS_ACCESS_KEY_ID", "AKID"),
            ("AWS_SECRET_ACCESS_KEY", "secret"),
        ]))
        .unwrap();
        assert_eq!(credentials.access_key_id(), "AKID");
        assert_eq!(credentials.secret_access_key(), "secret");
        assert_eq!(credentials.session_token(), None);
        assert_eq!(credentials.expires_at(), None);
        let credentials = Credentials::from_env_lookup(&env(&[
            ("AWS_ACCESS_KEY_ID", "AKID"),
            ("AWS_SECRET_ACCESS_KEY", "secret"),
            ("AWS_SESSION_TOKEN", "token"),
        ]))
        .unwrap();
        assert_eq!(credentials.session_token(), Some("token"));
    }

    #[test]
    fn debug_hides_the_secret_and_the_token() {
        let text = format!(
            "{:?}",
            Credentials::new("AKID", "the-secret", Some("the-token".into()))
        );
        assert!(text.contains("AKID"));
        assert!(!text.contains("the-secret"));
        assert!(!text.contains("the-token"));
    }

    #[test]
    fn the_expiry_is_the_expiry_time() {
        let credentials = Credentials::new("AKID", "secret", None);
        assert_eq!(credentials.expiry(), Expiry::Never);
        let at = web_time::UNIX_EPOCH + std::time::Duration::from_secs(60);
        assert_eq!(credentials.with_expiry(at).expiry(), Expiry::At(at));
    }
}
