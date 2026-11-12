//! Vault tokens and the auth methods that get them.
//!
//! [`TokenProvider`] is the seam: the client asks it for a [`VaultToken`]
//! before each request. This crate provides:
//!
//! * [`VaultToken`] itself: a static token, from an explicit value or from
//!   `VAULT_TOKEN` ([`VaultToken::from_env`]). Everywhere. The operator
//!   renews it.
//! * [`AppRoleLogin`]: AppRole auth (`role_id` and `secret_id` to
//!   `/v1/auth/{mount}/login`). Everywhere.
//! * [`KubernetesLogin`]: Kubernetes auth (the pod's service account token
//!   to `/v1/auth/{mount}/login`). **Native only**: it reads the token file.
//! * [`CachedToken`]: keeps the token a login returns and logs in again
//!   before its lease ends.
//! * [`DefaultAuth`] (native): picks one from the environment.
//!
//! In the WASI guest the host supplies the token (ADR-0014): the guest
//! implements [`TokenProvider`] over a host import.
//!
//! A login always makes a new token. The client does not call
//! `renew-self`: a renewal cannot pass the token's max TTL, so a client
//! that renews must also log in again, and one path is simpler to test.
//! Note that each AppRole login uses up one use of a `secret_id` with a
//! use limit (`secret_id_num_uses`).

use std::fmt;
use std::future::Future;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use stack_kms::{BackendErrorKind, MaybeSend};
use stack_kms_vendor::{
    classify_status, CredentialError, CredentialKind, Expiring, Expiry, FetchCredential,
    VendorRequest, VendorTransport,
};
use zeroize::Zeroizing;

use crate::config::{is_path, process_env, EnvLookup, VaultConfig};

/// A Vault token, and how long its lease lasts from when it was issued.
///
/// The token is wiped on drop and never printed.
#[derive(Clone)]
pub struct VaultToken {
    token: Zeroizing<String>,
    lease: Option<Duration>,
}

impl fmt::Debug for VaultToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultToken")
            .field("token", &"<redacted>")
            .field("lease", &self.lease)
            .finish()
    }
}

impl VaultToken {
    /// A token with no known lease: it is used until Vault refuses it.
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: Zeroizing::new(token.into()),
            lease: None,
        }
    }

    /// The same token, whose lease lasts `lease` from now.
    pub fn with_lease(mut self, lease: Duration) -> Self {
        self.lease = Some(lease);
        self
    }

    /// The token from `VAULT_TOKEN`, or `None` when it is not set.
    pub fn from_env() -> Option<Self> {
        Self::from_env_lookup(&process_env())
    }

    /// As [`from_env`](Self::from_env), reading the variable with `env`.
    pub fn from_env_lookup(env: &EnvLookup) -> Option<Self> {
        env("VAULT_TOKEN").map(Self::new)
    }

    /// The token.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// How long the lease lasts from when the token was issued. `None` for
    /// a token with no known lease.
    pub fn lease(&self) -> Option<Duration> {
        self.lease
    }
}

impl Expiring for VaultToken {
    fn expiry(&self) -> Expiry {
        self.lease.map_or(Expiry::Never, Expiry::After)
    }
}

pub use stack_kms_vendor::DEFAULT_REFRESH_BEFORE_EXPIRY;

/// The credential kind of this crate: a [`VaultToken`], one for the
/// client. It names [`AuthError`] and [`CachedToken`].
#[derive(Debug)]
pub enum VaultAuth {}

impl CredentialKind for VaultAuth {
    const LABEL: &'static str = "Vault auth";
    type Key = ();
    type Credential = VaultToken;
}

/// A token could not be got. The message starts with "Vault auth".
pub type AuthError = CredentialError<VaultAuth>;

/// Where a client gets its Vault token. The client asks before each
/// request, so a provider that logs in should cache ([`CachedToken`]).
///
/// The returned future is bounded by [`MaybeSend`]: `Send` on native
/// targets, unbounded on wasm32.
pub trait TokenProvider: Send + Sync {
    /// The current token.
    fn token(&self) -> impl Future<Output = Result<VaultToken, AuthError>> + MaybeSend;

    /// Vault refused the current token (HTTP 403). A caching provider drops
    /// it, so that the next request logs in again. The default does
    /// nothing.
    fn invalidate(&self) {}
}

impl TokenProvider for VaultToken {
    fn token(&self) -> impl Future<Output = Result<VaultToken, AuthError>> + MaybeSend {
        std::future::ready(Ok(self.clone()))
    }
}

/// Keeps the token `inner` returns, and gets a new one when its lease is
/// near its end: [`DEFAULT_REFRESH_BEFORE_EXPIRY`] before, or a third of
/// the lease before when the lease is shorter than three times that.
///
/// One login runs at a time: callers that arrive during a login wait for
/// it and share its result. If a login fails while the cached token's lease
/// has not ended, the cached token is still returned. A token with no
/// lease is kept until Vault refuses it ([`TokenProvider::invalidate`]).
pub type CachedToken<P> = stack_kms_vendor::CachedToken<P, VaultAuth>;

impl<P: TokenProvider> FetchCredential<P> for VaultAuth {
    fn fetch<'a>(
        provider: &'a P,
        _key: &'a (),
    ) -> impl Future<Output = Result<VaultToken, AuthError>> + MaybeSend + 'a {
        provider.token()
    }

    fn invalidate(provider: &P) {
        provider.invalidate();
    }
}

impl<P: TokenProvider> TokenProvider for CachedToken<P> {
    fn token(&self) -> impl Future<Output = Result<VaultToken, AuthError>> + MaybeSend {
        self.get(&())
    }

    fn invalidate(&self) {
        stack_kms_vendor::CachedToken::invalidate(self);
    }
}

#[derive(Deserialize)]
struct LoginResponse {
    auth: Option<LoginAuth>,
}

#[derive(Deserialize)]
struct LoginAuth {
    client_token: Option<String>,
    #[serde(default)]
    lease_duration: u64,
}

#[derive(Deserialize)]
struct ErrorBody {
    #[serde(default)]
    errors: Vec<String>,
}

/// Log in at `/v1/auth/{mount}/login` with the JSON `body`. The body is
/// wiped after it is sent.
async fn login<T: VendorTransport>(
    config: &VaultConfig,
    transport: &T,
    method: &'static str,
    mount: &str,
    body: Zeroizing<Vec<u8>>,
) -> Result<VaultToken, AuthError> {
    let mut request = VendorRequest::new("POST", config.url(&format!("auth/{mount}/login")))
        .header("content-type", "application/json")
        .header("x-vault-request", "true");
    request.body = body;
    if let Some(namespace) = config.namespace() {
        request = request.header("x-vault-namespace", namespace);
    }
    let response = transport.send(request).await.map_err(|error| {
        AuthError::unavailable(format!("{method} login got no response: {error}"))
    })?;
    if let Some(kind) = classify_status(response.status) {
        // A refused login is HTTP 400 ("invalid role or secret ID") or 403.
        let kind = match kind {
            BackendErrorKind::InvalidCiphertext => BackendErrorKind::AccessDenied,
            kind => kind,
        };
        let errors = serde_json::from_slice::<ErrorBody>(&response.body)
            .map(|body| body.errors.join("; "))
            .unwrap_or_default();
        return Err(AuthError::new(
            kind,
            format!(
                "{method} login failed with HTTP {}: {errors}",
                response.status
            ),
        ));
    }
    let parsed: LoginResponse = serde_json::from_slice(&response.body).map_err(|_| {
        AuthError::unavailable(format!(
            "{method} login returned a response that is not JSON"
        ))
    })?;
    let auth = parsed
        .auth
        .ok_or_else(|| AuthError::unavailable(format!("{method} login returned no auth")))?;
    let token = Zeroizing::new(
        auth.client_token
            .ok_or_else(|| AuthError::unavailable(format!("{method} login returned no token")))?,
    );
    let token = VaultToken { token, lease: None };
    Ok(match auth.lease_duration {
        0 => token,
        seconds => token.with_lease(Duration::from_secs(seconds)),
    })
}

fn check_mount(method: &str, mount: &str) -> Result<(), AuthError> {
    if is_path(mount) {
        Ok(())
    } else {
        Err(AuthError::access_denied(format!(
            "{mount:?} is not a {method} auth mount path"
        )))
    }
}

/// The default mount path of AppRole auth.
pub const DEFAULT_APPROLE_MOUNT: &str = "approle";

/// AppRole auth: `role_id` and `secret_id` to `/v1/auth/{mount}/login`.
/// Wrap it in a [`CachedToken`].
pub struct AppRoleLogin<T> {
    config: VaultConfig,
    transport: T,
    mount: String,
    role_id: String,
    secret_id: Zeroizing<String>,
}

impl<T> fmt::Debug for AppRoleLogin<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppRoleLogin")
            .field("mount", &self.mount)
            .field("role_id", &self.role_id)
            .field("secret_id", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl<T> AppRoleLogin<T> {
    /// Log in to the server of `config` (address and namespace) through
    /// `transport`, at [`DEFAULT_APPROLE_MOUNT`].
    pub fn new(
        config: &VaultConfig,
        transport: T,
        role_id: impl Into<String>,
        secret_id: impl Into<String>,
    ) -> Self {
        Self {
            config: config.clone(),
            transport,
            mount: DEFAULT_APPROLE_MOUNT.to_owned(),
            role_id: role_id.into(),
            secret_id: Zeroizing::new(secret_id.into()),
        }
    }

    /// Log in at the AppRole auth mount `mount` instead.
    pub fn with_mount(mut self, mount: impl Into<String>) -> Self {
        self.mount = mount.into().trim_matches('/').to_owned();
        self
    }

    /// The transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }
}

#[derive(Serialize)]
struct AppRoleBody<'a> {
    role_id: &'a str,
    secret_id: &'a str,
}

impl<T: VendorTransport + Send + Sync> TokenProvider for AppRoleLogin<T> {
    async fn token(&self) -> Result<VaultToken, AuthError> {
        check_mount("AppRole", &self.mount)?;
        let body = Zeroizing::new(
            serde_json::to_vec(&AppRoleBody {
                role_id: &self.role_id,
                secret_id: &self.secret_id,
            })
            .map_err(|_| AuthError::unavailable("AppRole login body"))?,
        );
        login(&self.config, &self.transport, "AppRole", &self.mount, body).await
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod kubernetes {
    use std::path::PathBuf;

    use super::*;

    /// The default mount path of Kubernetes auth.
    pub const DEFAULT_KUBERNETES_MOUNT: &str = "kubernetes";

    /// Where Kubernetes mounts the pod's service account token.
    pub const DEFAULT_SERVICE_ACCOUNT_TOKEN_PATH: &str =
        "/var/run/secrets/kubernetes.io/serviceaccount/token";

    /// Kubernetes auth: the pod's service account token (a JWT) and a
    /// Vault role to `/v1/auth/{mount}/login`. The token file is read on
    /// each login, because Kubernetes rotates it. Native only. Wrap it in a
    /// [`CachedToken`].
    pub struct KubernetesLogin<T> {
        config: VaultConfig,
        transport: T,
        mount: String,
        role: String,
        token_path: PathBuf,
    }

    impl<T> fmt::Debug for KubernetesLogin<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("KubernetesLogin")
                .field("mount", &self.mount)
                .field("role", &self.role)
                .field("token_path", &self.token_path)
                .finish_non_exhaustive()
        }
    }

    impl<T> KubernetesLogin<T> {
        /// Log in as `role` to the server of `config` through `transport`,
        /// at [`DEFAULT_KUBERNETES_MOUNT`], with the token at
        /// [`DEFAULT_SERVICE_ACCOUNT_TOKEN_PATH`].
        pub fn new(config: &VaultConfig, transport: T, role: impl Into<String>) -> Self {
            Self {
                config: config.clone(),
                transport,
                mount: DEFAULT_KUBERNETES_MOUNT.to_owned(),
                role: role.into(),
                token_path: PathBuf::from(DEFAULT_SERVICE_ACCOUNT_TOKEN_PATH),
            }
        }

        /// Log in at the Kubernetes auth mount `mount` instead.
        pub fn with_mount(mut self, mount: impl Into<String>) -> Self {
            self.mount = mount.into().trim_matches('/').to_owned();
            self
        }

        /// Read the service account token from `path` instead.
        pub fn with_token_path(mut self, path: impl Into<PathBuf>) -> Self {
            self.token_path = path.into();
            self
        }
    }

    #[derive(Serialize)]
    struct KubernetesBody<'a> {
        role: &'a str,
        jwt: &'a str,
    }

    impl<T: VendorTransport + Send + Sync> TokenProvider for KubernetesLogin<T> {
        async fn token(&self) -> Result<VaultToken, AuthError> {
            check_mount("Kubernetes", &self.mount)?;
            let jwt =
                Zeroizing::new(std::fs::read_to_string(&self.token_path).map_err(|error| {
                    AuthError::access_denied(format!(
                        "cannot read the service account token at {}: {}",
                        self.token_path.display(),
                        error.kind()
                    ))
                })?);
            let body = Zeroizing::new(
                serde_json::to_vec(&KubernetesBody {
                    role: &self.role,
                    jwt: jwt.trim(),
                })
                .map_err(|_| AuthError::unavailable("Kubernetes login body"))?,
            );
            login(
                &self.config,
                &self.transport,
                "Kubernetes",
                &self.mount,
                body,
            )
            .await
        }
    }

    /// The auth method [`DefaultAuth::from_env`] picks.
    #[derive(Debug)]
    pub enum DefaultAuth<T> {
        /// `VAULT_TOKEN`.
        Token(VaultToken),
        /// `VAULT_APPROLE_ROLE_ID` and `VAULT_APPROLE_SECRET_ID`.
        AppRole(CachedToken<AppRoleLogin<T>>),
        /// `VAULT_KUBERNETES_ROLE`.
        Kubernetes(CachedToken<KubernetesLogin<T>>),
    }

    impl<T: VendorTransport + Send + Sync> DefaultAuth<T> {
        /// Pick an auth method from the environment, in this order:
        ///
        /// 1. `VAULT_TOKEN`: a static token.
        /// 2. `VAULT_APPROLE_ROLE_ID` and `VAULT_APPROLE_SECRET_ID`: AppRole,
        ///    at `VAULT_APPROLE_MOUNT` (default `approle`).
        /// 3. `VAULT_KUBERNETES_ROLE`: Kubernetes, at
        ///    `VAULT_KUBERNETES_MOUNT` (default `kubernetes`), with the token
        ///    at `VAULT_KUBERNETES_TOKEN_PATH` (default the service account
        ///    token path).
        ///
        /// The login methods log in through `transport` and are cached.
        pub fn from_env(config: &VaultConfig, transport: T) -> Result<Self, AuthError> {
            Self::from_env_lookup(config, transport, &process_env())
        }

        /// As [`from_env`](Self::from_env), reading the variables with `env`.
        pub fn from_env_lookup(
            config: &VaultConfig,
            transport: T,
            env: &EnvLookup,
        ) -> Result<Self, AuthError> {
            if let Some(token) = VaultToken::from_env_lookup(env) {
                return Ok(Self::Token(token));
            }
            if let (Some(role_id), Some(secret_id)) = (
                env("VAULT_APPROLE_ROLE_ID"),
                env("VAULT_APPROLE_SECRET_ID").map(Zeroizing::new),
            ) {
                let mut login = AppRoleLogin::new(config, transport, role_id, secret_id.as_str());
                if let Some(mount) = env("VAULT_APPROLE_MOUNT") {
                    login = login.with_mount(mount);
                }
                return Ok(Self::AppRole(CachedToken::new(login)));
            }
            if let Some(role) = env("VAULT_KUBERNETES_ROLE") {
                let mut login = KubernetesLogin::new(config, transport, role);
                if let Some(mount) = env("VAULT_KUBERNETES_MOUNT") {
                    login = login.with_mount(mount);
                }
                if let Some(path) = env("VAULT_KUBERNETES_TOKEN_PATH") {
                    login = login.with_token_path(path);
                }
                return Ok(Self::Kubernetes(CachedToken::new(login)));
            }
            Err(AuthError::access_denied(
                "no Vault auth: set VAULT_TOKEN, VAULT_APPROLE_ROLE_ID and \
                 VAULT_APPROLE_SECRET_ID, or VAULT_KUBERNETES_ROLE",
            ))
        }
    }

    impl<T: VendorTransport + Send + Sync> TokenProvider for DefaultAuth<T> {
        async fn token(&self) -> Result<VaultToken, AuthError> {
            match self {
                Self::Token(token) => Ok(token.clone()),
                Self::AppRole(login) => login.token().await,
                Self::Kubernetes(login) => login.token().await,
            }
        }

        fn invalidate(&self) {
            match self {
                Self::Token(_) => {}
                Self::AppRole(login) => login.invalidate(),
                Self::Kubernetes(login) => login.invalidate(),
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use kubernetes::{
    DefaultAuth, KubernetesLogin, DEFAULT_KUBERNETES_MOUNT, DEFAULT_SERVICE_ACCOUNT_TOKEN_PATH,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_hides_the_token() {
        let text = format!("{:?}", VaultToken::new("hvs.secret"));
        assert!(!text.contains("hvs.secret"));
        let text = format!(
            "{:?}",
            AppRoleLogin::new(
                &VaultConfig::new("http://vault:8200").unwrap(),
                (),
                "role",
                "the-secret-id"
            )
        );
        assert!(text.contains("role"));
        assert!(!text.contains("the-secret-id"));
    }

    #[test]
    fn the_lease_is_the_expiry() {
        assert_eq!(VaultToken::new("t").expiry(), Expiry::Never);
        let token = VaultToken::new("t").with_lease(Duration::from_secs(60));
        assert_eq!(token.expiry(), Expiry::After(Duration::from_secs(60)));
    }
}
