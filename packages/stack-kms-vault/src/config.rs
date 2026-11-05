//! The address, namespace, mount and batch size of a Vault Transit client.

use std::num::NonZeroUsize;

/// How an environment variable is read: the process environment unless a
/// test gives another.
pub type EnvLookup = std::sync::Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// The process environment. An empty variable counts as unset.
pub fn process_env() -> EnvLookup {
    std::sync::Arc::new(|name| std::env::var(name).ok().filter(|value| !value.is_empty()))
}

/// The default mount path of the Transit secrets engine.
pub const DEFAULT_MOUNT: &str = "transit";

/// The default batch size: the most keys in one `batch_input`.
pub const DEFAULT_BATCH_SIZE: usize = 250;

/// The configuration is not usable.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    /// No address was given, and `VAULT_ADDR` is not set.
    #[error("no Vault address: set VAULT_ADDR or give one in the config")]
    NoAddress,
    /// The address is not an absolute HTTP or HTTPS URL with no query.
    #[error("{0:?} is not an HTTP or HTTPS Vault address")]
    InvalidAddress(String),
    /// The mount path is not a Vault path.
    #[error("{0:?} is not a Vault mount path")]
    InvalidMount(String),
    /// The namespace is not a Vault namespace path.
    #[error("{0:?} is not a Vault namespace")]
    InvalidNamespace(String),
}

/// Whether a Transit key derives a key per request from `context`
/// (`derived=true`).
///
/// Vault requires `context` for a derived key and silently ignores it for
/// a key that is not derived, so the client must know which. Either way the
/// client also binds the associated data itself
/// ([`stack_kms_vendor::bound`]), so a wrong answer can make a call fail but
/// never makes a wrapped key open under other associated data.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KeyDerivation {
    /// Read the key's configuration (`GET /v1/{mount}/keys/{name}`) on the
    /// first use of each key, and keep the answer. The token needs `read` on
    /// that path. This also refuses a key that does not exist (Transit's
    /// `encrypt` would otherwise create it) and a key type that is not an
    /// AEAD. The default.
    #[default]
    Detect,
    /// Every key is derived: send the associated data as `context`. No key
    /// read.
    Derived,
    /// No key is derived: send no `context`. No key read.
    NotDerived,
}

/// A path of one or more segments of `[A-Za-z0-9._-]`, none `.` or `..`.
pub(crate) fn is_path(text: &str) -> bool {
    !text.is_empty() && text.split('/').all(is_segment)
}

/// One path segment of `[A-Za-z0-9._-]`, not `.` or `..`.
pub(crate) fn is_segment(text: &str) -> bool {
    !text.is_empty()
        && text != "."
        && text != ".."
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// The address, namespace, mount path and batch size of a
/// [`VaultTransit`](crate::VaultTransit) client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultConfig {
    address: String,
    namespace: Option<String>,
    mount: String,
    batch_size: NonZeroUsize,
    derivation: KeyDerivation,
}

impl VaultConfig {
    /// The Vault server at `address` (`https://vault.example.com:8200`),
    /// with the Transit engine at [`DEFAULT_MOUNT`], no namespace and
    /// [`DEFAULT_BATCH_SIZE`].
    pub fn new(address: impl Into<String>) -> Result<Self, ConfigError> {
        let address = address.into();
        let parsed =
            url::Url::parse(&address).map_err(|_| ConfigError::InvalidAddress(address.clone()))?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host().is_none()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(ConfigError::InvalidAddress(address));
        }
        let address = parsed.as_str().trim_end_matches('/').to_owned();
        Ok(Self {
            address,
            namespace: None,
            mount: DEFAULT_MOUNT.to_owned(),
            batch_size: NonZeroUsize::new(DEFAULT_BATCH_SIZE).unwrap_or(NonZeroUsize::MIN),
            derivation: KeyDerivation::Detect,
        })
    }

    /// The address from `VAULT_ADDR`, the namespace from `VAULT_NAMESPACE`,
    /// and the mount path from `VAULT_TRANSIT_MOUNT` (default
    /// [`DEFAULT_MOUNT`]).
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_env_lookup(&process_env())
    }

    /// As [`from_env`](Self::from_env), reading the variables with `env`.
    pub fn from_env_lookup(env: &EnvLookup) -> Result<Self, ConfigError> {
        let mut config = Self::new(env("VAULT_ADDR").ok_or(ConfigError::NoAddress)?)?;
        if let Some(namespace) = env("VAULT_NAMESPACE") {
            config = config.with_namespace(namespace)?;
        }
        if let Some(mount) = env("VAULT_TRANSIT_MOUNT") {
            config = config.with_mount(mount)?;
        }
        Ok(config)
    }

    /// Send every request in `namespace` (Vault Enterprise and HCP Vault),
    /// as the `X-Vault-Namespace` header. A leading or trailing `/` is
    /// removed.
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Result<Self, ConfigError> {
        let namespace = namespace.into();
        let trimmed = namespace.trim_matches('/');
        if !is_path(trimmed) {
            return Err(ConfigError::InvalidNamespace(namespace));
        }
        self.namespace = Some(trimmed.to_owned());
        Ok(self)
    }

    /// Use the Transit engine mounted at `mount` (`transit`,
    /// `encryption/transit`). A leading or trailing `/` is removed.
    pub fn with_mount(mut self, mount: impl Into<String>) -> Result<Self, ConfigError> {
        let mount = mount.into();
        let trimmed = mount.trim_matches('/');
        if !is_path(trimmed) {
            return Err(ConfigError::InvalidMount(mount));
        }
        self.mount = trimmed.to_owned();
        Ok(self)
    }

    /// Send at most `batch_size` keys in one `batch_input`.
    pub fn with_batch_size(mut self, batch_size: NonZeroUsize) -> Self {
        self.batch_size = batch_size;
        self
    }

    /// How the client learns whether a key is derived. Default
    /// [`KeyDerivation::Detect`].
    pub fn with_key_derivation(mut self, derivation: KeyDerivation) -> Self {
        self.derivation = derivation;
        self
    }

    /// The address, with no trailing `/`.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// The namespace, if any.
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    /// The mount path of the Transit engine.
    pub fn mount(&self) -> &str {
        &self.mount
    }

    /// The most keys in one `batch_input`.
    pub fn batch_size(&self) -> NonZeroUsize {
        self.batch_size
    }

    /// How the client learns whether a key is derived.
    pub fn key_derivation(&self) -> KeyDerivation {
        self.derivation
    }

    /// The URL of the API path `path` (no leading `/`, no `v1/`).
    pub fn url(&self, path: &str) -> String {
        format!("{}/v1/{path}", self.address)
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
    fn the_address_is_normalised_and_checked() {
        let config = VaultConfig::new("https://vault.example.com:8200/").unwrap();
        assert_eq!(config.address(), "https://vault.example.com:8200");
        assert_eq!(
            config.url("transit/encrypt/k"),
            "https://vault.example.com:8200/v1/transit/encrypt/k"
        );
        assert_eq!(config.mount(), "transit");
        assert_eq!(config.namespace(), None);
        assert_eq!(config.batch_size().get(), DEFAULT_BATCH_SIZE);
        assert_eq!(config.key_derivation(), KeyDerivation::Detect);
        for bad in [
            "vault:8200",
            "ftp://vault/",
            "https://vault/?x=1",
            "https://vault/#x",
            "https://user:pass@vault/",
            "not a url",
        ] {
            assert_eq!(
                VaultConfig::new(bad),
                Err(ConfigError::InvalidAddress(bad.to_owned())),
                "{bad}"
            );
        }
    }

    #[test]
    fn mounts_and_namespaces_are_paths() {
        let config = VaultConfig::new("http://127.0.0.1:8200").unwrap();
        let config = config
            .with_mount("/encryption/transit/")
            .unwrap()
            .with_namespace("admin/team-a/")
            .unwrap();
        assert_eq!(config.mount(), "encryption/transit");
        assert_eq!(config.namespace(), Some("admin/team-a"));
        for bad in ["", "a//b", "../sys", "a/./b", "a b", "a?b", "a\nb", "a%2fb"] {
            assert_eq!(
                config.clone().with_mount(bad),
                Err(ConfigError::InvalidMount(bad.to_owned())),
                "{bad:?}"
            );
            assert_eq!(
                config.clone().with_namespace(bad),
                Err(ConfigError::InvalidNamespace(bad.to_owned())),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn the_config_comes_from_the_environment() {
        assert_eq!(
            VaultConfig::from_env_lookup(&env(&[])),
            Err(ConfigError::NoAddress)
        );
        let config = VaultConfig::from_env_lookup(&env(&[
            ("VAULT_ADDR", "https://vault:8200"),
            ("VAULT_NAMESPACE", "admin"),
            ("VAULT_TRANSIT_MOUNT", "kms"),
        ]))
        .unwrap();
        assert_eq!(config.address(), "https://vault:8200");
        assert_eq!(config.namespace(), Some("admin"));
        assert_eq!(config.mount(), "kms");
        assert_eq!(
            VaultConfig::from_env_lookup(&env(&[("VAULT_ADDR", "vault")])),
            Err(ConfigError::InvalidAddress("vault".to_owned()))
        );
    }

    #[test]
    fn the_batch_size_and_derivation_are_set() {
        let config = VaultConfig::new("http://127.0.0.1:8200")
            .unwrap()
            .with_batch_size(NonZeroUsize::new(7).unwrap())
            .with_key_derivation(KeyDerivation::Derived);
        assert_eq!(config.batch_size().get(), 7);
        assert_eq!(config.key_derivation(), KeyDerivation::Derived);
    }
}
