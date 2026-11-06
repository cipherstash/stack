//! The key identifiers a client accepts, the Azure clouds it knows, and its
//! settings.

/// How an environment variable is read: the process environment unless a
/// test gives another.
pub type EnvLookup = std::sync::Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// The process environment. An empty variable counts as unset.
pub fn process_env() -> EnvLookup {
    std::sync::Arc::new(|name| std::env::var(name).ok().filter(|value| !value.is_empty()))
}

/// The Key Vault REST API version of every request.
///
/// 7.4 is a GA version that Key Vault and Managed HSM both serve, and it has
/// every operation this client uses (`GET /keys`, `wrapkey`, `unwrapkey`).
pub const API_VERSION: &str = "7.4";

/// Key Vault or Managed HSM. Both speak the same REST API; they differ in
/// the DNS suffix and the token scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Flavour {
    /// Azure Key Vault (`{vault}.vault.azure.net`): RSA keys, so
    /// RSA-OAEP-256.
    KeyVault,
    /// Azure Key Vault Managed HSM (`{hsm}.managedhsm.azure.net`): `oct-HSM`
    /// keys, so A256KW (or RSA-HSM keys, so RSA-OAEP-256).
    ManagedHsm,
}

/// The DNS suffixes of the Azure clouds this client sends to, with the
/// flavour and the token scope of each. A key identifier on any other host
/// is refused, so a keyset record cannot send a bearer token elsewhere.
pub const KNOWN_SUFFIXES: [(&str, Flavour, &str); 6] = [
    (
        "vault.azure.net",
        Flavour::KeyVault,
        "https://vault.azure.net/.default",
    ),
    (
        "vault.azure.cn",
        Flavour::KeyVault,
        "https://vault.azure.cn/.default",
    ),
    (
        "vault.usgovcloudapi.net",
        Flavour::KeyVault,
        "https://vault.usgovcloudapi.net/.default",
    ),
    (
        "managedhsm.azure.net",
        Flavour::ManagedHsm,
        "https://managedhsm.azure.net/.default",
    ),
    (
        "managedhsm.azure.cn",
        Flavour::ManagedHsm,
        "https://managedhsm.azure.cn/.default",
    ),
    (
        "managedhsm.usgovcloudapi.net",
        Flavour::ManagedHsm,
        "https://managedhsm.usgovcloudapi.net/.default",
    ),
];

/// The token scope of Azure Key Vault in the public cloud.
pub const KEY_VAULT_SCOPE: &str = "https://vault.azure.net/.default";
/// The token scope of Managed HSM in the public cloud.
pub const MANAGED_HSM_SCOPE: &str = "https://managedhsm.azure.net/.default";

/// A parsed Azure key identifier:
/// `https://{vault}.vault.azure.net/keys/{name}` or
/// `https://{hsm}.managedhsm.azure.net/keys/{name}`, optionally followed by
/// `/{version}`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KeyId {
    vault: String,
    name: String,
    version: Option<String>,
    flavour: Flavour,
    scope: &'static str,
}

/// A vault, HSM or key name: `[A-Za-z0-9-]`, 1 to 127 characters.
fn is_name(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 127
        && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// A key version: `[A-Za-z0-9]`, 1 to [`MAX_VERSION_LEN`] characters. Azure
/// issues 32 hexadecimal digits.
pub fn is_version(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_VERSION_LEN
        && text.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// The longest key version this client accepts.
pub const MAX_VERSION_LEN: usize = 64;

impl KeyId {
    /// Parse `text`. `None` if it is not an Azure key identifier on a known
    /// host ([`KNOWN_SUFFIXES`]) with no port, query, fragment or
    /// credentials. The client refuses anything else before any call, so a
    /// key reference cannot change the host or the request path.
    pub fn parse(text: &str) -> Option<Self> {
        let rest = text.strip_prefix("https://")?;
        let (host, path) = rest.split_once('/')?;
        let host = host.to_ascii_lowercase();
        let (vault_name, suffix) = host.split_once('.')?;
        if !is_name(vault_name) || vault_name.len() > 63 {
            return None;
        }
        let (_, flavour, scope) = KNOWN_SUFFIXES
            .iter()
            .find(|(known, _, _)| *known == suffix)?;
        let parts: Vec<&str> = path.split('/').collect();
        let (name, version) = match parts.as_slice() {
            ["keys", name] => (*name, None),
            ["keys", name, version] => (*name, Some(*version)),
            _ => return None,
        };
        if !is_name(name) || version.is_some_and(|v| !is_version(v)) {
            return None;
        }
        Some(Self {
            vault: format!("https://{host}"),
            name: name.to_owned(),
            version: version.map(str::to_owned),
            flavour: *flavour,
            scope,
        })
    }

    /// The vault or HSM origin, `https://{host}`, lower case.
    pub fn vault(&self) -> &str {
        &self.vault
    }

    /// The key name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The pinned version, if the identifier names one.
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    /// Key Vault or Managed HSM.
    pub fn flavour(&self) -> Flavour {
        self.flavour
    }

    /// The token scope of the host: [`KEY_VAULT_SCOPE`],
    /// [`MANAGED_HSM_SCOPE`], or the one of a national cloud.
    pub fn scope(&self) -> &'static str {
        self.scope
    }

    /// The same key at `version`.
    pub fn with_version(&self, version: &str) -> Self {
        Self {
            version: Some(version.to_owned()),
            ..self.clone()
        }
    }

    /// The URL of the key (with its version, if any) and `operation`
    /// (`wrapkey`), or of the key itself when `operation` is `None`, with
    /// the API version.
    pub fn url(&self, operation: Option<&str>) -> String {
        let mut url = format!("{}/keys/{}", self.vault, self.name);
        if let Some(version) = &self.version {
            url.push('/');
            url.push_str(version);
        }
        if let Some(operation) = operation {
            url.push('/');
            url.push_str(operation);
        }
        url.push_str("?api-version=");
        url.push_str(API_VERSION);
        url
    }

    /// The identifier text: `{vault}/keys/{name}[/{version}]`.
    pub fn to_kid(&self) -> String {
        match &self.version {
            Some(version) => format!("{}/keys/{}/{version}", self.vault, self.name),
            None => format!("{}/keys/{}", self.vault, self.name),
        }
    }
}

/// The key wrap algorithm of a key. The stored wrapped key names it, so an
/// unwrap needs no key read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WrapAlgorithm {
    /// RSA-OAEP with SHA-256 and MGF1 with SHA-256, for `RSA` and `RSA-HSM`
    /// keys. Stored as `1`.
    RsaOaep256,
    /// AES key wrap (RFC 3394) with a 256-bit key, for Managed HSM `oct-HSM`
    /// keys. Stored as `2`.
    A256Kw,
}

impl WrapAlgorithm {
    /// The JSON Web Algorithm name Azure takes (`RSA-OAEP-256`, `A256KW`).
    pub fn name(self) -> &'static str {
        match self {
            Self::RsaOaep256 => "RSA-OAEP-256",
            Self::A256Kw => "A256KW",
        }
    }

    /// The byte of the stored wrapped key.
    pub fn byte(self) -> u8 {
        match self {
            Self::RsaOaep256 => 1,
            Self::A256Kw => 2,
        }
    }

    /// The algorithm of a stored byte.
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::RsaOaep256),
            2 => Some(Self::A256Kw),
            _ => None,
        }
    }

    /// The algorithm of a key of JSON Web Key type `kty`, or `None` when the
    /// type cannot wrap a key here (for example `EC`).
    pub fn for_key_type(kty: &str) -> Option<Self> {
        match kty {
            "RSA" | "RSA-HSM" => Some(Self::RsaOaep256),
            "oct" | "oct-HSM" => Some(Self::A256Kw),
            _ => None,
        }
    }
}

/// The settings of an [`AzureKeyVault`](crate::AzureKeyVault) client.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AzureKeyVaultConfig {
    algorithm: Option<WrapAlgorithm>,
}

impl AzureKeyVaultConfig {
    /// The default: the client reads each key once (`GET /keys/{name}`) to
    /// learn its type, and its current version when the key identifier has
    /// none.
    pub fn new() -> Self {
        Self::default()
    }

    /// Use `algorithm` for every key. With a versioned key identifier the
    /// client then reads no key before a wrap. A key whose type does not
    /// match is refused.
    pub fn with_algorithm(mut self, algorithm: WrapAlgorithm) -> Self {
        self.algorithm = Some(algorithm);
        self
    }

    /// The configured algorithm, if any.
    pub fn algorithm(&self) -> Option<WrapAlgorithm> {
        self.algorithm
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VAULT_KEY: &str = "https://my-vault.vault.azure.net/keys/users";
    const HSM_KEY: &str =
        "https://my-hsm.managedhsm.azure.net/keys/users/0123456789abcdef0123456789abcdef";

    #[test]
    fn key_ids_parse() {
        let id = KeyId::parse(VAULT_KEY).unwrap();
        assert_eq!(id.vault(), "https://my-vault.vault.azure.net");
        assert_eq!(id.name(), "users");
        assert_eq!(id.version(), None);
        assert_eq!(id.flavour(), Flavour::KeyVault);
        assert_eq!(id.scope(), KEY_VAULT_SCOPE);
        assert_eq!(id.to_kid(), VAULT_KEY);
        assert_eq!(
            id.url(None),
            "https://my-vault.vault.azure.net/keys/users?api-version=7.4"
        );
        assert_eq!(
            id.with_version("abc").url(Some("wrapkey")),
            "https://my-vault.vault.azure.net/keys/users/abc/wrapkey?api-version=7.4"
        );

        let id = KeyId::parse(HSM_KEY).unwrap();
        assert_eq!(id.flavour(), Flavour::ManagedHsm);
        assert_eq!(id.scope(), MANAGED_HSM_SCOPE);
        assert_eq!(id.version(), Some("0123456789abcdef0123456789abcdef"));
        assert_eq!(id.to_kid(), HSM_KEY);

        let id = KeyId::parse("https://My-Vault.VAULT.azure.cn/keys/k").unwrap();
        assert_eq!(id.vault(), "https://my-vault.vault.azure.cn");
        assert_eq!(id.scope(), "https://vault.azure.cn/.default");
        let id = KeyId::parse("https://h.managedhsm.usgovcloudapi.net/keys/k").unwrap();
        assert_eq!(id.scope(), "https://managedhsm.usgovcloudapi.net/.default");
    }

    #[test]
    fn anything_else_is_refused() {
        for bad in [
            "",
            "users",
            "http://my-vault.vault.azure.net/keys/users",
            "https://my-vault.vault.azure.net/keys/",
            "https://my-vault.vault.azure.net/keys/users/",
            "https://my-vault.vault.azure.net/keys/users/v1/wrapkey",
            "https://my-vault.vault.azure.net/secrets/users",
            "https://my-vault.vault.azure.net/keys/us_ers",
            "https://my-vault.vault.azure.net/keys/users?x=1",
            "https://my-vault.vault.azure.net/keys/users#x",
            "https://my-vault.vault.azure.net/keys/users/ab-cd",
            "https://my-vault.vault.azure.net:443/keys/users",
            "https://user@my-vault.vault.azure.net/keys/users",
            "https://my-vault.vault.azure.net.evil.example/keys/users",
            "https://evil.example/keys/users",
            "https://vault.azure.net/keys/users",
            "https://a.b.vault.azure.net/keys/users",
            "https://my-vault.vault.azure.net/keys/../users",
            "https://my-vault.vault.azure.net//keys/users",
        ] {
            assert_eq!(KeyId::parse(bad), None, "{bad:?}");
        }
        let long = format!("https://v.vault.azure.net/keys/k/{}", "a".repeat(65));
        assert_eq!(KeyId::parse(&long), None);
    }

    #[test]
    fn algorithms_round_trip() {
        for algorithm in [WrapAlgorithm::RsaOaep256, WrapAlgorithm::A256Kw] {
            assert_eq!(WrapAlgorithm::from_byte(algorithm.byte()), Some(algorithm));
        }
        assert_eq!(WrapAlgorithm::from_byte(0), None);
        assert_eq!(WrapAlgorithm::from_byte(3), None);
        assert_eq!(WrapAlgorithm::RsaOaep256.name(), "RSA-OAEP-256");
        assert_eq!(WrapAlgorithm::A256Kw.name(), "A256KW");
        assert_eq!(
            WrapAlgorithm::for_key_type("RSA-HSM"),
            Some(WrapAlgorithm::RsaOaep256)
        );
        assert_eq!(
            WrapAlgorithm::for_key_type("oct-HSM"),
            Some(WrapAlgorithm::A256Kw)
        );
        assert_eq!(WrapAlgorithm::for_key_type("EC"), None);
    }
}
