//! The key identifiers a client accepts and the Azure clouds it knows.

/// How an environment variable is read: the process environment unless a
/// test gives another.
pub type EnvLookup = std::sync::Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// The process environment. An empty variable counts as unset.
pub fn process_env() -> EnvLookup {
    std::sync::Arc::new(|name| std::env::var(name).ok().filter(|value| !value.is_empty()))
}

/// The Key Vault REST API version of every request.
///
/// Managed HSM speaks the Key Vault REST API. 7.4 is a GA version that
/// Managed HSM serves, and it has every operation this client uses
/// (`GET /keys`, `wrapkey`, `unwrapkey`).
pub const API_VERSION: &str = "7.4";

/// The DNS suffixes of the Managed HSM clouds this client sends to, with the
/// token scope of each. A key identifier on any other host is refused, so a
/// keyset record cannot send a bearer token elsewhere. A Key Vault host
/// (`vault.azure.net`) is refused too: a vault holds no AES key, and an RSA
/// wrap gives no proof of who wrapped the key.
pub const KNOWN_SUFFIXES: [(&str, &str); 3] = [
    (
        "managedhsm.azure.net",
        "https://managedhsm.azure.net/.default",
    ),
    (
        "managedhsm.azure.cn",
        "https://managedhsm.azure.cn/.default",
    ),
    (
        "managedhsm.usgovcloudapi.net",
        "https://managedhsm.usgovcloudapi.net/.default",
    ),
];

/// The token scope of Managed HSM in the public cloud.
pub const MANAGED_HSM_SCOPE: &str = "https://managedhsm.azure.net/.default";

/// The JSON Web Key type of the only key this client uses: a Managed HSM
/// AES key.
pub const KEY_TYPE: &str = "oct-HSM";

/// The key wrap algorithm of every wrap: AES key wrap (RFC 3394) with a
/// 256-bit key.
pub const WRAP_ALGORITHM: &str = "A256KW";

/// A parsed Managed HSM key identifier:
/// `https://{hsm}.managedhsm.azure.net/keys/{name}`, optionally followed by
/// `/{version}`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KeyId {
    hsm: String,
    name: String,
    version: Option<String>,
    scope: &'static str,
}

/// An HSM or key name: `[A-Za-z0-9-]`, 1 to 127 characters.
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
    /// Parse `text`. `None` if it is not a Managed HSM key identifier on a
    /// known host ([`KNOWN_SUFFIXES`]) with no port, query, fragment or
    /// credentials. The client refuses anything else before any call, so a
    /// key reference cannot change the host or the request path.
    pub fn parse(text: &str) -> Option<Self> {
        let rest = text.strip_prefix("https://")?;
        let (host, path) = rest.split_once('/')?;
        let host = host.to_ascii_lowercase();
        let (hsm_name, suffix) = host.split_once('.')?;
        if !is_name(hsm_name) || hsm_name.len() > 63 {
            return None;
        }
        let (_, scope) = KNOWN_SUFFIXES.iter().find(|(known, _)| *known == suffix)?;
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
            hsm: format!("https://{host}"),
            name: name.to_owned(),
            version: version.map(str::to_owned),
            scope,
        })
    }

    /// The HSM origin, `https://{host}`, lower case.
    pub fn hsm(&self) -> &str {
        &self.hsm
    }

    /// The key name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The pinned version, if the identifier names one.
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    /// The token scope of the host: [`MANAGED_HSM_SCOPE`], or the one of a
    /// national cloud.
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
        let mut url = format!("{}/keys/{}", self.hsm, self.name);
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

    /// The identifier text: `{hsm}/keys/{name}[/{version}]`.
    pub fn to_kid(&self) -> String {
        match &self.version {
            Some(version) => format!("{}/keys/{}/{version}", self.hsm, self.name),
            None => format!("{}/keys/{}", self.hsm, self.name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "https://my-hsm.managedhsm.azure.net/keys/users";
    const PINNED: &str =
        "https://my-hsm.managedhsm.azure.net/keys/users/0123456789abcdef0123456789abcdef";

    #[test]
    fn key_ids_parse() {
        let id = KeyId::parse(KEY).unwrap();
        assert_eq!(id.hsm(), "https://my-hsm.managedhsm.azure.net");
        assert_eq!(id.name(), "users");
        assert_eq!(id.version(), None);
        assert_eq!(id.scope(), MANAGED_HSM_SCOPE);
        assert_eq!(id.to_kid(), KEY);
        assert_eq!(
            id.url(None),
            "https://my-hsm.managedhsm.azure.net/keys/users?api-version=7.4"
        );
        assert_eq!(
            id.with_version("abc").url(Some("wrapkey")),
            "https://my-hsm.managedhsm.azure.net/keys/users/abc/wrapkey?api-version=7.4"
        );

        let id = KeyId::parse(PINNED).unwrap();
        assert_eq!(id.version(), Some("0123456789abcdef0123456789abcdef"));
        assert_eq!(id.to_kid(), PINNED);

        let id = KeyId::parse("https://My-HSM.MANAGEDHSM.azure.cn/keys/k").unwrap();
        assert_eq!(id.hsm(), "https://my-hsm.managedhsm.azure.cn");
        assert_eq!(id.scope(), "https://managedhsm.azure.cn/.default");
        let id = KeyId::parse("https://h.managedhsm.usgovcloudapi.net/keys/k").unwrap();
        assert_eq!(id.scope(), "https://managedhsm.usgovcloudapi.net/.default");
    }

    #[test]
    fn anything_else_is_refused() {
        for bad in [
            "",
            "users",
            "http://my-hsm.managedhsm.azure.net/keys/users",
            "https://my-hsm.managedhsm.azure.net/keys/",
            "https://my-hsm.managedhsm.azure.net/keys/users/",
            "https://my-hsm.managedhsm.azure.net/keys/users/v1/wrapkey",
            "https://my-hsm.managedhsm.azure.net/secrets/users",
            "https://my-hsm.managedhsm.azure.net/keys/us_ers",
            "https://my-hsm.managedhsm.azure.net/keys/users?x=1",
            "https://my-hsm.managedhsm.azure.net/keys/users#x",
            "https://my-hsm.managedhsm.azure.net/keys/users/ab-cd",
            "https://my-hsm.managedhsm.azure.net:443/keys/users",
            "https://user@my-hsm.managedhsm.azure.net/keys/users",
            "https://my-hsm.managedhsm.azure.net.evil.example/keys/users",
            "https://evil.example/keys/users",
            "https://managedhsm.azure.net/keys/users",
            "https://a.b.managedhsm.azure.net/keys/users",
            "https://my-hsm.managedhsm.azure.net/keys/../users",
            "https://my-hsm.managedhsm.azure.net//keys/users",
            // Azure Key Vault is not supported.
            "https://my-vault.vault.azure.net/keys/users",
            "https://my-vault.vault.azure.cn/keys/users",
            "https://my-vault.vault.usgovcloudapi.net/keys/users",
        ] {
            assert_eq!(KeyId::parse(bad), None, "{bad:?}");
        }
        let long = format!("https://h.managedhsm.azure.net/keys/k/{}", "a".repeat(65));
        assert_eq!(KeyId::parse(&long), None);
    }
}
