//! The endpoint of a Cloud KMS client, and the crypto key names it accepts.

/// How an environment variable is read: the process environment unless a
/// test gives another.
pub type EnvLookup = std::sync::Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// The process environment. An empty variable counts as unset.
pub fn process_env() -> EnvLookup {
    std::sync::Arc::new(|name| std::env::var(name).ok().filter(|value| !value.is_empty()))
}

/// The Cloud KMS API endpoint.
pub const DEFAULT_ENDPOINT: &str = "https://cloudkms.googleapis.com";

/// The configuration is not usable.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    /// The endpoint is not an absolute HTTP or HTTPS URL with no path,
    /// query or credentials.
    #[error("{0:?} is not an HTTP or HTTPS Cloud KMS endpoint")]
    InvalidEndpoint(String),
}

/// The endpoint of a [`GcpKms`](crate::GcpKms) client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GcpKmsConfig {
    endpoint: String,
}

impl Default for GcpKmsConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl GcpKmsConfig {
    /// The public Cloud KMS endpoint, [`DEFAULT_ENDPOINT`].
    pub fn new() -> Self {
        Self {
            endpoint: DEFAULT_ENDPOINT.to_owned(),
        }
    }

    /// Send to `endpoint` instead: a regional or Private Service Connect
    /// endpoint (`https://cloudkms.europe-west1.rep.googleapis.com`), or a
    /// test server. A trailing `/` is removed.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Result<Self, ConfigError> {
        let endpoint = endpoint.into();
        let parsed = url::Url::parse(&endpoint)
            .map_err(|_| ConfigError::InvalidEndpoint(endpoint.clone()))?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host().is_none()
            || parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(ConfigError::InvalidEndpoint(endpoint));
        }
        self.endpoint = parsed.as_str().trim_end_matches('/').to_owned();
        Ok(self)
    }

    /// The endpoint, with no trailing `/`.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The URL of the method `method` (`encrypt`) on the resource `name`.
    pub fn url(&self, name: &str, method: &str) -> String {
        format!("{}/v1/{name}:{method}", self.endpoint)
    }
}

/// One resource id of a Cloud KMS name: `[A-Za-z0-9._-]`, not `.` or `..`.
/// Only a project id may hold a `:`, because it can be domain-scoped
/// (`example.com:project`); anywhere else a `:` would name a method.
fn is_id(text: &str, project: bool) -> bool {
    !text.is_empty()
        && text.len() <= 128
        && text != "."
        && text != ".."
        && text.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-') || (project && b == b':')
        })
}

/// A crypto key name, `projects/{p}/locations/{l}/keyRings/{r}/cryptoKeys/{k}`,
/// optionally followed by `/cryptoKeyVersions/{n}`.
///
/// Returns the crypto key name and the version, or `None` if `key_ref` is not
/// such a name. The client refuses anything else before any call, so a key
/// reference cannot change the request path.
pub fn parse_key_name(key_ref: &str) -> Option<(&str, Option<u32>)> {
    let parts: Vec<&str> = key_ref.split('/').collect();
    let fixed = ["projects", "locations", "keyRings", "cryptoKeys"];
    if parts.len() != 8 && parts.len() != 10 {
        return None;
    }
    for (index, collection) in fixed.iter().enumerate() {
        if parts[2 * index] != *collection || !is_id(parts[2 * index + 1], index == 0) {
            return None;
        }
    }
    if parts.len() == 8 {
        return Some((key_ref, None));
    }
    let version = parts[9];
    if parts[8] != "cryptoKeyVersions"
        || version.is_empty()
        || version.len() > 10
        || !version.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let version: u32 = version.parse().ok()?;
    let key_len = key_ref.len() - "/cryptoKeyVersions/".len() - parts[9].len();
    Some((&key_ref[..key_len], Some(version)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "projects/p-1/locations/global/keyRings/ring/cryptoKeys/key";

    #[test]
    fn the_endpoint_is_normalised_and_checked() {
        let config = GcpKmsConfig::new();
        assert_eq!(config.endpoint(), DEFAULT_ENDPOINT);
        assert_eq!(
            config.url(KEY, "encrypt"),
            format!("https://cloudkms.googleapis.com/v1/{KEY}:encrypt")
        );
        let config = GcpKmsConfig::new()
            .with_endpoint("http://127.0.0.1:9011/")
            .unwrap();
        assert_eq!(config.endpoint(), "http://127.0.0.1:9011");
        for bad in [
            "cloudkms.googleapis.com",
            "ftp://kms/",
            "https://kms/v1",
            "https://kms/?x=1",
            "https://kms/#x",
            "https://user:pass@kms/",
            "not a url",
        ] {
            assert_eq!(
                GcpKmsConfig::new().with_endpoint(bad),
                Err(ConfigError::InvalidEndpoint(bad.to_owned())),
                "{bad}"
            );
        }
    }

    #[test]
    fn key_names_parse() {
        assert_eq!(parse_key_name(KEY), Some((KEY, None)));
        let version = format!("{KEY}/cryptoKeyVersions/12");
        assert_eq!(parse_key_name(&version), Some((KEY, Some(12))));
        let scoped = "projects/example.com:p/locations/us-east1/keyRings/r_1/cryptoKeys/k-2";
        assert_eq!(parse_key_name(scoped), Some((scoped, None)));
        for bad in [
            "",
            "key",
            "projects/p/locations/l/keyRings/r",
            "projects/p/locations/l/keyRings/r/cryptoKeys/",
            "projects/p/locations/l/keyRings/r/cryptoKeys/k/",
            "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions",
            "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/x",
            "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/99999999999",
            "projects/p/locations/l/keyRings/r/cryptoKeys/k/versions/1",
            "projects/p/locations/l/keyRings/../cryptoKeys/k",
            "projects/p/locations/l/keyRings/r/cryptoKeys/k?x",
            "projects/p/locations/l/keyRings/r/cryptoKeys/k:decrypt",
            "projects/p/locations/l/keyRings/r/cryptoKeys/a b",
            "folders/p/locations/l/keyRings/r/cryptoKeys/k",
            "/projects/p/locations/l/keyRings/r/cryptoKeys/k",
        ] {
            assert_eq!(parse_key_name(bad), None, "{bad:?}");
        }
    }
}
