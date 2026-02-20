use crate::{AuthStrategy, SecretToken, Token};
use std::path::{Path, PathBuf};

/// Errors that can occur when reading or writing the token store.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TokenStoreError {
    /// An I/O error occurred while reading or writing the token file.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The token file contained invalid JSON.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// The user's home directory could not be determined.
    #[error("Could not determine home directory")]
    HomeDirNotFound,
    /// No token was found in the store.
    #[error("No token found")]
    NotFound,
    /// The token has expired.
    #[error("Token has expired")]
    Expired,
}

/// Persists and loads tokens from a JSON file on disk.
///
/// The default location is `~/.cipherstash/auth.json`.
pub struct TokenStore {
    path: PathBuf,
}

impl TokenStore {
    /// Returns the default token store location: `~/.cipherstash/auth.json`.
    pub fn default_location() -> Result<PathBuf, TokenStoreError> {
        let home = dirs::home_dir().ok_or(TokenStoreError::HomeDirNotFound)?;
        Ok(home.join(".cipherstash").join("auth.json"))
    }

    /// Create a token store at the default location (`~/.cipherstash/auth.json`).
    pub fn new_default() -> Result<Self, TokenStoreError> {
        Ok(Self {
            path: Self::default_location()?,
        })
    }

    /// Create a token store at a custom path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Returns the path to the token file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Save a [`Token`] to disk.
    ///
    /// Creates parent directories if they don't exist.
    pub fn save(&self, token: &Token) -> Result<(), TokenStoreError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(token)?;
        std::fs::write(&self.path, json)?;
        Ok(())
    }

    /// Load a [`Token`] from disk.
    ///
    /// Returns `None` if the file does not exist.
    pub fn load(&self) -> Result<Option<Token>, TokenStoreError> {
        match std::fs::read_to_string(&self.path) {
            Ok(contents) => {
                let token: Token = serde_json::from_str(&contents)?;
                Ok(Some(token))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(TokenStoreError::Io(e)),
        }
    }

    /// Remove the token file from disk.
    ///
    /// Does nothing if the file does not already exist.
    pub fn clear(&self) -> Result<(), TokenStoreError> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(TokenStoreError::Io(e)),
        }
    }
}

/// An [`AuthStrategy`] that loads a token from a [`TokenStore`] and caches it in memory.
///
/// The token is loaded from disk on the first call to [`get_token`](AuthStrategy::get_token)
/// and cached for subsequent calls.
pub struct TokenStoreStrategy {
    store: TokenStore,
    cached: tokio::sync::OnceCell<Token>,
}

impl TokenStoreStrategy {
    /// Create a new `TokenStoreStrategy` backed by the given [`TokenStore`].
    pub fn new(store: TokenStore) -> Self {
        Self {
            store,
            cached: tokio::sync::OnceCell::new(),
        }
    }
}

impl<'a> AuthStrategy<'a> for &'a TokenStoreStrategy {
    type Error = TokenStoreError;

    async fn get_token(self) -> Result<&'a SecretToken, Self::Error> {
        let token = self
            .cached
            .get_or_try_init(|| async { self.store.load()?.ok_or(TokenStoreError::NotFound) })
            .await?;
        if token.is_expired() {
            return Err(TokenStoreError::Expired);
        }
        Ok(token.access_token())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecretToken;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn make_token(expires_in: u64, refresh: bool) -> Token {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Token {
            access_token: SecretToken::new("test-access-token"),
            token_type: "Bearer".to_string(),
            expires_at: now + expires_in,
            refresh_token: if refresh {
                Some(SecretToken::new("test-refresh-token"))
            } else {
                None
            },
        }
    }

    #[test]
    fn round_trip_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let store = TokenStore::new(dir.path().join("auth.json"));

        let token = make_token(3600, false);
        store.save(&token).unwrap();

        let loaded = store.load().unwrap().unwrap();
        assert_eq!(loaded.access_token().as_str(), "test-access-token");
        assert_eq!(loaded.token_type(), "Bearer");
        assert!(loaded.refresh_token().is_none());
    }

    #[test]
    fn expires_at_is_set_correctly() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let token = make_token(3600, false);

        let diff = token.expires_at().abs_diff(now + 3600);
        assert!(diff <= 2, "expires_at should be ~now+3600, diff was {diff}");
    }

    #[test]
    fn expires_in_computes_remaining_time() {
        let token = make_token(3600, false);
        let remaining = token.expires_in();
        assert!(
            (3598..=3600).contains(&remaining),
            "expires_in should be ~3600, got {remaining}"
        );
    }

    #[test]
    fn is_expired_for_fresh_token() {
        let token = make_token(3600, false);
        assert!(!token.is_expired());
    }

    #[test]
    fn is_expired_for_expired_token() {
        let token = make_token(0, false);
        assert!(token.is_expired());
    }

    #[test]
    fn load_returns_none_for_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = TokenStore::new(dir.path().join("nonexistent.json"));

        let result = store.load().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn clear_removes_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = TokenStore::new(dir.path().join("auth.json"));

        let token = make_token(3600, false);
        store.save(&token).unwrap();
        assert!(store.path().exists());

        store.clear().unwrap();
        assert!(!store.path().exists());
    }

    #[test]
    fn clear_succeeds_for_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = TokenStore::new(dir.path().join("nonexistent.json"));
        store.clear().unwrap();
    }

    #[test]
    fn save_creates_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        let store = TokenStore::new(dir.path().join("nested").join("dir").join("auth.json"));

        let token = make_token(3600, false);
        store.save(&token).unwrap();

        let loaded = store.load().unwrap().unwrap();
        assert_eq!(loaded.access_token().as_str(), "test-access-token");
    }

    #[test]
    fn refresh_token_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let store = TokenStore::new(dir.path().join("auth.json"));

        let token = make_token(3600, true);
        store.save(&token).unwrap();

        let loaded = store.load().unwrap().unwrap();
        assert_eq!(
            loaded.refresh_token().unwrap().as_str(),
            "test-refresh-token"
        );
    }

    #[test]
    fn debug_output_does_not_leak_secrets() {
        let token = make_token(3600, true);
        let debug = format!("{:?}", token);
        assert!(
            !debug.contains("test-access-token"),
            "Debug output should not contain access token, got: {debug}"
        );
        assert!(
            !debug.contains("test-refresh-token"),
            "Debug output should not contain refresh token, got: {debug}"
        );
    }
}
