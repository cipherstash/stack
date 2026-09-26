use url::Url;

use stack_profile::ProfileStore;
#[cfg(not(target_arch = "wasm32"))]
use stack_profile::{FileLockGuard, ProfileData};

use crate::refresher::Refresher;
use crate::transport::SharedTransport;
use crate::{AuthError, SecretToken, Token};

/// Implements [`Refresher`] using OAuth refresh tokens.
///
/// Optionally owns a [`ProfileStore`] for persisting refreshed tokens to disk.
/// When the store is `None`, tokens are cached in memory only. On wasm32 the
/// embedding host must hold the refresh lock across the whole refresh call.
pub(crate) struct DeviceSessionRefresher {
    store: Option<ProfileStore>,
    base_url: Url,
    client_id: String,
    region: String,
    device_instance_id: Option<String>,
    transport: SharedTransport,
}

impl DeviceSessionRefresher {
    pub(crate) fn new(
        store: Option<ProfileStore>,
        base_url: Url,
        client_id: impl Into<String>,
        region: impl Into<String>,
        device_instance_id: Option<String>,
        transport: SharedTransport,
    ) -> Self {
        Self {
            store,
            base_url,
            client_id: client_id.into(),
            region: region.into(),
            device_instance_id,
            transport,
        }
    }
}

impl Refresher for DeviceSessionRefresher {
    type Credential = SecretToken;

    fn save(&self, _token: &Token) {
        // No-op: persistence happens inside `refresh` while the cross-process
        // file lock is held, so a sibling process can't observe a stale
        // refresh token after we've burned it. Saving again here would
        // either be a redundant rewrite of the same content or — worse, if
        // the in-memory and on-disk tokens have diverged — clobber a sibling
        // process's rotation result.
    }

    fn try_credential(&self, token: Option<&mut Token>) -> Option<Self::Credential> {
        token.and_then(|t| t.take_refresh_token())
    }

    fn restore(&self, token: &mut Token, credential: Self::Credential) {
        token.refresh_token = Some(credential);
    }

    async fn refresh(&self, credential: &Self::Credential) -> Result<Token, AuthError> {
        // Cross-process refresh lock: only one process should be exchanging
        // a refresh token with the upstream IdP at a time. Without this,
        // two CLI invocations sharing `~/.cipherstash` both load the same
        // refresh token, both POST `/oauth/token`, and the second one trips
        // Clerk's refresh-token-rotation replay detection — Clerk revokes
        // the entire chain and every subsequent attempt fails with
        // "invalid grant".
        //
        // The lock is held across the HTTP exchange and the on-disk save so
        // a sibling process picks up the rotated token before attempting
        // its own refresh.
        #[cfg(not(target_arch = "wasm32"))]
        let _lock = self.acquire_refresh_lock().await?;
        // On wasm32 this is the host's responsibility: the Go credential
        // binding holds the sibling auth.json lock across its refresh export.
        // WASI preview 1 has no file-lock operation for this arm to call.

        // After acquiring the lock, the disk may already hold a fresher
        // token that another process just rotated to. Burn our (now-stale)
        // credential against Clerk and we'd get "already used"; return the
        // disk copy directly instead.
        if let Some(disk_token) = self.load_freshly_refreshed_token(credential) {
            tracing::debug!(
                "refresh skipped: another process rotated the token while we waited on the lock"
            );
            return Ok(disk_token);
        }

        let mut token = Token::refresh_with(
            &self.transport,
            credential,
            &self.base_url,
            &self.client_id,
            self.device_instance_id.as_deref(),
        )
        .await?;
        token.set_region(&self.region);
        token.set_client_id(&self.client_id);
        if let Some(ref id) = self.device_instance_id {
            token.set_device_instance_id(id);
        }

        // Persist while holding the lock — any sibling process waiting on
        // the lock will read the rotated token on their next attempt and
        // skip burning their stale credential.
        self.persist_refreshed(&token)?;

        Ok(token)
    }
}

impl DeviceSessionRefresher {
    /// Acquire the cross-process refresh lock on `auth.json`, off the async
    /// runtime thread so we don't block other tasks. Returns `None` when no
    /// `ProfileStore` is configured (in-memory refreshers can't race against
    /// other processes since there's no shared state).
    #[cfg(not(target_arch = "wasm32"))]
    async fn acquire_refresh_lock(&self) -> Result<Option<FileLockGuard>, AuthError> {
        let Some(store) = self.store.clone() else {
            return Ok(None);
        };
        let lock = tokio::task::spawn_blocking(move || store.lock_exclusive(Token::FILENAME))
            .await
            .map_err(|e| {
                AuthError::Server(crate::error::ServerError(format!(
                    "refresh lock task join failed: {e}"
                )))
            })?
            .map_err(|e| {
                AuthError::Server(crate::error::ServerError(format!(
                    "failed to acquire refresh lock: {e}"
                )))
            })?;
        Ok(Some(lock))
    }

    /// Returns a token from disk if it has a *different* refresh token than
    /// the stale credential we were about to burn — that's the signature of
    /// another process having already rotated while we waited for the lock.
    /// Returns `None` if there's no on-disk token, it has no refresh token,
    /// or its refresh token still matches our credential (i.e. nothing has
    /// rotated and we genuinely do need to refresh).
    fn load_freshly_refreshed_token(&self, credential: &SecretToken) -> Option<Token> {
        let store = self.store.as_ref()?;
        let disk_token: Token = store.load_profile().ok()?;
        let disk_refresh = disk_token.refresh_token()?;
        if disk_refresh.as_str() != credential.as_str() {
            Some(disk_token)
        } else {
            None
        }
    }

    /// Persist the freshly refreshed token to disk while the lock is held.
    /// A failure here must reach the caller: returning a token while disk
    /// still holds its consumed refresh token would hide a broken rotation.
    fn persist_refreshed(&self, token: &Token) -> Result<(), AuthError> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        store.save_profile(token).map_err(|err| {
            tracing::error!(%err, "failed to persist refreshed token to disk");
            AuthError::from(err)
        })?;
        tracing::debug!("refreshed token saved to disk");
        Ok(())
    }
}

#[cfg(test)]
#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::transport::default_transport;
    use mocktail::prelude::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    const WORKSPACE_ID: &str = "ZVATKW3VHMFG27DY";

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn token_on_disk(access: &str, refresh: &str) -> Token {
        Token {
            access_token: SecretToken::new(access),
            refresh_token: Some(SecretToken::new(refresh)),
            token_type: "Bearer".to_string(),
            expires_at: now() + 3600,
            region: Some("ap-southeast-2.aws".to_string()),
            client_id: Some("cli".to_string()),
            device_instance_id: None,
        }
    }

    async fn start_server(mocks: MockSet) -> MockServer {
        let server = MockServer::new_http("oauth-refresher-lock-test").with_mocks(mocks);
        server.start().await.unwrap();
        server
    }

    fn refresher_with_disk_token(
        dir: &tempfile::TempDir,
        base_url: Url,
        on_disk: Token,
    ) -> DeviceSessionRefresher {
        let store = ProfileStore::new(dir.path());
        store.init_workspace(WORKSPACE_ID).unwrap();
        let ws_store = store.current_workspace_store().unwrap();
        ws_store.save_profile(&on_disk).unwrap();
        DeviceSessionRefresher::new(
            Some(ws_store),
            base_url,
            "cli",
            "ap-southeast-2.aws",
            None,
            default_transport(),
        )
    }

    /// If disk holds a different refresh token than the credential we're
    /// holding, another process has already rotated. We must return the
    /// disk token rather than burning our stale credential against Clerk
    /// (which would respond "already used" and revoke the chain).
    #[tokio::test]
    async fn refresh_returns_disk_token_when_sibling_already_rotated() {
        // Mock server that errors if hit — proves the HTTP refresh is
        // skipped entirely on the lock-and-reload fast path.
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/oauth/token");
            then.bad_request().json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "must not be called"
            }));
        });
        let server = start_server(mocks).await;
        let dir = tempfile::tempdir().unwrap();

        // Disk has v2 (the rotated refresh token); in-memory credential is
        // v1 (stale — the one we'd otherwise replay).
        let disk = token_on_disk("rotated-access", "rotated-refresh");
        let refresher = refresher_with_disk_token(&dir, server.url(""), disk);

        let stale_credential = SecretToken::new("stale-refresh");
        let result = refresher.refresh(&stale_credential).await.unwrap();

        assert_eq!(
            result.access_token().as_str(),
            "rotated-access",
            "refresh should return the disk-cached rotated token"
        );
        assert_eq!(
            result.refresh_token().unwrap().as_str(),
            "rotated-refresh",
            "rotated refresh token from disk should flow through"
        );
    }

    /// If disk holds the *same* refresh token as our credential, no sibling
    /// has rotated and we genuinely need to call Clerk. The refreshed
    /// token must be persisted to disk while the lock is held so a sibling
    /// won't replay it.
    #[tokio::test]
    async fn refresh_calls_upstream_and_persists_when_disk_matches() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/oauth/token");
            then.json(serde_json::json!({
                "access_token": "new-access",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "new-refresh"
            }));
        });
        let server = start_server(mocks).await;
        let dir = tempfile::tempdir().unwrap();

        let disk = token_on_disk("old-access", "matching-refresh");
        let refresher = refresher_with_disk_token(&dir, server.url(""), disk);

        let credential = SecretToken::new("matching-refresh");
        let result = refresher.refresh(&credential).await.unwrap();

        assert_eq!(
            result.access_token().as_str(),
            "new-access",
            "refresh should return the new access token"
        );
        assert_eq!(
            result.refresh_token().unwrap().as_str(),
            "new-refresh",
            "refresh should return the rotated refresh token"
        );
        // The `/oauth/token` response carries neither; the refresher stamps
        // them, and a token without its region cannot derive its workspace
        // CRN on the next load.
        assert_eq!(
            result.region(),
            Some("ap-southeast-2.aws"),
            "refresh should preserve the region"
        );
        assert_eq!(
            result.client_id(),
            Some("cli"),
            "refresh should preserve the client id"
        );

        // Persistence must have happened inside refresh() while the lock
        // was held — so disk now reflects the rotated state.
        let on_disk: Token = ProfileStore::new(dir.path())
            .workspace_store(WORKSPACE_ID)
            .unwrap()
            .load_profile()
            .unwrap();
        assert_eq!(
            on_disk.access_token().as_str(),
            "new-access",
            "the rotated access token should be persisted"
        );
        assert_eq!(
            on_disk.refresh_token().unwrap().as_str(),
            "new-refresh",
            "the rotated refresh token should be persisted"
        );
        assert_eq!(
            on_disk.region(),
            Some("ap-southeast-2.aws"),
            "the region should be persisted"
        );
        assert_eq!(
            on_disk.client_id(),
            Some("cli"),
            "the client id should be persisted"
        );
    }

    /// The refresh response does not echo the device instance (CIP-2793), so
    /// a device-bound refresher re-attaches it: the next refresh has to
    /// present the same instance, and it reads it from this token.
    #[tokio::test]
    async fn refresh_carries_the_device_instance_through() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/oauth/token");
            then.json(serde_json::json!({
                "access_token": "new-access",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "new-refresh"
            }));
        });
        let server = start_server(mocks).await;
        let dir = tempfile::tempdir().unwrap();

        let store = ProfileStore::new(dir.path());
        store.init_workspace(WORKSPACE_ID).unwrap();
        let ws_store = store.current_workspace_store().unwrap();
        ws_store
            .save_profile(&token_on_disk("old-access", "matching-refresh"))
            .unwrap();
        let refresher = DeviceSessionRefresher::new(
            Some(ws_store),
            server.url(""),
            "cli",
            "ap-southeast-2.aws",
            Some("device-7".to_string()),
            default_transport(),
        );

        let result = refresher
            .refresh(&SecretToken::new("matching-refresh"))
            .await
            .unwrap();
        assert_eq!(
            result.device_instance_id(),
            Some("device-7"),
            "refresh should preserve the device instance"
        );

        let on_disk: Token = ProfileStore::new(dir.path())
            .workspace_store(WORKSPACE_ID)
            .unwrap()
            .load_profile()
            .unwrap();
        assert_eq!(
            on_disk.device_instance_id(),
            Some("device-7"),
            "the rotated token on disk should keep the device instance"
        );
    }

    /// Concurrent in-process calls to `refresh` must not produce a stale
    /// replay. The first to acquire the lock rotates; the second sees the
    /// disk has changed and returns the disk token without burning its
    /// stale credential. Verified by upstream call counter.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_refreshes_only_call_upstream_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);
        let app = axum::Router::new().route(
            "/oauth/token",
            axum::routing::post(move || {
                let counter = Arc::clone(&counter_clone);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    // Small delay so the second caller is reliably waiting
                    // on the lock while we serve this response.
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    axum::Json(serde_json::json!({
                        "access_token": "rotated-access",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                        "refresh_token": "rotated-refresh"
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let base_url = Url::parse(&format!("http://{addr}")).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(dir.path());
        store.init_workspace(WORKSPACE_ID).unwrap();
        let ws_store = store.current_workspace_store().unwrap();
        ws_store
            .save_profile(&token_on_disk("old-access", "shared-refresh"))
            .unwrap();

        // Two separate DeviceSessionRefresher instances sharing the same on-disk
        // profile — same shape as two processes with the same ~/.cipherstash.
        let r1 = Arc::new(DeviceSessionRefresher::new(
            Some(ws_store.clone()),
            base_url.clone(),
            "cli",
            "ap-southeast-2.aws",
            None,
            default_transport(),
        ));
        let r2 = Arc::new(DeviceSessionRefresher::new(
            Some(ws_store),
            base_url,
            "cli",
            "ap-southeast-2.aws",
            None,
            default_transport(),
        ));

        let cred1 = SecretToken::new("shared-refresh");
        let cred2 = SecretToken::new("shared-refresh");

        let r1c = Arc::clone(&r1);
        let h1 = tokio::spawn(async move { r1c.refresh(&cred1).await });
        let r2c = Arc::clone(&r2);
        let h2 = tokio::spawn(async move { r2c.refresh(&cred2).await });

        let (a, b) = tokio::join!(h1, h2);
        let a = a.unwrap().unwrap();
        let b = b.unwrap().unwrap();

        assert_eq!(a.access_token().as_str(), "rotated-access");
        assert_eq!(b.access_token().as_str(), "rotated-access");
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "exactly one upstream refresh — the second caller must take the lock-and-reload fast path"
        );
    }
}
