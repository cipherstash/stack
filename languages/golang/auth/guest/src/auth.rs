//! Auth strategies retained inside one credential guest instance. The Go
//! package constructs typed sources; this registry owns the Rust strategies
//! and their cached CTS tokens until a source or the guest is closed.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

use cts_common::Crn;
use futures::executor::block_on;
use serde::Deserialize;
use stack_auth::{
    AccessKey, AccessKeyStrategy, AuthStrategy, DeviceSessionStrategy, OidcFederationStrategy,
    Token,
};
use stack_profile::ProfileStore;
use zeroize::Zeroizing;

use crate::host::{HostOidcProvider, WasiAuthTransport};
use stack_auth::AuthError;
use stack_guest_abi::last_error::{malformed, out_of_order};

use crate::status::{fail_auth, fail_profile, STATUS_AUTH_REFRESH_REQUIRED};

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Config {
    AccessKey {
        crn: String,
        access_key: String,
        base_url: Option<String>,
    },
    Oidc {
        crn: String,
        provider: u32,
        base_url: Option<String>,
        /// How many distinct JWTs keep a CTS token; the strategy's default
        /// when absent. See `auth.WithCacheCapacity`.
        cache_capacity: Option<usize>,
    },
    DeviceSession {
        workspace_dir: String,
        base_url: Option<String>,
    },
}

enum Strategy {
    AccessKey(AccessKeyStrategy),
    Oidc(OidcFederationStrategy<HostOidcProvider>),
    // A device session is rebuilt for refresh only after Go has acquired the
    // cross-process lock. A fresh token can be read without the lock; keeping
    // a cached Token here would defeat the post-lock re-read on refresh.
    DeviceSession {
        workspace_dir: String,
        base_url: Option<url::Url>,
    },
}

thread_local! {
    static STRATEGIES: RefCell<HashMap<u32, Strategy>> = RefCell::new(HashMap::new());
    static NEXT: Cell<u32> = const { Cell::new(1) };
}

fn parse_base_url(value: Option<String>) -> Result<Option<url::Url>, u32> {
    value
        .map(|v| {
            v.parse::<url::Url>()
                .map_err(|_| malformed("the strategy config's base_url is not a URL"))
        })
        .transpose()
}

pub fn validate_crn(bytes: &[u8]) -> Result<Vec<u8>, u32> {
    let text = std::str::from_utf8(bytes).map_err(|_| malformed("the CRN is not UTF-8"))?;
    let _: Crn = text.parse().map_err(|e| fail_auth(&AuthError::from(e)))?;
    Ok(Vec::new())
}

// A CRN or access key that does not parse is a configuration error, the
// class Rust's `AutoStrategy` reports (`INVALID_CRN`, `INVALID_ACCESS_KEY`)
// and the one `validate_crn` already uses. `STATUS_ENCODING` is kept for the
// JSON envelope itself.

pub fn create(config: &[u8]) -> Result<Vec<u8>, u32> {
    // Never serde_json's message: it can quote the config, which carries
    // the access key.
    let config: Config = serde_json::from_slice(config)
        .map_err(|_| malformed("the strategy config is not a JSON object of the expected shape"))?;
    let strategy = match config {
        Config::AccessKey {
            crn,
            access_key,
            base_url,
        } => {
            let access_key = Zeroizing::new(access_key);
            let crn: Crn = crn.parse().map_err(|e| fail_auth(&AuthError::from(e)))?;
            let key: AccessKey = access_key
                .parse()
                .map_err(|e| fail_auth(&AuthError::from(e)))?;
            let mut builder = AccessKeyStrategy::builder(crn, key).transport(WasiAuthTransport);
            if let Some(url) = parse_base_url(base_url)? {
                builder = builder.base_url(url);
            }
            Strategy::AccessKey(builder.build().map_err(|e| fail_auth(&e))?)
        }
        Config::Oidc {
            crn,
            provider,
            base_url,
            cache_capacity,
        } => {
            let crn: Crn = crn.parse().map_err(|e| fail_auth(&AuthError::from(e)))?;
            let mut builder = OidcFederationStrategy::builder(crn, HostOidcProvider(provider))
                .transport(WasiAuthTransport);
            if let Some(url) = parse_base_url(base_url)? {
                builder = builder.base_url(url);
            }
            if let Some(capacity) = cache_capacity {
                builder = builder.cache_capacity(capacity);
            }
            Strategy::Oidc(builder.build().map_err(|e| fail_auth(&e))?)
        }
        Config::DeviceSession {
            workspace_dir,
            base_url,
        } => {
            if workspace_dir.is_empty() {
                return Err(malformed("the strategy config's workspace_dir is empty"));
            }
            Strategy::DeviceSession {
                workspace_dir,
                base_url: parse_base_url(base_url)?,
            }
        }
    };
    let id = NEXT.with(|next| {
        let id = next.get();
        next.set(id.wrapping_add(1).max(1));
        id
    });
    STRATEGIES.with(|items| {
        let _ = items.borrow_mut().insert(id, strategy);
    });
    Ok(id.to_string().into_bytes())
}

fn parse_handle(bytes: &[u8]) -> Result<u32, u32> {
    let refuse = || malformed("a strategy handle is not a decimal number");
    let text = std::str::from_utf8(bytes).map_err(|_| refuse())?;
    text.parse::<u32>().map_err(|_| refuse())
}

pub fn token(handle: &[u8]) -> Result<Vec<u8>, u32> {
    let id = parse_handle(handle)?;
    STRATEGIES.with(|items| {
        let items = items.borrow();
        let strategy = items.get(&id).ok_or_else(no_strategy)?;
        match strategy {
            Strategy::AccessKey(strategy) => block_on(strategy.get_token())
                .map(|token| token.as_str().as_bytes().to_vec())
                .map_err(|e| fail_auth(&e)),
            Strategy::Oidc(strategy) => block_on(strategy.get_token())
                .map(|token| token.as_str().as_bytes().to_vec())
                .map_err(|e| fail_auth(&e)),
            Strategy::DeviceSession {
                workspace_dir,
                base_url,
            } => cached_device_token(workspace_dir, base_url),
        }
    })
}

/// A fresh token needs only a profile read. The 90-second refresh window is
/// decided by stack-auth's Token, so Go does not duplicate that rule.
fn cached_device_token(workspace_dir: &str, base_url: &Option<url::Url>) -> Result<Vec<u8>, u32> {
    let token: Token = ProfileStore::new(workspace_dir)
        .load_profile()
        .map_err(|e| fail_profile(&e))?;
    if token.region().is_none() || token.client_id().is_none() {
        return Err(fail_auth(&stack_auth::NotAuthenticated.into()));
    }
    if base_url.is_none() {
        let _ = token.issuer().map_err(|e| fail_auth(&e))?;
    }
    if token.is_expired() {
        return Err(STATUS_AUTH_REFRESH_REQUIRED);
    }
    Ok(token.access_token().as_str().as_bytes().to_vec())
}

/// Called only after Go acquires the profile lock. Building from the store
/// here re-reads a token another process may have rotated while Go waited.
pub fn refresh(handle: &[u8]) -> Result<Vec<u8>, u32> {
    let id = parse_handle(handle)?;
    STRATEGIES.with(|items| {
        let items = items.borrow();
        let Strategy::DeviceSession {
            workspace_dir,
            base_url,
        } = items.get(&id).ok_or_else(no_strategy)?
        else {
            return Err(out_of_order("only a device session strategy refreshes"));
        };
        let store = ProfileStore::new(workspace_dir);
        let mut builder =
            DeviceSessionStrategy::with_workspace_store(store).transport(WasiAuthTransport);
        if let Some(url) = base_url {
            builder = builder.base_url(url.clone());
        }
        let strategy = builder.build().map_err(|e| fail_auth(&e))?;
        let token = block_on(strategy.get_token()).map_err(|e| fail_auth(&e))?;
        Ok(token.as_str().as_bytes().to_vec())
    })
}

pub fn free(handle: &[u8]) -> Result<Vec<u8>, u32> {
    let id = parse_handle(handle)?;
    STRATEGIES.with(|items| {
        let _removed = items.borrow_mut().remove(&id).ok_or_else(no_strategy)?;
        Ok(Vec::new())
    })
}

/// A handle that names no live strategy: never created, or already freed.
fn no_strategy() -> u32 {
    out_of_order("no strategy has this handle: it was never created, or was freed")
}

pub fn clear() {
    STRATEGIES.with(|items| items.borrow_mut().clear());
}
