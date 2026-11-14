//! An in-memory key vendor backend for tests.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use stack_kms::{BackendErrorKind, Error, KeyVendor};
use vitaminc::protected::Protected;

use crate::static_key::StaticKeyVendor;
use crate::vendor::{KeyBytes, KeyVendorBackend};

/// How many calls a [`FakeVendor`] has answered, by operation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FakeVendorCalls {
    /// Calls to [`wrap`](KeyVendorBackend::wrap).
    pub wrap: usize,
    /// Calls to [`unwrap`](KeyVendorBackend::unwrap).
    pub unwrap: usize,
    /// Calls refused as throttled.
    pub throttled: usize,
}

/// An in-memory key vendor backend, for tests
/// and for the [contract suite](crate::contract).
///
/// It wraps with AES-256-GCM under in-memory vendor keys, as
/// [`StaticKeyVendor`] does, but reports itself as the vendor it was built
/// with, counts its calls, can refuse the next calls as throttled, and
/// records the waits the adapter asks for. It does no I/O.
pub struct FakeVendor {
    vendor: KeyVendor,
    inner: StaticKeyVendor,
    wraps: AtomicUsize,
    unwraps: AtomicUsize,
    throttled: AtomicUsize,
    throttle_next: AtomicUsize,
    sleeps: Mutex<Vec<Duration>>,
}

impl std::fmt::Debug for FakeVendor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeVendor")
            .field("vendor", &self.vendor)
            .field("calls", &self.calls())
            .finish()
    }
}

impl FakeVendor {
    /// The vendor key reference every fake vendor holds.
    pub const KEY_REF: &'static str = "fake-key/v1";

    /// A fake that reports itself as `vendor`, with one vendor key,
    /// [`KEY_REF`](Self::KEY_REF).
    pub fn new(vendor: KeyVendor) -> Self {
        Self {
            vendor,
            inner: StaticKeyVendor::new(Self::KEY_REF, Protected::new([0x5au8; 32])),
            wraps: AtomicUsize::new(0),
            unwraps: AtomicUsize::new(0),
            throttled: AtomicUsize::new(0),
            throttle_next: AtomicUsize::new(0),
            sleeps: Mutex::new(Vec::new()),
        }
    }

    /// Add another vendor key, for rewrap tests.
    pub fn with_key(mut self, key_ref: &str, key: KeyBytes) -> Self {
        self.inner = self.inner.with_key(key_ref, key);
        self
    }

    /// Refuse the next `count` calls as throttled.
    pub fn throttle_next(&self, count: usize) {
        self.throttle_next.store(count, Ordering::SeqCst);
    }

    /// The calls answered so far.
    pub fn calls(&self) -> FakeVendorCalls {
        FakeVendorCalls {
            wrap: self.wraps.load(Ordering::SeqCst),
            unwrap: self.unwraps.load(Ordering::SeqCst),
            throttled: self.throttled.load(Ordering::SeqCst),
        }
    }

    /// The waits the adapter asked for, in order.
    pub fn sleeps(&self) -> Vec<Duration> {
        self.sleeps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Refuse this call as throttled if a throttle is pending.
    fn throttle(&self) -> Result<(), Error> {
        let pending = self
            .throttle_next
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1));
        if pending.is_ok() {
            let _ = self.throttled.fetch_add(1, Ordering::SeqCst);
            return Err(Error::Backend {
                backend: self.vendor.into(),
                kind: BackendErrorKind::Throttled,
                source: "the fake vendor is throttling".into(),
            });
        }
        Ok(())
    }

    /// Report the inner static vendor's failure as this vendor's.
    fn rename(&self, error: Error) -> Error {
        match error {
            Error::Backend { kind, source, .. } => Error::Backend {
                backend: self.vendor.into(),
                kind,
                source,
            },
            other => other,
        }
    }
}

impl KeyVendorBackend for FakeVendor {
    fn vendor(&self) -> KeyVendor {
        self.vendor
    }

    async fn wrap(&self, key_ref: &str, key: &KeyBytes, aad: &[u8]) -> Result<Vec<u8>, Error> {
        self.throttle()?;
        let _ = self.wraps.fetch_add(1, Ordering::SeqCst);
        self.inner
            .wrap(key_ref, key, aad)
            .await
            .map_err(|error| self.rename(error))
    }

    async fn unwrap(&self, key_ref: &str, wrapped: &[u8], aad: &[u8]) -> Result<KeyBytes, Error> {
        self.throttle()?;
        let _ = self.unwraps.fetch_add(1, Ordering::SeqCst);
        self.inner
            .unwrap(key_ref, wrapped, aad)
            .await
            .map_err(|error| self.rename(error))
    }

    async fn sleep(&self, duration: Duration) {
        self.sleeps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(duration);
    }
}
