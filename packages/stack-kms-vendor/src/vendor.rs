//! The vendor seam: what a key vendor backend must provide.

use std::future::Future;
use std::time::Duration;

use stack_kms::{Error, KeyVendor, MaybeSend};
use vitaminc::protected::Protected;
use vitaminc::random::{Generatable, SafeRand};

/// A 256-bit key, wiped when it drops: a root key, an index key or a data
/// key, in the clear.
pub type KeyBytes = Protected<[u8; 32]>;

/// What a key vendor backend must provide: wrap and unwrap a key under a
/// vendor key, with associated data.
///
/// This is the whole contract of a vendor. The adapter
/// ([`VendorKeySource`](crate::VendorKeySource)) builds the derived data key
/// mode, the keyset records and the root key TTL on top of it, so a vendor
/// crate (`stack-kms-aws` and so on) implements this trait and never
/// implements [`DataKeySource`](stack_kms::DataKeySource) or
/// [`IndexKeySource`](stack_kms::IndexKeySource) itself.
///
/// # Rules for an implementation
///
/// * **Bind the associated data.** `unwrap` must fail unless `aad` is the
///   `aad` given to `wrap`. A vendor with native associated data (AWS KMS
///   encryption context, Google Cloud KMS `additionalAuthenticatedData`)
///   passes it through. A vendor without it (Azure Managed HSM), or with it
///   on some keys or versions only (Vault Transit), must bind it some other
///   way: wrap the bound key of
///   [`bound::bind_key`](crate::bound::bind_key) in place of the key, and
///   open it with [`bound::open_bound_key`](crate::bound::open_bound_key).
/// * **Report failures as [`Error::Backend`]**, with
///   this vendor ([`vendor`](Self::vendor)) as `backend` and the nearest
///   [`BackendErrorKind`](stack_kms::BackendErrorKind). A wrong key, a wrong
///   `aad` or damaged bytes is `InvalidCiphertext`. A rate limit is
///   `Throttled`: the adapter backs off and retries it. Never put key
///   material or plaintext in an error.
/// * **`key_ref` is the versioned vendor key reference** from the keyset
///   record (an AWS key ARN, a Vault key name, a Google Cloud KMS crypto
///   key name, an Azure key id). Its format is the vendor's. A vendor key
///   that rotates behind one name is versioned by the vendor: its
///   ciphertexts name the version that made them.
pub trait KeyVendorBackend: Send + Sync {
    /// Which key vendor backend this is.
    fn vendor(&self) -> KeyVendor;

    /// Wrap `key` under the vendor key `key_ref`, binding `aad`.
    fn wrap(
        &self,
        key_ref: &str,
        key: &KeyBytes,
        aad: &[u8],
    ) -> impl Future<Output = Result<Vec<u8>, Error>> + MaybeSend;

    /// Unwrap `wrapped` under the vendor key `key_ref`. Fails unless `aad`
    /// is the `aad` the key was wrapped with.
    fn unwrap(
        &self,
        key_ref: &str,
        wrapped: &[u8],
        aad: &[u8],
    ) -> impl Future<Output = Result<KeyBytes, Error>> + MaybeSend;

    /// Wait for `duration` before a retry.
    ///
    /// The adapter calls this to back off after a `Throttled` failure. The
    /// default returns at once, because this crate has no timer of its own
    /// and must run on native Rust and in the WASI guest alike. A vendor
    /// overrides it with its transport's timer
    /// ([`VendorTransport::sleep`](crate::VendorTransport::sleep)).
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + MaybeSend {
        let _ = duration;
        std::future::ready(())
    }
}

/// A fresh random 256-bit key, from the CSPRNG.
pub(crate) fn random_key(vendor: KeyVendor) -> Result<KeyBytes, Error> {
    let mut rng = SafeRand::from_entropy().map_err(|error| Error::Backend {
        backend: vendor.into(),
        kind: stack_kms::BackendErrorKind::Unavailable,
        source: Box::new(error),
    })?;
    KeyBytes::random(&mut rng).map_err(|error| Error::Backend {
        backend: vendor.into(),
        kind: stack_kms::BackendErrorKind::Unavailable,
        source: Box::new(error),
    })
}

/// Fresh random bytes, from the CSPRNG.
pub(crate) fn random_bytes<const N: usize>(vendor: KeyVendor) -> Result<[u8; N], Error> {
    let mut rng = SafeRand::from_entropy().map_err(|error| Error::Backend {
        backend: vendor.into(),
        kind: stack_kms::BackendErrorKind::Unavailable,
        source: Box::new(error),
    })?;
    <[u8; N]>::random(&mut rng).map_err(|error| Error::Backend {
        backend: vendor.into(),
        kind: stack_kms::BackendErrorKind::Unavailable,
        source: Box::new(error),
    })
}
