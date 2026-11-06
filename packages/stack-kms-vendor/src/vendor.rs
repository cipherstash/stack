//! The vendor seam: what a key vendor backend must provide.

use std::future::Future;
use std::num::NonZeroUsize;
use std::time::Duration;

use stack_kms::{Error, KeyMode, KeyVendor, MaybeSend};
use vitaminc::protected::Protected;
use vitaminc::random::{Generatable, SafeRand};

/// A 256-bit key, wiped when it drops: a root key, an index key or a data
/// key, in the clear.
pub type KeyBytes = Protected<[u8; 32]>;

/// What a key vendor backend must provide: wrap and unwrap a key under a
/// vendor key, with associated data.
///
/// This is the whole contract of a vendor. The adapter
/// ([`VendorKeySource`](crate::VendorKeySource)) builds both key modes, the
/// keyset records, key lifetime and batching on top of it, so a vendor
/// crate (`stack-kms-aws` and so on) implements this trait and never
/// implements [`DataKeySource`](stack_kms::DataKeySource) or
/// [`IndexKeySource`](stack_kms::IndexKeySource) itself.
///
/// # Rules for an implementation
///
/// * **Bind the associated data.** `unwrap` must fail unless `aad` is the
///   `aad` given to `wrap`. A vendor with native associated data (AWS KMS
///   encryption context, Vault Transit `associated_data`, Google Cloud KMS
///   `additionalAuthenticatedData`) passes it through. A vendor without it
///   must bind it some other way: wrap the bound key of
///   [`bound::bind_key`](crate::bound::bind_key) in place of the key, and
///   open it with [`bound::open_bound_key`](crate::bound::open_bound_key).
/// * **Report failures as [`Error::Backend`]**, with
///   [`KeyVendor::name`] as `vendor` and the nearest
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

    /// Whether this vendor offers `mode`. The default is both modes. The
    /// static key backend offers derived data keys only.
    fn supports_mode(&self, mode: KeyMode) -> bool {
        let _ = mode;
        true
    }

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

    /// Generate a fresh data key and wrap it under `key_ref`, binding `aad`.
    /// Returns the key and its wrapped form.
    ///
    /// The default generates the key locally with a CSPRNG and calls
    /// [`wrap`](Self::wrap): one vendor call either way. A vendor with a
    /// native operation (AWS `GenerateDataKey`) may override it.
    fn generate_wrapped(
        &self,
        key_ref: &str,
        aad: &[u8],
    ) -> impl Future<Output = Result<(KeyBytes, Vec<u8>), Error>> + MaybeSend {
        async move {
            let key = random_key(self.vendor())?;
            let wrapped = self.wrap(key_ref, &key, aad).await?;
            Ok((key, wrapped))
        }
    }

    /// The most keys one [`wrap_batch`](Self::wrap_batch) or
    /// [`unwrap_batch`](Self::unwrap_batch) call takes, or `None` (the
    /// default) when the vendor has no batch operation.
    ///
    /// When it is `Some(n)`, the adapter wraps and unwraps the wrapped data
    /// keys of a batch in chunks of at most `n` keys, one batch call per
    /// chunk, and generates each data key locally with the CSPRNG. When it
    /// is `None`, the adapter makes one call per key
    /// ([`generate_wrapped`](Self::generate_wrapped) or
    /// [`unwrap`](Self::unwrap)). The keyset record key is always one
    /// [`unwrap`](Self::unwrap) call.
    fn batch_limit(&self) -> Option<NonZeroUsize> {
        None
    }

    /// Wrap each key under `key_ref`, binding its associated data, in one
    /// vendor call. Returns the wrapped keys in the order of `items`.
    ///
    /// The adapter calls it only when [`batch_limit`](Self::batch_limit) is
    /// `Some(n)`, with at most `n` items. The rules of
    /// [`wrap`](Self::wrap) apply to each item. A batch fails whole: return
    /// the first failure. The default wraps the items one at a time.
    fn wrap_batch(
        &self,
        key_ref: &str,
        items: &[WrapItem<'_>],
    ) -> impl Future<Output = Result<Vec<Vec<u8>>, Error>> + MaybeSend {
        async move {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(self.wrap(key_ref, item.key, item.aad).await?);
            }
            Ok(out)
        }
    }

    /// Unwrap each wrapped key under `key_ref`, in one vendor call. Returns
    /// the keys in the order of `items`.
    ///
    /// The adapter calls it only when [`batch_limit`](Self::batch_limit) is
    /// `Some(n)`, with at most `n` items. The rules of
    /// [`unwrap`](Self::unwrap) apply to each item. A batch fails whole:
    /// return the first failure. The default unwraps the items one at a
    /// time.
    fn unwrap_batch(
        &self,
        key_ref: &str,
        items: &[UnwrapItem<'_>],
    ) -> impl Future<Output = Result<Vec<KeyBytes>, Error>> + MaybeSend {
        async move {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(self.unwrap(key_ref, item.wrapped, item.aad).await?);
            }
            Ok(out)
        }
    }

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

/// One key of a [`KeyVendorBackend::wrap_batch`] call.
#[derive(Clone, Copy)]
pub struct WrapItem<'a> {
    /// The key to wrap.
    pub key: &'a KeyBytes,
    /// The associated data to bind.
    pub aad: &'a [u8],
}

impl std::fmt::Debug for WrapItem<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WrapItem")
            .field("aad_len", &self.aad.len())
            .finish_non_exhaustive()
    }
}

/// One wrapped key of a [`KeyVendorBackend::unwrap_batch`] call.
#[derive(Clone, Copy, Debug)]
pub struct UnwrapItem<'a> {
    /// The wrapped key.
    pub wrapped: &'a [u8],
    /// The associated data it was wrapped with.
    pub aad: &'a [u8],
}

/// A fresh random 256-bit key, from the CSPRNG.
pub(crate) fn random_key(vendor: KeyVendor) -> Result<KeyBytes, Error> {
    let mut rng = SafeRand::from_entropy().map_err(|error| Error::Backend {
        vendor: vendor.name(),
        kind: stack_kms::BackendErrorKind::Unavailable,
        source: Box::new(error),
    })?;
    KeyBytes::random(&mut rng).map_err(|error| Error::Backend {
        vendor: vendor.name(),
        kind: stack_kms::BackendErrorKind::Unavailable,
        source: Box::new(error),
    })
}

/// Fresh random bytes, from the CSPRNG.
pub(crate) fn random_bytes<const N: usize>(vendor: KeyVendor) -> Result<[u8; N], Error> {
    let mut rng = SafeRand::from_entropy().map_err(|error| Error::Backend {
        vendor: vendor.name(),
        kind: stack_kms::BackendErrorKind::Unavailable,
        source: Box::new(error),
    })?;
    <[u8; N]>::random(&mut rng).map_err(|error| Error::Backend {
        vendor: vendor.name(),
        kind: stack_kms::BackendErrorKind::Unavailable,
        source: Box::new(error),
    })
}
