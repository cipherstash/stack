//! The static key backend: a key held in memory.

use std::collections::BTreeMap;
use std::fmt;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use stack_kms::{BackendErrorKind, Error, KeyMode, KeyVendor};
use vitaminc::protected::{Controlled, Protected};
use zeroize::Zeroizing;

use crate::vendor::{random_bytes, KeyBytes, KeyVendorBackend};

/// The first byte of every key the static key backend wraps.
const WRAP_VERSION: u8 = 1;
/// The AES-GCM nonce length.
const NONCE_LEN: usize = 12;

/// The static key backend ([`KeyVendor::Static`]): a 256-bit vendor key
/// held in the application's memory.
///
/// **For development, or for customers who manage the key themselves.**
/// The vendor key is always in memory, so there is no vendor that can see
/// or refuse an unwrap. For that reason it offers derived data keys only
/// (ADR-0009): [`KeysetRecord::create`](crate::KeysetRecord::create)
/// refuses wrapped data keys with
/// [`RecordError::ModeUnsupported`](crate::RecordError::ModeUnsupported).
///
/// Each vendor key has a reference (`key_ref`), which the keyset record
/// stores. Hold more than one key ([`with_key`](Self::with_key)) to rotate:
/// rewrap each record under the new reference, then drop the old key.
///
/// A key is wrapped with AES-256-GCM under a random 96-bit nonce, with the
/// associated data bound: `version (1) ‖ nonce (12) ‖ ciphertext ‖ tag`.
pub struct StaticKeyVendor {
    keys: BTreeMap<String, KeyBytes>,
}

impl fmt::Debug for StaticKeyVendor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaticKeyVendor")
            .field("key_refs", &self.keys.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl StaticKeyVendor {
    /// A static key backend with one vendor key, named `key_ref`.
    pub fn new(key_ref: impl Into<String>, key: KeyBytes) -> Self {
        Self {
            keys: BTreeMap::new(),
        }
        .with_key(key_ref, key)
    }

    /// Add another vendor key, named `key_ref`. A key of the same name is
    /// replaced.
    pub fn with_key(mut self, key_ref: impl Into<String>, key: KeyBytes) -> Self {
        let _ = self.keys.insert(key_ref.into(), key);
        self
    }

    fn cipher(&self, key_ref: &str) -> Result<Aes256Gcm, Error> {
        let key = self.keys.get(key_ref).ok_or_else(|| {
            failure(
                BackendErrorKind::NotFound,
                "no static key has this reference",
            )
        })?;
        Aes256Gcm::new_from_slice(key.risky_ref()).map_err(|_| {
            failure(
                BackendErrorKind::NotFound,
                "the static key has a bad length",
            )
        })
    }
}

fn failure(kind: BackendErrorKind, message: &'static str) -> Error {
    Error::Backend {
        backend: KeyVendor::Static.into(),
        kind,
        source: message.into(),
    }
}

impl KeyVendorBackend for StaticKeyVendor {
    fn vendor(&self) -> KeyVendor {
        KeyVendor::Static
    }

    fn supports_mode(&self, mode: KeyMode) -> bool {
        mode == KeyMode::Derived
    }

    async fn wrap(&self, key_ref: &str, key: &KeyBytes, aad: &[u8]) -> Result<Vec<u8>, Error> {
        let cipher = self.cipher(key_ref)?;
        let nonce = random_bytes::<NONCE_LEN>(KeyVendor::Static)?;
        let sealed = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: key.risky_ref(),
                    aad,
                },
            )
            .map_err(|_| {
                failure(
                    BackendErrorKind::Unavailable,
                    "the static key could not wrap",
                )
            })?;
        let mut out = Vec::with_capacity(1 + NONCE_LEN + sealed.len());
        out.push(WRAP_VERSION);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    async fn unwrap(&self, key_ref: &str, wrapped: &[u8], aad: &[u8]) -> Result<KeyBytes, Error> {
        let invalid = || {
            failure(
                BackendErrorKind::InvalidCiphertext,
                "the wrapped key does not open",
            )
        };
        let cipher = self.cipher(key_ref)?;
        let (version, rest) = wrapped.split_first().ok_or_else(invalid)?;
        if *version != WRAP_VERSION || rest.len() < NONCE_LEN {
            return Err(invalid());
        }
        let (nonce, sealed) = rest.split_at(NONCE_LEN);
        let opened = Zeroizing::new(
            cipher
                .decrypt(Nonce::from_slice(nonce), Payload { msg: sealed, aad })
                .map_err(|_| invalid())?,
        );
        let key: [u8; 32] = opened.as_slice().try_into().map_err(|_| invalid())?;
        Ok(Protected::new(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vendor() -> StaticKeyVendor {
        StaticKeyVendor::new("dev", Protected::new([3u8; 32]))
    }

    fn kind(error: Error) -> BackendErrorKind {
        match error {
            Error::Backend { backend, kind, .. } => {
                assert_eq!(backend, KeyVendor::Static.into());
                kind
            }
            other => panic!("expected a backend error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_key_round_trips_and_binds_its_aad() {
        let vendor = vendor();
        let key = Protected::new([9u8; 32]);
        let wrapped = vendor.wrap("dev", &key, b"aad").await.unwrap();
        assert_eq!(wrapped.len(), 1 + 12 + 32 + 16);
        assert_eq!(wrapped[0], WRAP_VERSION);
        let opened = vendor.unwrap("dev", &wrapped, b"aad").await.unwrap();
        assert_eq!(opened.risky_ref(), &[9u8; 32]);
        // A fresh nonce each time.
        assert_ne!(wrapped, vendor.wrap("dev", &key, b"aad").await.unwrap());

        let refused = vendor.unwrap("dev", &wrapped, b"other").await.unwrap_err();
        assert_eq!(kind(refused), BackendErrorKind::InvalidCiphertext);
        let mut damaged = wrapped.clone();
        damaged[20] ^= 1;
        assert_eq!(
            kind(vendor.unwrap("dev", &damaged, b"aad").await.unwrap_err()),
            BackendErrorKind::InvalidCiphertext
        );
        let mut relabelled = wrapped.clone();
        relabelled[0] = 2;
        assert_eq!(
            kind(vendor.unwrap("dev", &relabelled, b"aad").await.unwrap_err()),
            BackendErrorKind::InvalidCiphertext
        );
        assert_eq!(
            kind(vendor.unwrap("dev", &[1, 2], b"aad").await.unwrap_err()),
            BackendErrorKind::InvalidCiphertext
        );
        assert_eq!(
            kind(vendor.unwrap("dev", &[], b"aad").await.unwrap_err()),
            BackendErrorKind::InvalidCiphertext
        );
    }

    #[tokio::test]
    async fn another_key_does_not_unwrap_and_an_unknown_ref_is_not_found() {
        let vendor = vendor().with_key("next", Protected::new([4u8; 32]));
        let wrapped = vendor
            .wrap("dev", &Protected::new([9u8; 32]), b"aad")
            .await
            .unwrap();
        assert_eq!(
            kind(vendor.unwrap("next", &wrapped, b"aad").await.unwrap_err()),
            BackendErrorKind::InvalidCiphertext
        );
        assert_eq!(
            kind(vendor.unwrap("gone", &wrapped, b"aad").await.unwrap_err()),
            BackendErrorKind::NotFound
        );
    }

    #[test]
    fn it_offers_derived_data_keys_only_and_prints_no_key() {
        let vendor = vendor();
        assert!(vendor.supports_mode(KeyMode::Derived));
        assert!(!vendor.supports_mode(KeyMode::Wrapped));
        assert_eq!(vendor.vendor(), KeyVendor::Static);
        assert_eq!(
            format!("{vendor:?}"),
            r#"StaticKeyVendor { key_refs: ["dev"] }"#
        );
    }
}
