//! The deterministic key source of the `deterministic-kms` test build:
//! `stack-kms`'s [`DeterministicSource`] (behind its `test-support` feature),
//! the one definition that also sealed stack-encrypt's record fixture
//! (`tests/fixtures/record_lowering.json`). A Go test that loads this build
//! with the fixture's seed opens the records Rust sealed and derives the same
//! term bytes, because both run the same code.
//!
//! It is a test double. The feature that compiles it is off by default, and
//! the build it produces goes under languages/golang/encrypt/testdata, which
//! `go build` and the package's `//go:embed wasm` both ignore, so no Go
//! binary carries it; the tests read it from disk.

pub use stack_kms::DeterministicSource;

use serde::Deserialize;
use stack_encrypt::dynamic::frame::serde::from_slice;
use stack_guest_abi::last_error::malformed;
use zeroize::Zeroize;

/// The `deterministic-kms` build's ZeroKMS stand-in config: the source's
/// 32-byte seed, a frame holding bytes and nothing else. Wiped when it
/// drops.
#[derive(Deserialize)]
#[serde(try_from = "&[u8]")]
pub struct Seed([u8; 32]);

impl TryFrom<&[u8]> for Seed {
    type Error = &'static str;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        bytes
            .try_into()
            .map(Seed)
            .map_err(|_| "a seed that is not 32 bytes")
    }
}

impl Drop for Seed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The `deterministic-kms` build's whole config: the seed, and a key vendor
/// backend when one is configured. The host sends the bare seed, or, for
/// the hermetic Go tests of the vendor path, an object of the seed and the
/// key vendor backend keys ([`crate::config`] has them):
/// `{"seed": bytes, "key_vendor": .., ..}`.
pub struct SeedConfig {
    pub seed: Seed,
    pub vendor: Option<crate::vendor::VendorConfig>,
}

impl SeedConfig {
    /// Read the config the host sent.
    pub fn parse(bytes: &[u8]) -> Result<Self, u32> {
        if let Ok(seed) = from_slice::<Seed>(bytes) {
            return Ok(Self { seed, vendor: None });
        }
        let wire: SeededWire<'_> = from_slice(bytes).map_err(|_| {
            malformed(
                "the deterministic build's config is a 32-byte seed, or an object of a seed and the key vendor backend keys",
            )
        })?;
        let vendor = crate::config::vendor_wire!(wire)
            .config()
            .map_err(|e| malformed(format!("the config: {e}")))?;
        Ok(Self {
            seed: wire.seed,
            vendor,
        })
    }
}

/// The object form of the deterministic config.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SeededWire<'a> {
    seed: Seed,
    #[serde(default, borrow, deserialize_with = "present")]
    key_vendor: Option<&'a str>,
    #[serde(default, borrow, deserialize_with = "present")]
    keyset_records: Option<Vec<&'a str>>,
    #[serde(default, borrow, deserialize_with = "present")]
    aws_region: Option<&'a str>,
    #[serde(default, borrow, deserialize_with = "present")]
    aws_endpoint: Option<&'a str>,
    #[serde(default, borrow, deserialize_with = "present")]
    vault_address: Option<&'a str>,
    #[serde(default, borrow, deserialize_with = "present")]
    vault_namespace: Option<&'a str>,
    #[serde(default, borrow, deserialize_with = "present")]
    vault_mount: Option<&'a str>,
    #[serde(default, borrow, deserialize_with = "present")]
    gcp_endpoint: Option<&'a str>,
    #[serde(default, borrow, deserialize_with = "present")]
    static_key_ref: Option<&'a str>,
    #[serde(default, borrow, deserialize_with = "present")]
    static_key: Option<&'a [u8]>,
}

/// Absent is `None`. Present, a value must be of its type: a null is
/// refused.
fn present<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

impl Seed {
    /// The key source this seed drives.
    pub fn source(&self) -> DeterministicSource {
        DeterministicSource::new(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{Seed, SeedConfig};
    use crate::test_frame::{frame, obj, s, V};
    use stack_encrypt::dynamic::frame::serde::from_slice;

    /// A seed is 32 bytes, and only bytes: 32 characters of text are refused.
    #[test]
    fn a_seed_is_32_bytes_never_text() {
        assert!(from_slice::<Seed>(&frame(&V::Bytes(vec![7; 32]))).is_ok());
        assert!(from_slice::<Seed>(&frame(&V::Bytes(vec![7; 31]))).is_err());
        assert!(from_slice::<Seed>(&frame(&V::Str("x".repeat(32)))).is_err());
    }

    /// The object form adds a key vendor backend beside the seed; a bare
    /// seed has none.
    #[test]
    fn a_seed_object_carries_a_key_vendor_backend() {
        let bare = SeedConfig::parse(&frame(&V::Bytes(vec![7; 32]))).unwrap();
        assert!(bare.vendor.is_none());
        let with = SeedConfig::parse(&frame(&obj(vec![
            ("seed", V::Bytes(vec![7; 32])),
            ("key_vendor", s("static")),
            ("keyset_records", V::Arr(vec![s("stack-keyset:AQ")])),
            ("static_key_ref", s("local")),
            ("static_key", V::Bytes(vec![9; 32])),
        ])))
        .unwrap();
        assert_eq!(
            with.vendor.map(|v| v.settings.vendor()),
            Some(stack_kms::KeyVendor::Static)
        );
        assert!(SeedConfig::parse(&frame(&obj(vec![("seed", V::Bytes(vec![7; 31]))]))).is_err());
        assert!(SeedConfig::parse(&frame(&obj(vec![
            ("seed", V::Bytes(vec![7; 32])),
            ("other", s("x")),
        ])))
        .is_err());
    }
}
