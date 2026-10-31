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

/// The `deterministic-kms` build's whole config: the source's 32-byte seed,
/// a frame holding bytes and nothing else. Wiped when it drops.
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

impl Seed {
    /// Read the seed frame the host sent in place of a config.
    pub fn parse(bytes: &[u8]) -> Result<Self, u32> {
        from_slice(bytes)
            .map_err(|_| malformed("the deterministic build's config is a 32-byte seed"))
    }

    /// The key source this seed drives.
    pub fn source(&self) -> DeterministicSource {
        DeterministicSource::new(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::Seed;
    use crate::test_frame::{frame, V};
    use stack_encrypt::dynamic::frame::serde::from_slice;

    /// A seed is 32 bytes, and only bytes: 32 characters of text are refused.
    #[test]
    fn a_seed_is_32_bytes_never_text() {
        assert!(from_slice::<Seed>(&frame(&V::Bytes(vec![7; 32]))).is_ok());
        assert!(from_slice::<Seed>(&frame(&V::Bytes(vec![7; 31]))).is_err());
        assert!(from_slice::<Seed>(&frame(&V::Str("x".repeat(32)))).is_err());
    }
}
