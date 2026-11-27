use crate::Unspecified;
use std::cell::RefCell;
use vitaminc_random::{Generatable, SafeRand};

/// Represents a nonce used in AEAD encryption of `N` bytes length.
/// It is public protocol data, not a secret. This type carries bytes but does
/// not prove they are unique for a key.
pub struct Nonce<const N: usize>([u8; N]);

impl<const N: usize> AsRef<[u8]> for Nonce<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> Nonce<N> {
    pub(crate) fn new(inner: [u8; N]) -> Self {
        Self(inner)
    }

    /// Consume the nonce and recover its public bytes.
    pub fn into_inner(self) -> [u8; N] {
        self.0
    }
}

// TODO: Make this a trait that can be implemented for a cipher rather than an associated type on the Cipher
// That way we can have multiple implementations of the same cipher with different nonce generation strategies
/// Source of `N`-byte nonces for a cipher.
///
/// Implementations and callers must agree on nonce policy and per-key usage
/// limits. Repeated generation must not deliberately reuse a nonce with the
/// same key; random generation still carries a collision probability.
pub trait NonceGenerator<const N: usize> {
    /// Initialize the generator, returning [`Unspecified`] if its entropy
    /// source or other initialization fails.
    fn init() -> Result<Self, Unspecified>
    where
        Self: Sized;
    /// Generate the next nonce, returning [`Unspecified`] if generation fails.
    /// A successful result alone is not evidence of per-key uniqueness.
    fn generate(&self) -> Result<Nonce<N>, Unspecified>;
}

/// Nonces drawn from an entropy-seeded [`SafeRand`] held in a `RefCell`.
///
/// This generator is not `Sync`. It tracks neither keys nor previously drawn
/// nonces and does not enforce a per-key message limit. Callers must choose
/// `N` and limits appropriate to their cipher's random-nonce collision risk.
pub struct RandomNonceGenerator<const N: usize>(RefCell<SafeRand>);

impl<const N: usize> NonceGenerator<N> for RandomNonceGenerator<N> {
    fn init() -> Result<Self, Unspecified> {
        let rng = SafeRand::from_entropy().map_err(|_| Unspecified)?;
        Ok(Self(RefCell::new(rng)))
    }

    fn generate(&self) -> Result<Nonce<N>, Unspecified> {
        let mut rng = self.0.borrow_mut();
        Generatable::random(&mut rng)
            .map_err(|_| Unspecified)
            .map(Nonce::new)
    }
}
