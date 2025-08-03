use std::cell::RefCell;
use vitaminc_random::{Generatable, SafeRand, SeedableRng};
use crate::Unspecified;

// TODO: Add a ValidNonceSize trait to ensure that the nonce size is valid for the cipher

/// Represents a nonce used in AEAD encryption of `N` bytes length.
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

    pub fn into_inner(self) -> [u8; N] {
        self.0
    }
}

// TODO: Make this a trait that can be implemented for a cipher rather than an associated type on the Cipher
// That way we can have multiple implementations of the same cipher with different nonce generation strategies
pub trait NonceGenerator<const N: usize> {
    fn init() -> Self;
    fn generate(&self) -> Result<Nonce<N>, Unspecified>;
}

pub struct RandomNonceGenerator<const N: usize>(RefCell<SafeRand>);

impl<const N: usize> NonceGenerator<N> for RandomNonceGenerator<N> {
    fn init() -> Self {
        let rng = SafeRand::from_entropy();
        Self(RefCell::new(rng))
    }

    fn generate(&self) -> Result<Nonce<N>, Unspecified> {
        let mut rng = self.0.borrow_mut();
        Generatable::random(&mut rng).map_err(|_| Unspecified).map(Nonce::new)
    }
}
