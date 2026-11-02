//! Owned collections: `Vec<S>` encrypts into `Vec<T>` as one logical batch,
//! and `Vec<T>` decrypts back, through the element's own declaration.
//!
//! A collection declares nothing of its own. Its `ContextInput` is the
//! element's, so whether a caller may omit or must supply a context is
//! decided once, by the element target, and holds for the column: a
//! `Vec<Ciphertext>` is reached with no caller context, a column of a
//! `RequiredContext` target is not. `Default` plays no part in that.
//!
//! Each element is sealed under its own ZeroKMS data key and authenticated
//! on its own. Neither the collection's length nor the order of its
//! elements is authenticated: stored values are rows and columns, which
//! come back in any order and in part. The elements' key requests are
//! merged into one logical batch ([`Pending::collect`]), in element order,
//! and an empty collection makes no request at all. The key source may
//! still split one logical batch into several provider requests.
//!
//! A `Vec<u8>` is not a collection here: `u8` is not an opaque scalar, since
//! Vitamin C keeps `Vec<u8>` a byte leaf and gives `u8` no source of its own,
//! so neither `vec![1u8].encrypt_into::<Vec<Ciphertext>, _>(..)` nor a whole
//! byte vector as one `Ciphertext` compiles. A nullable element, `Option<S>`,
//! is likewise not an opaque scalar in this slice.
use super::{DecryptSource, Decryption, EncryptTarget, Encryption, Pending};
use stack_kms::MaybeSend;
use zeroize::Zeroize;

impl<S: Zeroize, T: EncryptTarget<S>> EncryptTarget<Vec<S>> for Vec<T>
where
    T::ContextInput: Clone + MaybeSend + 'static,
{
    /// The element's: a column may omit or must supply exactly what one
    /// element may or must.
    type ContextInput = T::ContextInput;
    fn encryption<'s, K: 'static>() -> Encryption<'s, Vec<S>, Self, K, Self::ContextInput>
    where
        S: 's,
    {
        // Each element is handed by reference to the element declaration,
        // which runs in its usual borrowed mode: the owned conversion holds
        // the whole vector in its guard, and nothing is cloned. The
        // collection stops declaring at the first element that fails, so a
        // refused context is reported once rather than once per row.
        Encryption::from_build(
            move |source: &'s Vec<S>, cipher, context: T::ContextInput| {
                Pending::collect(
                    cipher,
                    source
                        .iter()
                        .map(|element| cipher.run(T::encryption(), element, context.clone())),
                )
            },
        )
    }
}

impl<P: Zeroize + 'static, T: DecryptSource<P>> DecryptSource<Vec<P>> for Vec<T>
where
    T::ContextInput: Clone,
{
    /// The element's, as on the encrypt side.
    type ContextInput = T::ContextInput;
    fn decryption<K: 'static>(self, context: Self::ContextInput) -> Decryption<Vec<P>, K> {
        // Every element's keys are retrieved in one batch and the results
        // keep element order. An element that fails after its key arrived
        // fails the column, and the elements recovered before it are wiped.
        Decryption::all_wiping(
            self.into_iter()
                .map(|element| element.decryption(context.clone())),
        )
    }
}
