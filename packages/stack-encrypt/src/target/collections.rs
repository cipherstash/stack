//! Owned collections. A `Vec<S>` encrypts into a `Vec<T>` as one logical
//! batch, and a `Vec<T>` decrypts back. Both use the element target's own
//! declaration.
//!
//! A collection declares nothing of its own. A collection's `ContextInput` is
//! the element target's, so the element target decides once whether a caller can
//! omit a context or must give one. The same rule then applies to the whole
//! collection. For example, a `Vec<Ciphertext>` needs no caller context, but
//! a collection of a `RequiredContext` target does. `Default` does not affect
//! this.
//!
//! Each element is encrypted under its own ZeroKMS data key and authenticated
//! on its own. The collection's length and the order of its elements are not
//! part of what is authenticated. That suits a very common case, where each
//! element is stored in its own database row. A database can return rows in
//! any order. A query can also return only some of them.
//!
//! [`Pending::collect`] merges the elements' key requests into one logical
//! batch, in element order. An empty collection makes no request. The key
//! source can still split one logical batch into several requests to its
//! provider.
//!
//! A `Vec<u8>` is not a collection. Vitamin C encrypts a `Vec<u8>` as one
//! byte string, and `u8` is not an opaque scalar. So
//! `vec![1u8].encrypt_into::<Vec<Ciphertext>, _>(..)` does not compile. A
//! `Vec<u8>` encrypts into one `Ciphertext`, and a `Vec<Vec<u8>>` is a
//! collection of them. A nullable element, `Option<S>`, is not an opaque scalar either.
use super::{DecryptSource, Decryption, EncryptTarget, Encryption, Pending};
use stack_kms::MaybeSend;
use zeroize::Zeroize;

impl<S: Zeroize, T: EncryptTarget<S>> EncryptTarget<Vec<S>> for Vec<T>
where
    T::ContextInput: Clone + MaybeSend + 'static,
{
    /// The element target's context input. A collection can omit a context
    /// only if one element can. A collection must be given a context if one
    /// element must.
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
    /// The element target's context input, as for encryption.
    type ContextInput = T::ContextInput;
    fn decryption<K: 'static>(self, context: Self::ContextInput) -> Decryption<Vec<P>, K> {
        // Every element's keys are retrieved in one batch and the results
        // keep element order. An element that fails after its key arrived
        // fails the collection, and the elements recovered before it are wiped.
        Decryption::all_wiping(
            self.into_iter()
                .map(|element| element.decryption(context.clone())),
        )
    }
}
