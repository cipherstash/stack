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
    /// Each element is moved into the owned form of the element's own
    /// declaration. So an element that moves part of itself into its output,
    /// such as a record's passthrough fields, does so here too. Each element's
    /// own declaration guards it and wipes it before the column's pending
    /// request is returned.
    fn owned_encryption<'s, K: 'static>(
    ) -> Encryption<'s, Vec<S>, Self, K, Self::ContextInput, super::Owned>
    where
        S: 's,
    {
        Encryption::from_build(move |source: Vec<S>, cipher, context: T::ContextInput| {
            // Run every element, whatever happened to the elements before it.
            // Each element's own declaration is what wipes it, so an element
            // left unvisited after an earlier failure would be dropped as it
            // is. The column still reports a refused context once, because
            // `collect` keeps the first failure.
            //
            // The elements not yet handed over stay in a guard. The guard
            // wipes them if a declaration panics, as the guard over the whole
            // vector did before. An element is taken out only once its
            // description and context exist, so nothing that can panic runs
            // while an element is unguarded.
            let mut unvisited = Unvisited(source.into_iter());
            let mut elements = Vec::with_capacity(unvisited.0.len());
            while !unvisited.0.as_slice().is_empty() {
                let description = T::owned_encryption();
                let context = context.clone();
                let Some(element) = unvisited.0.next() else {
                    break;
                };
                elements.push(cipher.run(description, element, context));
            }
            Pending::collect(cipher, elements)
        })
    }
}

/// The elements of an owned column that are not yet handed to their
/// declarations. The guard is dropped when a declaration unwinds, or when
/// every element has been handed over. When it is dropped, it wipes the
/// elements that are left in it.
struct Unvisited<S: Zeroize>(std::vec::IntoIter<S>);

impl<S: Zeroize> Drop for Unvisited<S> {
    fn drop(&mut self) {
        self.0.as_mut_slice().iter_mut().for_each(Zeroize::zeroize);
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
