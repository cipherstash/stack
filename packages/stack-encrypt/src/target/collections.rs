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
use vitaminc_protected::{Controlled, Protected};
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
            T::encryption::<K>().shapes(),
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
        Encryption::from_build(
            T::owned_encryption::<K>().shapes(),
            move |source: Vec<S>, cipher, context: T::ContextInput| {
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
            },
        )
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

/// An optional value. An `Option<S>` encrypts into an `Option<T>`.
///
/// - `Some` runs the target's own declaration.
/// - `None` stays `None`. Nothing is stored. No key is requested. The column
///   is a database NULL: no value at all.
///
/// A database NULL is not a sealed null. Some targets seal a null, such as an
/// EQL type encrypted from an `Option<String>`. Such a target stores a value
/// that means "null", under a key, with the terms of a null.
///
/// The type of the field decides which one a column stores: `Option<T>` for
/// a database NULL, and `T` over an `Option<S>` for a sealed null. Neither is
/// read as the other. A sealed null opened through `Option<T>` into an
/// `Option<S>` is refused as the wrong type.
impl<S: Zeroize, T: EncryptTarget<S> + MaybeSend> EncryptTarget<Option<S>> for Option<T> {
    /// The target's context input. A `None` takes the same context as a
    /// `Some`, so the call is the same whatever the data.
    type ContextInput = T::ContextInput;
    fn encryption<'s, K: 'static>() -> Encryption<'s, Option<S>, Self, K, Self::ContextInput>
    where
        S: 's,
    {
        Encryption::from_build(
            T::encryption::<K>().shapes(),
            move |source: &'s Option<S>, cipher, context: T::ContextInput| match source {
                Some(value) => cipher.run(T::encryption(), value, context).map(Some),
                None => Pending::ready(cipher, Ok(None)),
            },
        )
    }
    /// A `Some` value is moved into the owned form of the target's own
    /// declaration. That declaration guards the value and wipes it. The
    /// elements of a collection are handled the same way.
    fn owned_encryption<'s, K: 'static>(
    ) -> Encryption<'s, Option<S>, Self, K, Self::ContextInput, super::Owned>
    where
        S: 's,
    {
        Encryption::from_build(
            T::owned_encryption::<K>().shapes(),
            move |source: Option<S>, cipher, context: T::ContextInput| {
                // Building the target's declaration can panic, so the value stays
                // guarded until the declaration exists. The declaration then takes
                // the value over, and wipes it.
                let guarded = Protected::new(source);
                let description = T::owned_encryption();
                match guarded.risky_unwrap() {
                    Some(value) => cipher.run(description, value, context).map(Some),
                    None => Pending::ready(cipher, Ok(None)),
                }
            },
        )
    }
    fn indexes() -> Vec<super::IndexSpec> {
        T::indexes()
    }
}

/// A stored `None` opens as `None`, with no key request. A stored `Some`
/// opens through the target's own declaration.
impl<P: Zeroize + MaybeSend + 'static, T: DecryptSource<P>> DecryptSource<Option<P>> for Option<T> {
    /// The target's context input, as for encryption.
    type ContextInput = T::ContextInput;
    fn decryption<K: 'static>(self, context: Self::ContextInput) -> Decryption<Option<P>, K> {
        match self {
            Some(stored) => stored.decryption(context).map(Some),
            None => Decryption::ready(None),
        }
    }
}
