//! A tuple of targets is a target: each element derived from the same
//! plaintext, under the one context the tuple is handed, settled in one
//! batch. This is a `plaintext = T` record without the struct, and what a
//! one-value plan's [`encrypt_into`](crate::plan::ValueStart::encrypt_into)
//! names: `encrypt_into::<(StackCipherText, EqualityTerm)>()`.
//!
//! The context is a [`CallerContext`], as a derived record's is: a
//! ciphertext element takes its AEAD half, a term the whole
//! ([`Encryption::accepting`]), so the bytes are the derive's.
use super::context::CallerContext;
use super::operations::{
    DecryptField, DecryptInto, Decryptable, Decryption, EncryptFrom, Encryption,
};
use super::IndexSpec;
use crate::Error;

macro_rules! tuple_of_targets {
    ($(($first:ident $(, $rest:ident)+) => $nested:pat,)+) => {$(
        impl<S, $first, $($rest),+> EncryptFrom<S> for ($first, $($rest),+)
        where
            $first: EncryptFrom<S>,
            $($rest: EncryptFrom<S>,)+
            CallerContext: Into<$first::Context> $(+ Into<$rest::Context>)+,
        {
            type Context = CallerContext;
            fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::Context>
            where
                S: 's,
            {
                $first::encryption()
                    .accepting::<CallerContext>()
                    $(.zip($rest::encryption().accepting::<CallerContext>()))+
                    .map(|$nested| ($first, $($rest),+))
            }
            fn indexes() -> Vec<IndexSpec> {
                let mut indexes = $first::indexes();
                $(indexes.extend($rest::indexes());)+
                indexes
            }
        }

        /// The tuple is decryptable when one of its elements is.
        impl<$first: Decryptable, $($rest: Decryptable),+> Decryptable for ($first, $($rest),+) {
            const DECRYPTABLE: bool = $first::DECRYPTABLE $(|| $rest::DECRYPTABLE)+;
        }

        /// Opened through its first element that holds recoverable
        /// ciphertext ([`DecryptField`]), under the tuple's one context, as
        /// a derived record opens its one decryptable field. A tuple of terms
        /// alone does not open: [`Error::NotOpened`].
        impl<P: 'static, $first, $($rest),+> DecryptInto<P> for ($first, $($rest),+)
        where
            $first: DecryptField<P, CallerContext>,
            $($rest: DecryptField<P, CallerContext>,)+
        {
            type Context = CallerContext;
            fn decryption<K: 'static>(self, context: CallerContext) -> Decryption<P, K> {
                let ($first, $($rest),+) = self;
                $first
                    .decryption_field(context.clone())
                    $(.or_else(|| $rest.decryption_field(context.clone())))+
                    .unwrap_or_else(|| Decryption::failed(Error::NotOpened))
            }
        }

        /// As a field, a tuple holding no recoverable ciphertext is
        /// `None`, as a term is: the search for the field that opens the
        /// record moves on to the ciphertext beside it, rather than
        /// stopping at a tuple that cannot open.
        impl<P: 'static, Ctx, $first, $($rest),+> DecryptField<P, Ctx> for ($first, $($rest),+)
        where
            Self: DecryptInto<P> + Decryptable,
            Ctx: Into<<Self as DecryptInto<P>>::Context>,
        {
            fn decryption_field<K: 'static>(self, context: Ctx) -> Option<Decryption<P, K>> {
                if !<Self as Decryptable>::DECRYPTABLE {
                    return None;
                }
                Some(self.decryption(context.into()))
            }
        }
    )+};
}

// The closure's pattern re-binds each output under its target's type name.
#[allow(non_snake_case)]
mod impls {
    use super::*;
    tuple_of_targets! {
        (A, B) => (A, B),
        (A, B, C) => ((A, B), C),
        (A, B, C, D) => (((A, B), C), D),
        (A, B, C, D, E) => ((((A, B), C), D), E),
    }
}
