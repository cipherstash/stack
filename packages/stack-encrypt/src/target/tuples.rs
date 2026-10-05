//! A tuple of targets is a target: each element derived from the same
//! plaintext, under the one context the tuple is handed, settled in one
//! batch. This is a `plaintext = T` record without the struct, and what a
//! one-value plan's [`encrypt_into`](crate::plan::ValueStart::encrypt_into)
//! names: `encrypt_into::<(StackCipherText, EqualityTerm)>()`.
//!
//! The context is the one every element accepts ([`JoinContext`]): an
//! [`AeadContext`] for a tuple of ciphertexts, a [`CallerContext`] as soon as
//! one element derives a term. A ciphertext element takes its AEAD half, a
//! term the whole ([`Encryption::accepting`]), so the bytes are the derive's.
use super::context::{AeadContext, CallerContext, DeclaredContext};
use super::operations::{
    DecryptField, DecryptInto, Decryptable, Decryption, EncryptFrom, Encryption,
};
use super::IndexSpec;
use crate::Error;
use stack_kms::MaybeSend;

/// The one context two targets can be handed together: what a tuple of
/// targets takes, so each element receives the same value (ADR-0004).
///
/// Two targets that need the same context take that context; a ciphertext
/// ([`AeadContext`]) beside a term or a record ([`CallerContext`],
/// [`DeclaredContext`]) takes a [`CallerContext`], of which the ciphertext's
/// context is the AEAD half. A tuple of ciphertexts therefore takes an
/// [`AeadContext`], and accepts every context a lone ciphertext accepts:
/// what a `plaintext = T` record declared `context_type = AeadContext` is.
///
/// `Output` is a context every element's own context is made from (`Into`
/// each of them): the tuple's impl asks that, so a join can only ever widen
/// what an element is handed, never drop part of it.
///
/// Sealed: the pairs are those above, and a context paired with itself.
/// Targets whose contexts differ otherwise do not form a tuple (nor a
/// `plaintext = T` record, whose outputs are one), so a target of your own
/// that sits beside a ciphertext or a term declares one of this crate's
/// contexts, usually [`CallerContext`], and takes what it needs from it.
/// Sealing keeps the joins this crate's to extend: a pair implemented
/// outside it would conflict with any join added here later, which would
/// make adding one a breaking change.
pub trait JoinContext<Other>: sealed::Sealed<Other> {
    /// The context both are handed.
    type Output: Clone + MaybeSend + 'static;
}
mod sealed {
    pub trait Sealed<Other> {}
}
impl<C: Clone + MaybeSend + 'static> sealed::Sealed<C> for C {}
impl<C: Clone + MaybeSend + 'static> JoinContext<C> for C {
    type Output = C;
}
macro_rules! join_to_caller {
    ($($left:ty, $right:ty;)+) => {$(
        impl sealed::Sealed<$right> for $left {}
        impl JoinContext<$right> for $left {
            type Output = CallerContext;
        }
    )+};
}
join_to_caller! {
    AeadContext, CallerContext;
    CallerContext, AeadContext;
    AeadContext, DeclaredContext;
    DeclaredContext, AeadContext;
    CallerContext, DeclaredContext;
    DeclaredContext, CallerContext;
}

/// The joined context of a list of targets, left to right.
macro_rules! joined {
    ($s:ident; $first:ident) => { <$first as EncryptFrom<$s>>::Context };
    ($s:ident; $first:ident, $second:ident $(, $rest:ident)*) => {
        joined!(@acc $s; <<$first as EncryptFrom<$s>>::Context as JoinContext<<$second as EncryptFrom<$s>>::Context>>::Output $(, $rest)*)
    };
    (@acc $s:ident; $acc:ty) => { $acc };
    (@acc $s:ident; $acc:ty, $next:ident $(, $rest:ident)*) => {
        joined!(@acc $s; <$acc as JoinContext<<$next as EncryptFrom<$s>>::Context>>::Output $(, $rest)*)
    };
}

macro_rules! tuple_of_targets {
    ($(($first:ident $(, $rest:ident)+) => $nested:pat, joins $([$($pre:ident),+; $next:ident])+;)+) => {$(
        impl<S, $first, $($rest),+> EncryptFrom<S> for ($first, $($rest),+)
        where
            $first: EncryptFrom<S>,
            $($rest: EncryptFrom<S>,)+
            $(joined!(S; $($pre),+): JoinContext<<$next as EncryptFrom<S>>::Context>,)+
            joined!(S; $first $(, $rest)+): Into<$first::Context> $(+ Into<$rest::Context>)+,
        {
            type Context = joined!(S; $first $(, $rest)+);
            fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::Context>
            where
                S: 's,
            {
                $first::encryption()
                    .accepting::<Self::Context>()
                    $(.zip($rest::encryption().accepting::<Self::Context>()))+
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
        (A, B) => (A, B), joins [A; B];
        (A, B, C) => ((A, B), C), joins [A; B] [A, B; C];
        (A, B, C, D) => (((A, B), C), D), joins [A; B] [A, B; C] [A, B, C; D];
        (A, B, C, D, E) => ((((A, B), C), D), E), joins [A; B] [A, B; C] [A, B, C; D] [A, B, C, D; E];
    }
}
