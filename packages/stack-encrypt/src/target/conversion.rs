//! Owned conversions over core-owned declarations.

use super::{
    AcceptsContext, AllowsNoContext, CipherScope, ContextInput, Decryption, Encryption, IndexSpec,
    Owned, Pending,
};
use crate::KeysetCipher;
use vitaminc_protected::{Controlled, Protected};
use zeroize::Zeroize;

/// A declaration has two forms of one description. The library runs the form
/// that matches how the call passes the plaintext:
///
/// - [`encryption`](Self::encryption) is given the plaintext **by reference**.
///   A declaration composes this form when it takes a field out of a borrowed
///   struct ([`Encryption::project`]). A collection or a plan runs it for each
///   element.
/// - [`owned_encryption`](Self::owned_encryption) is given the plaintext **by
///   value**. [`EncryptInto`] runs this form. By default, it guards the value
///   with [`Protected`], runs the borrowed description over it, and wipes it
///   before the pending request is returned. The value is wiped even when
///   building or running the description fails. A record overrides this form,
///   field by field ([`Encryption::split`]). It moves the fields it stores in
///   the clear into its output, and guards the fields it seals.
///
/// Neither form is given the cipher and the plaintext together. The source
/// does not need to implement `Clone`.
pub trait EncryptTarget<S: Zeroize>: Sized + 'static {
    /// What the caller must or may supply, independently of declared context.
    type ContextInput: ContextInput;
    /// Describe the encryption over a borrowed plaintext. Key requests wait
    /// until the returned pending request runs.
    fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::ContextInput>
    where
        S: 's;
    /// Describe the encryption over the plaintext by value. This form is
    /// responsible for wiping what it does not move into the output.
    ///
    /// The default guards the whole value, and runs
    /// [`encryption`](Self::encryption) over a borrow of it. So a declaration
    /// that only composes operations over a borrow does not need to implement
    /// this method.
    fn owned_encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::ContextInput, Owned>
    where
        S: 's,
    {
        Encryption::from_build(
            Self::encryption::<K>().shapes(),
            move |source: S, cipher, context| {
                let guarded = Protected::new(source);
                // The borrowed description takes a plain `&S`, not a
                // protected borrow: a declaration takes a field out of a
                // borrowed struct (`Encryption::project`), and a
                // `ProtectedRef` of a struct cannot lend one of its fields.
                let pending = cipher.run(Self::encryption(), guarded.risky_ref(), context);
                drop(guarded);
                pending
            },
        )
    }
    /// The indexes that this target's terms support, as data. A plan field
    /// typed with this target lets a query use these indexes. The default is
    /// none. That is correct for a ciphertext, and for a record whose fields
    /// have contexts of their own.
    fn indexes() -> Vec<IndexSpec> {
        vec![]
    }
}

/// Declare how stored output recovers plaintext, without performing key I/O.
pub trait DecryptSource<P: Zeroize>: Sized {
    /// The decrypt-side caller requirement, independent of the encrypt side.
    type ContextInput: ContextInput;
    /// Inspect this stored value and describe its opening.
    fn decryption<K: 'static>(self, context: Self::ContextInput) -> Decryption<P, K>;
}

/// Consume plaintext and execute a target declaration through the shared engine.
pub trait EncryptInto: Zeroize + Sized {
    /// Encrypt with explicitly omitted caller context.
    fn encrypt_into<'a, T, K: 'static>(self, cipher: &'a KeysetCipher<'_, K>) -> Pending<'a, T, K>
    where
        T: EncryptTarget<Self>,
        T::ContextInput: AllowsNoContext,
    {
        // The plaintext stays guarded while the declaration is built. It also
        // stays guarded while the omitted context is initialised. Either step
        // can panic, because a record's declaration builds its fields'
        // declarations here. The plaintext must not then be dropped without
        // being wiped. The declaration takes over the guard once both exist.
        let source = Protected::new(self);
        let description = T::owned_encryption();
        let context = T::ContextInput::omitted();
        cipher.run(description, source.risky_unwrap(), context)
    }

    /// Encrypt with a supplied context, without manually wrapping its presence.
    fn encrypt_into_with_context<'a, T, K: 'static>(
        self,
        cipher: &'a KeysetCipher<'_, K>,
        context: impl Into<<T::ContextInput as AcceptsContext>::Value>,
    ) -> Pending<'a, T, K>
    where
        T: EncryptTarget<Self>,
        T::ContextInput: AcceptsContext,
    {
        // The plaintext stays guarded while the caller's context is converted.
        // It also stays guarded while the declaration is built. Either step
        // can panic. If one does, the plaintext must not be dropped without being
        // wiped. The declaration takes over the guard once both exist.
        let source = Protected::new(self);
        let context = T::ContextInput::supplied(context.into());
        let description = T::owned_encryption();
        cipher.run(description, source.risky_unwrap(), context)
    }
}
impl<S: Zeroize> EncryptInto for S {}

/// Construct owned plaintext from a declared encrypted source.
///
/// **Decrypt a record into a [`Protected`].** A `Zeroize` bound does not make
/// a returned value wipe itself when it is dropped, and the plaintext of a
/// derived `struct = ..` record cannot implement `ZeroizeOnDrop` at all. A
/// derived record implements `DecryptSource<Protected<P>>` as well, so
/// `Protected::<P>::decrypt_from(record, &cipher)` returns a value that is
/// wiped when it is dropped. A bare `P` must be wiped by the caller.
pub trait DecryptFrom: Zeroize + Sized + 'static {
    /// Decrypt with explicitly omitted caller context.
    fn decrypt_from<'a, S, K: 'static>(
        source: S,
        cipher: impl CipherScope<'a, K>,
    ) -> Pending<'a, Self, K>
    where
        S: DecryptSource<Self>,
        S::ContextInput: AllowsNoContext,
    {
        source
            .decryption(S::ContextInput::omitted())
            .open_in(cipher)
    }

    /// Decrypt with the context supplied at encryption.
    fn decrypt_from_with_context<'a, S, K: 'static>(
        source: S,
        cipher: impl CipherScope<'a, K>,
        context: impl Into<<S::ContextInput as AcceptsContext>::Value>,
    ) -> Pending<'a, Self, K>
    where
        S: DecryptSource<Self>,
        S::ContextInput: AcceptsContext,
    {
        source
            .decryption(S::ContextInput::supplied(context.into()))
            .open_in(cipher)
    }
}
impl<P: Zeroize + 'static> DecryptFrom for P {}
