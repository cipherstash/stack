//! Owned conversions over core-owned declarations.

use super::{
    AcceptsContext, AllowsNoContext, CipherScope, ContextInput, Decryption, Encryption, IndexSpec,
    Owned, Pending,
};
use crate::KeysetCipher;
use vitaminc_protected::{Controlled, Protected};
use zeroize::Zeroize;

/// Declare how to encrypt an owned plaintext into this target.
///
/// A declaration has two forms of one description, and the library runs
/// whichever the call supplies the plaintext in:
///
/// - [`encryption`](Self::encryption) is handed the plaintext **by
///   reference**. It is what a declaration composes when it picks a field
///   out of a borrowed struct ([`Encryption::project`]), and what a
///   collection or a plan runs per element.
/// - [`owned_encryption`](Self::owned_encryption) is handed the plaintext
///   **by value**: what [`EncryptInto`] runs. Its default guards the value
///   with [`Protected`], runs the borrowed description over it and wipes it
///   before the pending request is returned, including when description
///   construction or execution fails. A record overrides it to move the
///   fields it stores in the clear into its output and to guard the ones it
///   seals, field by field ([`Encryption::split`]).
///
/// Neither form receives the cipher and plaintext together, and no `Clone`
/// bound is imposed on the source.
pub trait EncryptTarget<S: Zeroize>: Sized + 'static {
    /// What the caller must or may supply, independently of declared context.
    type ContextInput: ContextInput;
    /// Describe the encryption over a borrowed plaintext; key I/O is deferred
    /// to the returned pending.
    fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::ContextInput>
    where
        S: 's;
    /// Describe the encryption over the plaintext by value, taking
    /// responsibility for wiping what it does not carry into the output.
    ///
    /// The default guards the whole value and runs
    /// [`encryption`](Self::encryption) over a borrow of it, so a declaration
    /// that only composes operations over a borrow need not implement this.
    fn owned_encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::ContextInput, Owned>
    where
        S: 's,
    {
        Encryption::from_build(move |source: S, cipher, context| {
            let guarded = Protected::new(source);
            let pending = cipher.run(Self::encryption(), guarded.risky_ref(), context);
            drop(guarded);
            pending
        })
    }
    /// The indexes this target's terms answer queries by, as data: what a
    /// plan field typed with this target lets a query ask for. The default
    /// is none, which is right for a ciphertext and for a record whose
    /// fields sit under contexts of their own.
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
        // Guarded while the declaration is constructed and the omitted
        // context initialised: either may panic (a record's declaration
        // constructs its fields' declarations here), and the plaintext must
        // not then drop unwiped. The declaration takes over the guard once
        // both exist.
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
        // Guarded while the caller's context converts and the declaration
        // is constructed: either may panic, and the plaintext must not then
        // drop unwiped. The declaration takes over the guard once both
        // exist.
        let source = Protected::new(self);
        let context = T::ContextInput::supplied(context.into());
        let description = T::owned_encryption();
        cipher.run(description, source.risky_unwrap(), context)
    }
}
impl<S: Zeroize> EncryptInto for S {}

/// Construct owned plaintext from a declared encrypted source.
///
/// Successful return transfers cleanup responsibility to the caller: a
/// `Zeroize` bound does not make ordinary returned values wipe themselves on drop.
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
