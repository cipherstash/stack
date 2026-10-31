//! Owned conversions over core-owned declarations.

use super::{
    AcceptsContext, AllowsNoContext, CipherScope, ContextInput, Decryption, Encryption, Pending,
};
use crate::KeysetCipher;
use zeroize::{Zeroize, Zeroizing};

/// Declare how to encrypt an owned plaintext into this target.
///
/// The library guards the source with `Zeroizing`, then synchronously runs
/// this description over a borrow of it. The description may select core
/// operations and map their outputs; it never receives the cipher and
/// plaintext together. Source buffers are wiped before the pending request
/// is returned, including when description construction or execution fails.
/// No `Clone` bound is imposed on the source.
pub trait EncryptTarget<S: Zeroize>: Sized + 'static {
    /// What the caller must or may supply, independently of declared context.
    type ContextInput: ContextInput;
    /// Describe the encryption; key I/O is deferred to the returned pending.
    fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::ContextInput>
    where
        S: 's;
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
        let source = Zeroizing::new(self);
        cipher.run(T::encryption(), &*source, T::ContextInput::omitted())
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
        let source = Zeroizing::new(self);
        let context = T::ContextInput::supplied(context.into());
        cipher.run(T::encryption(), &*source, context)
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
