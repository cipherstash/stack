//! A field of an owned `struct = ..` record is given the field context that
//! the record builds, extended by the caller's context. A target that accepts
//! no caller context, or that requires a context of another type, cannot take
//! it. That field is a compile error.
use stack_encrypt::target::{
    AcceptsContext, DecryptSource, Decryptable, Decryption, EncryptTarget, Encryption,
    NoCallerContext, OptionalContext, RequiredContext, ScalarContext,
};
use stack_encrypt::{nonempty, Ciphertext};

/// Declares its whole context itself.
struct Fixed(Ciphertext);
impl EncryptTarget<i32> for Fixed {
    type ContextInput = NoCallerContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, i32, Self, K, Self::ContextInput> {
        stack_encrypt::target::scalar_ciphertext()
            .map(Self)
            .under(nonempty!("users/fixed"))
            .accepting()
    }
}
impl DecryptSource<i32> for Fixed {
    type ContextInput = NoCallerContext;
    fn decryption<K: 'static>(self, _: Self::ContextInput) -> Decryption<i32, K> {
        self.0.decryption(OptionalContext::<ScalarContext>::supplied("users/fixed".into()))
    }
}

impl Decryptable for Fixed {
    const DECRYPTABLE: bool = true;
}

/// Requires a row id from the caller, not a field context.
struct Bound(Ciphertext);
impl Decryptable for Bound {
    const DECRYPTABLE: bool = true;
}
impl EncryptTarget<i32> for Bound {
    type ContextInput = RequiredContext<u64>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, i32, Self, K, Self::ContextInput> {
        stack_encrypt::target::scalar_ciphertext().map(Self).accepting()
    }
}

#[derive(zeroize::Zeroize)]
struct Reading {
    fixed: i32,
    bound: i32,
}

#[derive(EncryptTarget)]
#[stash(struct = Reading, context = "readings")]
struct EncryptedReading {
    fixed: Fixed,
    bound: Bound,
}

fn main() {}
