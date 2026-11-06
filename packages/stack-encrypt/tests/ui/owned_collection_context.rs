//! A column takes exactly the element's caller-context capability: a column
//! of a `RequiredContext` target cannot omit the context, even for a `u64`
//! that implements `Default`, and a column of a `NoCallerContext` target
//! cannot be handed one.
use stack_encrypt::target::{
    DecryptSource, Decryption, EncryptTarget, Encryption, NoCallerContext, RequiredContext,
};
use stack_encrypt::{Ciphertext, DecryptFrom, EncryptInto};

struct Required(Ciphertext);
impl EncryptTarget<i32> for Required {
    type ContextInput = RequiredContext<u64>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, i32, Self, K, Self::ContextInput> {
        stack_encrypt::target::scalar_ciphertext().map(Self).accepting()
    }
}
impl DecryptSource<i32> for Required {
    type ContextInput = RequiredContext<u64>;
    fn decryption<K: 'static>(self, _: Self::ContextInput) -> Decryption<i32, K> {
        Decryption::failed(stack_encrypt::Error::Aead)
    }
}
struct Fixed;
impl EncryptTarget<i32> for Fixed {
    type ContextInput = NoCallerContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, i32, Self, K, Self::ContextInput> {
        Encryption::failed(stack_encrypt::Error::Aead)
    }
}
impl DecryptSource<i32> for Fixed {
    type ContextInput = NoCallerContext;
    fn decryption<K: 'static>(self, _: Self::ContextInput) -> Decryption<i32, K> {
        Decryption::failed(stack_encrypt::Error::Aead)
    }
}
fn capabilities<K: 'static>(
    keyset: &stack_encrypt::KeysetCipher<'_, K>,
    required: Vec<Required>,
    fixed: Vec<Fixed>,
) {
    let _ = vec![1i32, 2].encrypt_into::<Vec<Required>, _>(keyset);
    let _ = Vec::<i32>::decrypt_from(required, keyset);
    let _ = vec![1i32, 2].encrypt_into_with_context::<Vec<Fixed>, _>(keyset, ());
    let _ = Vec::<i32>::decrypt_from_with_context(fixed, keyset, ());
}
fn main() {}
