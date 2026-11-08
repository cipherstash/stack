use stack_encrypt::{Ciphertext, DecryptFrom, EncryptInto};
use stack_encrypt::target::{DecryptSource, Decryption, EncryptTarget, Encryption, RequiredContext};

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
fn missing<K: 'static>(keyset: &stack_encrypt::KeysetCipher<'_, K>, encrypted: Required) {
    // u64: Default does not grant permission to omit a required context.
    let _ = 42i32.encrypt_into::<Required, _>(keyset);
    let _ = i32::decrypt_from(encrypted, keyset);
}
fn main() {}
