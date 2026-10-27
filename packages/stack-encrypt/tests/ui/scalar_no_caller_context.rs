use stack_encrypt::{DecryptFrom, EncryptInto};
use stack_encrypt::target::{DecryptSource, Decryption, EncryptTarget, Encryption, NoCallerContext};
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
fn extra<K: 'static>(keyset: &stack_encrypt::KeysetCipher<'_, K>) {
    let _ = 42i32.encrypt_into_with_context::<Fixed, _>(keyset, ());
    let _ = i32::decrypt_from_with_context(Fixed, keyset, ());
}
fn main() {}
