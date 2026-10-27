use stack_encrypt::{Ciphertext, EncryptInto};
fn moved<K: 'static>(keyset: &stack_encrypt::KeysetCipher<'_, K>) {
    let value = String::from("secret");
    let _ = value.encrypt_into::<Ciphertext, _>(keyset);
    drop(value);
}
fn main() {}
