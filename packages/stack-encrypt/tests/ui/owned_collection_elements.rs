//! A collection's elements must be opaque scalars. `u8` is not one: Vitamin
//! C keeps `Vec<u8>` a byte leaf and gives `u8` no source of its own, so a
//! byte vector is neither a column of bytes nor one ciphertext here (a whole
//! byte vector is a blob, a separate representation). A nullable element and
//! a borrowed element are not opaque scalars either.
use stack_encrypt::{Ciphertext, EncryptInto};
fn unsupported<K: 'static>(keyset: &stack_encrypt::KeysetCipher<'_, K>) {
    let _ = vec![1u8, 2].encrypt_into::<Vec<Ciphertext>, _>(keyset);
    let _ = vec![Some(1i32), None].encrypt_into::<Vec<Ciphertext>, _>(keyset);
    let _ = vec!["borrowed", "plaintext"].encrypt_into::<Vec<Ciphertext>, _>(keyset);
}
fn main() {}
