//! A collection's elements must be opaque scalars. `u8` is not one: Vitamin
//! C keeps `Vec<u8>` a byte leaf and gives `u8` no source of its own, so a
//! byte vector is neither a column of bytes nor one ciphertext here (a whole
//! byte vector is a blob, a separate representation). A nullable element and
//! a borrowed element are not opaque scalars either. No vector, of bytes or
//! of scalars, encrypts into one `Ciphertext`, and the decrypt side refuses
//! the same element types.
use stack_encrypt::{Ciphertext, DecryptFrom, EncryptInto};
fn unsupported<K: 'static>(keyset: &stack_encrypt::KeysetCipher<'_, K>, column: Vec<Ciphertext>) {
    let _ = vec![1u8, 2].encrypt_into::<Vec<Ciphertext>, _>(keyset);
    let _ = vec![Some(1i32), None].encrypt_into::<Vec<Ciphertext>, _>(keyset);
    let _ = EncryptInto::encrypt_into::<Vec<Ciphertext>, _>(vec!["borrowed", "plaintext"], keyset);
    let _ = vec![1u8, 2].encrypt_into::<Ciphertext, _>(keyset);
    let _ = vec![1i32, 2].encrypt_into::<Ciphertext, _>(keyset);
    let _ = Vec::<u8>::decrypt_from(column.clone(), keyset);
    let _ = Vec::<Option<i32>>::decrypt_from(column, keyset);
}
fn main() {}
