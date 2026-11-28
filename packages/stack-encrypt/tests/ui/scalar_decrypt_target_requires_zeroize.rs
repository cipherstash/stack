//! One scalar builds a newtype that derives `Decrypt` over a `String`. A
//! `Ciphertext` still does not decrypt into the newtype, because the newtype
//! does not implement `Zeroize`.
use stack_encrypt::{Ciphertext, Decrypt, KeysetCipher};

#[derive(Decrypt)]
struct Email(String);

fn refused<K: 'static>(keyset: &KeysetCipher<'_, K>, ciphertext: Ciphertext) {
    let _ = keyset.decrypt::<Email>(ciphertext);
}

fn main() {}
