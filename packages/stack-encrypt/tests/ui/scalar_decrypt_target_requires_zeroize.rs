//! One scalar builds a newtype that derives `Decrypt` over a `String`. A
//! `Ciphertext` still does not decrypt into the newtype, because the newtype
//! does not implement `Zeroize`. The same is true of a `uuid::Uuid`: the
//! error points to `value::Uuid`.
use stack_encrypt::{Ciphertext, Decrypt, KeysetCipher};

#[derive(Decrypt)]
struct Email(String);

fn refused<K: 'static>(keyset: &KeysetCipher<'_, K>, ciphertext: Ciphertext) {
    let _ = keyset.decrypt::<Email>(ciphertext.clone());
    let _ = keyset.decrypt::<uuid::Uuid>(ciphertext);
}

fn main() {}
