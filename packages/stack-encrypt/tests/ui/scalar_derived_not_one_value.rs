//! A derived type that is not one value still derives `Encrypt`. So it can
//! be a field of a struct. `keyset.encrypt` refuses each of these types:
//!
//! - a newtype over a `Vec`
//! - a newtype over an `Option`
//! - a struct with named fields
//!
//! Each error says what `keyset.encrypt` encrypts, and what to use instead.
use stack_encrypt::{Encrypt, KeysetCipher};
use zeroize::Zeroize;

#[derive(Encrypt, Zeroize)]
struct Tags(Vec<String>);

#[derive(Encrypt, Zeroize)]
struct Nickname(Option<String>);

#[derive(Encrypt, Zeroize)]
struct Profile {
    name: String,
}

fn refused<K: 'static>(keyset: &KeysetCipher<'_, K>) {
    let _ = keyset.encrypt(Tags(vec!["admin".into()]));
    let _ = keyset.encrypt(Nickname(None));
    let _ = keyset.encrypt(Profile { name: "Ada".into() });
}

fn main() {}
