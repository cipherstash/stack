//! A newtype is transparent, so its value is not stored under a key and
//! there is nothing to rename.

use vitaminc_aead::Plaintext;

#[derive(Plaintext)]
struct Token(#[aead(rename = "token")] String);

fn main() {}
