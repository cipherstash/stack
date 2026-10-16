//! A newtype is transparent, so its value is not stored under a key and
//! there is nothing to rename.

use vitaminc_aead::Encrypt;

#[derive(Encrypt)]
struct Token(#[aead(rename = "token")] String);

fn main() {}
