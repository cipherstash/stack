//! A newtype is transparent, so its value is not stored under a key and
//! there is nothing to rename.

// Stack Encrypt's derives. stack-encrypt depends on this crate, so each
// derive here names this crate with `#[aead(crate = "::vitaminc_aead")]`.
use stack_encrypt_derive::Encrypt;

#[derive(Encrypt)]
#[aead(crate = "::vitaminc_aead")]
struct Token(#[aead(rename = "token")] String);

fn main() {}
