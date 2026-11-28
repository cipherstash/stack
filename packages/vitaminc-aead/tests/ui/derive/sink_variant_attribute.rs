//! A variant is stored as its discriminant, so there is nothing for an
//! attribute to describe.

// Stack Encrypt's derives. stack-encrypt depends on this crate, so each
// derive here names this crate with `#[aead(crate = "::vitaminc_aead")]`.
use stack_encrypt_derive::Encrypt;

#[derive(Encrypt)]
#[aead(crate = "::vitaminc_aead")]
enum Status {
    #[aead(rename = "on")]
    Active,
    Suspended,
}

fn main() {}
