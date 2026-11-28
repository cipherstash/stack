//! The wire holds a `u32`, so a discriminant has to be an unsigned integer
//! literal that fits one.

// Stack Encrypt's derives. stack-encrypt depends on this crate, so each
// derive here names this crate with `#[aead(crate = "::vitaminc_aead")]`.
use stack_encrypt_derive::Encrypt;

#[derive(Encrypt)]
#[aead(crate = "::vitaminc_aead")]
enum Status {
    Active = -1,
    Suspended,
}

fn main() {}
