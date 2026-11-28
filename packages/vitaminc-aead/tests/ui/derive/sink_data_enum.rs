//! A variant with fields has no agreed payload layout, so the sink derives
//! accept only fieldless enums and say so.

// Stack Encrypt's derives. stack-encrypt depends on this crate, so each
// derive here names this crate with `#[aead(crate = "::vitaminc_aead")]`.
use stack_encrypt_derive::Decrypt;
use stack_encrypt_derive::Encrypt;

#[derive(Encrypt, Decrypt)]
#[aead(crate = "::vitaminc_aead")]
enum Choice {
    Text(String),
    Number(u32),
    Nothing,
}

fn main() {}
