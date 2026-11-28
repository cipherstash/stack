//! Every field skipped or passed through would seal nothing, so the
//! ciphertext would carry no tag at all.

// Stack Encrypt's derives. stack-encrypt depends on this crate, so each
// derive here names this crate with `#[aead(crate = "::vitaminc_aead")]`.
use stack_encrypt_derive::Encrypt;

#[derive(Encrypt)]
#[aead(crate = "::vitaminc_aead")]
struct Row {
    #[aead(passthrough)]
    id: i64,
    #[aead(skip)]
    cached: u32,
}

fn main() {}
