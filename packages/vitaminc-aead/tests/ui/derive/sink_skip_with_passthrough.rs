//! A skipped field has no entry to pass through.

// Stack Encrypt's derives. stack-encrypt depends on this crate, so each
// derive here names this crate with `#[aead(crate = "::vitaminc_aead")]`.
use stack_encrypt_derive::Decrypt;

#[derive(Decrypt)]
#[aead(crate = "::vitaminc_aead")]
struct Row {
    #[aead(skip, passthrough)]
    id: i64,
    ssn: String,
}

fn main() {}
