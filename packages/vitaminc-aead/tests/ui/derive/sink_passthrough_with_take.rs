//! A passthrough field is lent to the sink, never taken out of `self`.

// Stack Encrypt's derives. stack-encrypt depends on this crate, so each
// derive here names this crate with `#[aead(crate = "::vitaminc_aead")]`.
use stack_encrypt_derive::Encrypt;

#[derive(Encrypt)]
#[aead(crate = "::vitaminc_aead")]
struct Row {
    #[aead(passthrough, take)]
    tenant: String,
    ssn: String,
}

fn main() {}
