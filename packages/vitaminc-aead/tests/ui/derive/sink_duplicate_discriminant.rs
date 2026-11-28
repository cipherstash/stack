//! Two variants with one discriminant would be stored as the same value.

// Stack Encrypt's derives. stack-encrypt depends on this crate, so each
// derive here names this crate with `#[aead(crate = "::vitaminc_aead")]`.
use stack_encrypt_derive::Decrypt;

#[derive(Decrypt)]
#[aead(crate = "::vitaminc_aead")]
enum Status {
    Active = 1,
    Suspended = 0,
    Closed,
}

fn main() {}
