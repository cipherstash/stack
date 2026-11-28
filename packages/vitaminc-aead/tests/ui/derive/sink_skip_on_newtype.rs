//! A newtype is transparent, so skipping its only field leaves nothing.

// Stack Encrypt's derives. stack-encrypt depends on this crate, so each
// derive here names this crate with `#[aead(crate = "::vitaminc_aead")]`.
use stack_encrypt_derive::Encrypt;

#[derive(Encrypt)]
#[aead(crate = "::vitaminc_aead")]
struct Wrapper(#[aead(skip)] String);

fn main() {}
