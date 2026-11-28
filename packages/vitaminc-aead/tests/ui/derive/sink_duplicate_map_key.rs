// Two fields under one key would overwrite each other on encrypt and be
// rejected as a duplicate on decrypt — an unreadable ciphertext with no error
// until read time.
// Stack Encrypt's derives. stack-encrypt depends on this crate, so each
// derive here names this crate with `#[aead(crate = "::vitaminc_aead")]`.
use stack_encrypt_derive::{Decrypt, Encrypt};

#[derive(Encrypt, Decrypt)]
#[aead(crate = "::vitaminc_aead")]
struct Clash {
    a: String,
    #[aead(rename = "a")]
    b: String,
}

fn main() {}
