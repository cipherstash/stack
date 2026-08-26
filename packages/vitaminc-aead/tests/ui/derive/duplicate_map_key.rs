// Two fields under one key would overwrite each other on encrypt and be
// rejected as a duplicate on decrypt — an unreadable ciphertext with no error
// until read time.
use vitaminc_aead::{Decrypt, Encrypt};

#[derive(Encrypt, Decrypt)]
struct Clash {
    a: String,
    #[aead(rename = "a")]
    b: String,
}

fn main() {}
