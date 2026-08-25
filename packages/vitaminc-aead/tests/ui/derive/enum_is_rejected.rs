// A ciphertext carries no authenticated variant discriminator, so any encoding
// the macro could pick would leak the variant or leave it forgeable.
use vitaminc_aead::{Decrypt, Encrypt};

#[derive(Encrypt, Decrypt)]
enum Choice {
    A(String),
    B(u32),
}

fn main() {}
