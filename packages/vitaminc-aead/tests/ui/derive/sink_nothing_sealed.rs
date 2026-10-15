//! Every field skipped or passed through would seal nothing, so the
//! ciphertext would carry no tag at all.

use vitaminc_aead::Plaintext;

#[derive(Plaintext)]
struct Row {
    #[aead(passthrough)]
    id: i64,
    #[aead(skip)]
    cached: u32,
}

fn main() {}
