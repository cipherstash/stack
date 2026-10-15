//! An enum with no variants has no value to seal.

use vitaminc_aead::Plaintext;

#[derive(Plaintext)]
enum Never {}

fn main() {}
