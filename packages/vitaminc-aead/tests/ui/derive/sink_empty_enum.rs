//! An enum with no variants has no value to seal.

use vitaminc_aead::Encrypt;

#[derive(Encrypt)]
enum Never {}

fn main() {}
