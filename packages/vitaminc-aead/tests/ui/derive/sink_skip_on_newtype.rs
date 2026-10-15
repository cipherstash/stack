//! A newtype is transparent, so skipping its only field leaves nothing.

use vitaminc_aead::Plaintext;

#[derive(Plaintext)]
struct Wrapper(#[aead(skip)] String);

fn main() {}
