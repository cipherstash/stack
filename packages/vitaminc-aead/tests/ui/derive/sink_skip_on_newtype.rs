//! A newtype is transparent, so skipping its only field leaves nothing.

use vitaminc_aead::Encrypt;

#[derive(Encrypt)]
struct Wrapper(#[aead(skip)] String);

fn main() {}
