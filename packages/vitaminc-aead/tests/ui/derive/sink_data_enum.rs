//! A variant with fields has no agreed payload layout, so the sink derives
//! accept only fieldless enums and say so.

use vitaminc_aead::Decrypt;
use vitaminc_aead::Plaintext;

#[derive(Plaintext, Decrypt)]
enum Choice {
    Text(String),
    Number(u32),
    Nothing,
}

fn main() {}
