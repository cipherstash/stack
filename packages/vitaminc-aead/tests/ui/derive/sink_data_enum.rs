//! A variant with fields has no agreed payload layout, so the sink derives
//! accept only fieldless enums and say so.

use vitaminc_aead::Decrypt;
use vitaminc_aead::Encrypt;

#[derive(Encrypt, Decrypt)]
enum Choice {
    Text(String),
    Number(u32),
    Nothing,
}

fn main() {}
