//! The wire holds a `u32`, so a discriminant has to be an unsigned integer
//! literal that fits one.

use vitaminc_aead::Plaintext;

#[derive(Plaintext)]
enum Status {
    Active = -1,
    Suspended,
}

fn main() {}
