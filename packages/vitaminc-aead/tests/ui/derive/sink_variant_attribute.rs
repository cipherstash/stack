//! A variant is stored as its discriminant, so there is nothing for an
//! attribute to describe.

use vitaminc_aead::Plaintext;

#[derive(Plaintext)]
enum Status {
    #[aead(rename = "on")]
    Active,
    Suspended,
}

fn main() {}
