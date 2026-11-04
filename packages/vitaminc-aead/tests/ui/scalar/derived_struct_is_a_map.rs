//! A derived struct walks as a map, one leaf per field, so it is not a
//! `Scalar` even with a single field.

use vitaminc_aead::{Encrypt, Scalar};

#[derive(Encrypt)]
struct Account {
    id: u64,
}

fn seals_one_leaf<S: Scalar>(_: S) {}

fn main() {
    seals_one_leaf(Account { id: 1 });
}
