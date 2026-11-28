//! A derived struct reads a map with one leaf for each field. So one scalar
//! does not build it, even when the struct has a single field.

use vitaminc_aead::{Decrypt, ScalarTarget};

#[derive(Decrypt)]
struct Account {
    id: u64,
}

fn opens_one_leaf<T: ScalarTarget>() {}

fn main() {
    opens_one_leaf::<Account>();
}
