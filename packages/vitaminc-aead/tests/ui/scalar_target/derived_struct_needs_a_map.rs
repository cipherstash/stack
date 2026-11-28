//! A derived struct reads a map, one leaf per field, so one scalar does
//! not build it, even with a single field.

use vitaminc_aead::{Decrypt, ScalarTarget};

#[derive(Decrypt)]
struct Account {
    id: u64,
}

fn opens_one_leaf<T: ScalarTarget>() {}

fn main() {
    opens_one_leaf::<Account>();
}
