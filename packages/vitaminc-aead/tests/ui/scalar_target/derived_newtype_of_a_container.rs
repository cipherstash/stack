//! A derived newtype reads what its inner type reads. A newtype of a
//! sequence needs a sequence, so one scalar does not build it.

use vitaminc_aead::{Decrypt, ScalarTarget};

#[derive(Decrypt)]
struct Tags(Vec<String>);

fn opens_one_leaf<T: ScalarTarget>() {}

fn main() {
    opens_one_leaf::<Tags>();
}
