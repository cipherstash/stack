//! A `Vec<T>` of a scalar target reads a sequence with one leaf for each
//! element. So one scalar does not build it. `Vec<u8>` is different: it is
//! the bytes scalar, so one scalar builds it.

use vitaminc_aead::ScalarTarget;

fn opens_one_leaf<T: ScalarTarget>() {}

fn main() {
    opens_one_leaf::<Vec<u8>>();
    opens_one_leaf::<Vec<String>>();
}
