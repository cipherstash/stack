//! A `Vec<T>` of a scalar target reads a sequence, one leaf per element,
//! so one scalar does not build it. (`Vec<u8>` is the byte leaf, and one
//! scalar does build it.)

use vitaminc_aead::ScalarTarget;

fn opens_one_leaf<T: ScalarTarget>() {}

fn main() {
    opens_one_leaf::<Vec<u8>>();
    opens_one_leaf::<Vec<String>>();
}
