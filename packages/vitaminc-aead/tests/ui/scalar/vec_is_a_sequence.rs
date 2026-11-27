//! A `Vec<T>` of a scalar `T` walks as a sequence of leaves, one per
//! element, so it is not a `Scalar`. (`Vec<u8>` is: it is one byte leaf.)

use vitaminc_aead::Scalar;

fn seals_one_leaf<S: Scalar>(_: S) {}

fn main() {
    seals_one_leaf(vec![1i32, 2, 3]);
}
