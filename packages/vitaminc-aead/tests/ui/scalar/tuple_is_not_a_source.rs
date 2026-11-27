//! A tuple is not a source at all, let alone a scalar: a pair of values
//! is a struct's job, which walks as a map.

use vitaminc_aead::Scalar;

fn seals_one_leaf<S: Scalar>(_: S) {}

fn main() {
    seals_one_leaf((1i32, 2i32));
}
