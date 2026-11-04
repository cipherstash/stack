//! An `Option<T>` walks as one leaf, a value or a null, but it is not a
//! `Scalar`: a caller that asks for a scalar is asking for a value that is
//! there.

use vitaminc_aead::Scalar;

fn seals_one_leaf<S: Scalar>(_: S) {}

fn main() {
    seals_one_leaf(Some(42i32));
}
