//! The generic impls pass `Scalar` through a wrapper only when the wrapped
//! type is itself a `Scalar`. A `Vec<i32>` is a sequence, so neither a
//! `Protected` holding it, a borrow of that, a `ProtectedRef` to it nor a
//! double borrow of it is a `Scalar`.

use vitaminc_aead::Scalar;
use vitaminc_protected::{AsProtectedRef, Protected};

fn seals_one_leaf<S: Scalar>(_: S) {}

fn main() {
    let owned = Protected::new(vec![1i32, 2]);
    seals_one_leaf(&owned);
    seals_one_leaf(owned.as_protected_ref());
    seals_one_leaf(owned);
    seals_one_leaf(&&vec![1i32, 2]);
}
