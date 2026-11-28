//! `Option` and `Protected` pass the marker through only when what they
//! wrap carries it. A `Vec<i32>` reads a sequence, so neither an `Option`
//! of it, a `Protected` of it nor a `Protected` of an `Option` of it is
//! built by one scalar.

use vitaminc_aead::ScalarTarget;
use vitaminc_protected::Protected;

fn opens_one_leaf<T: ScalarTarget>() {}

fn main() {
    opens_one_leaf::<Option<Vec<i32>>>();
    opens_one_leaf::<Protected<Vec<i32>>>();
    opens_one_leaf::<Protected<Option<Vec<i32>>>>();
}
