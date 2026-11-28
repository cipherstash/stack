//! `Option` and `Protected` are scalar targets only when the type they wrap
//! is one. A `Vec<i32>` reads a sequence. So one scalar does not build an
//! `Option` of it, a `Protected` of it, or a `Protected` of an `Option` of
//! it.

use vitaminc_aead::ScalarTarget;
use vitaminc_protected::Protected;

fn opens_one_leaf<T: ScalarTarget>() {}

fn main() {
    opens_one_leaf::<Option<Vec<i32>>>();
    opens_one_leaf::<Protected<Vec<i32>>>();
    opens_one_leaf::<Protected<Option<Vec<i32>>>>();
}
