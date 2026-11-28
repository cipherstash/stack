//! A derived newtype is a `Scalar` only when its inner type is one. A
//! newtype over a `Vec` encrypts as a sequence. A newtype over an `Option`
//! can be absent. So neither newtype is a `Scalar`, by value or by
//! reference. Both still derive `Encrypt`.

use vitaminc_aead::{Encrypt, Scalar};

#[derive(Encrypt)]
struct Tags(Vec<String>);

#[derive(Encrypt)]
struct Nickname(Option<String>);

#[derive(Encrypt)]
struct Wrapper<T>(T);

fn seals_one_leaf<S: Scalar>(_: S) {}

fn main() {
    seals_one_leaf(Tags(vec![]));
    seals_one_leaf(&Tags(vec![]));
    seals_one_leaf(Nickname(None));
    seals_one_leaf(Wrapper(vec![1i32]));
}
