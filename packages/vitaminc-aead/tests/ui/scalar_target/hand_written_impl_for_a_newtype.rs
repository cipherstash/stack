//! No one implements `ScalarTarget` by hand. A target is one when its sink
//! is marked. A derived newtype's sink is this crate's, so an impl written
//! for a newtype of a sequence conflicts with the one impl there is.

use vitaminc_aead::{Decrypt, ScalarTarget};

#[derive(Decrypt)]
struct Tags(Vec<String>);

impl ScalarTarget for Tags {}

fn main() {}
