//! No one implements `ScalarTarget` directly. A target is a `ScalarTarget`
//! when its sink implements `TakesScalar`. The sink of a derived newtype is
//! defined in vitaminc-aead. So an impl of `ScalarTarget` for a newtype of a
//! sequence conflicts with the blanket impl.

use vitaminc_aead::{Decrypt, ScalarTarget};

#[derive(Decrypt)]
struct Tags(Vec<String>);

impl ScalarTarget for Tags {}

fn main() {}
