//! No one implements `ScalarTarget` by hand. A derived struct's sink is
//! generated beside the struct, and it is not marked, because it reads a
//! map. An impl written for the struct is refused for that reason.

use vitaminc_aead::{Decrypt, ScalarTarget};

#[derive(Decrypt)]
struct Account {
    id: u64,
}

impl ScalarTarget for Account {}

fn main() {}
