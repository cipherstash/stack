//! No one implements `ScalarTarget` directly. The sink of a derived struct
//! is generated beside the struct. That sink reads a map, so it does not
//! implement `TakesScalar`. So the compiler rejects an impl of
//! `ScalarTarget` for the struct.

use vitaminc_aead::{Decrypt, ScalarTarget};

#[derive(Decrypt)]
struct Account {
    id: u64,
}

impl ScalarTarget for Account {}

fn main() {}
