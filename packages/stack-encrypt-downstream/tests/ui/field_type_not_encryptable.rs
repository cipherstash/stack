//! A field whose type implements neither `Encrypt` nor `Decrypt`. Each
//! error names the trait by its `stack_encrypt` path.
use stack_encrypt::{Decrypt, Encrypt};

struct Opaque;

#[derive(Encrypt, Decrypt)]
struct Record {
    name: String,
    secret: Opaque,
}

fn main() {}
