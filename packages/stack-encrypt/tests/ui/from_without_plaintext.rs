//! `from = ..` reaches into a field of the plaintext, which is what
//! `#[stash(struct = ..)]` means; a `plaintext` record derives every field
//! from the whole value.
use stack_encrypt::{EncryptFrom, StackCipherText};

struct User {
    age: u32,
}

#[derive(EncryptFrom)]
#[stash(plaintext = User)]
struct Row {
    #[stash(from = age)]
    age: StackCipherText,
}

#[derive(EncryptFrom)]
struct Unnamed {
    #[stash(from = age)]
    age: StackCipherText,
}

fn main() {}
