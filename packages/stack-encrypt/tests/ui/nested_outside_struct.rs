//! `nested` opts a field out of the context a `struct` derive infers. With a
//! `plaintext` record there is no inferred context to opt out of — a field
//! with no `context` is already handed the caller's — so it is rejected
//! rather than ignored.
use stack_encrypt::{EncryptFrom, StackCipherText};

#[derive(EncryptFrom)]
#[stash(plaintext = u32)]
struct Rec {
    #[stash(nested)]
    c: StackCipherText,
}

fn main() {}
