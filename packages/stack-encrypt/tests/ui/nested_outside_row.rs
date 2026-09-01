//! `nested` opts a row field out of its inferred context. Outside a row it
//! is at best redundant — a `plaintext` record's `from` field with no
//! `context` is already handed `()` — so it is rejected rather than ignored.
use stack_encrypt::{EncryptFrom, StackCipherText};

struct User {
    email: String,
}

#[derive(EncryptFrom)]
#[stash(plaintext = User)]
struct EncryptedUser {
    #[stash(nested, from = email)]
    email: StackCipherText,
}

fn main() {}
