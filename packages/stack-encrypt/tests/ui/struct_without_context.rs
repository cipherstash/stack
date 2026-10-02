//! `struct = ..` requires an explicit container `context = ".."`: the prefix
//! is part of the stored data's identity — the AAD of every ciphertext
//! derived from the struct and the domain of every term — so it is never
//! inferred from the Rust type's name. Two types named `Account` in
//! different modules must not silently share every field context.
use stack_encrypt::{EncryptFrom, StackCipherText};

struct User {
    email: String,
}

#[derive(EncryptFrom)]
#[stash(struct = User)]
struct EncryptedUser {
    email: StackCipherText,
}

fn main() {}
