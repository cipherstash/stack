//! `row = ..` requires an explicit container `context = ".."`: the prefix is
//! part of the stored data's identity — the AAD of every ciphertext in the
//! row and the domain of every term — so it is never inferred from the Rust
//! type's name. Two types named `Account` in different modules must not
//! silently share every column context.
use stack_encrypt::{EncryptFrom, StackCipherText};

struct User {
    email: String,
}

#[derive(EncryptFrom)]
#[stash(row = User)]
struct EncryptedUser {
    email: StackCipherText,
}

fn main() {}
