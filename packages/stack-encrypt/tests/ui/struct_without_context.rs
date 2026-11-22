//! `struct = ..` requires an explicit container `scope = ".."`: the record's name
//! is part of the stored data's identity — the AAD of every ciphertext
//! derived from the struct and the domain of every term — so it is never
//! inferred from the Rust type's name. Two types named `Account` in
//! different modules must not silently share every field context.
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::StackCipherText;

#[derive(zeroize::Zeroize)]
struct User {
    email: String,
}

#[derive(EncryptTarget)]
#[stash(struct = User)]
struct EncryptedUser {
    email: StackCipherText,
}

fn main() {}
