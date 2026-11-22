//! `struct` and `plaintext` both name the plaintext, so a record gives one.
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::StackCipherText;

#[derive(zeroize::Zeroize)]
struct User {
    email: String,
}

#[derive(EncryptTarget)]
#[stash(struct = User, plaintext = User)]
struct EncryptedUser {
    email: StackCipherText,
}

fn main() {}
