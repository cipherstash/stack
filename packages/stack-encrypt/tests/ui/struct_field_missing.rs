//! A field is derived from the plaintext field of its own name; a name the
//! plaintext does not have is reported by rustc at the field.
use stack_encrypt::{EncryptFrom, StackCipherText};

struct User {
    email: String,
}

#[derive(EncryptFrom)]
#[stash(struct = User, context = "user")]
struct EncryptedUser {
    email: StackCipherText,
    nickname: StackCipherText,
}

fn main() {}
