use stack_encrypt::{EncryptFrom, StackCipherText};

struct User {
    email: String,
}

#[derive(EncryptFrom)]
#[stash(struct = User, plaintext = User)]
struct EncryptedUser {
    email: StackCipherText,
}

fn main() {}
