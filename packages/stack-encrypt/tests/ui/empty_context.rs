use stack_encrypt::{EncryptFrom, StackCipherText};

struct User {
    email: String,
}

#[derive(EncryptFrom)]
#[stash(plaintext = User)]
struct EncryptedUser {
    #[stash(from = email, context = "")]
    email: StackCipherText,
}

fn main() {}
