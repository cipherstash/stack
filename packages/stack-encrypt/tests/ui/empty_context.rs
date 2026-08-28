use stack_encrypt::{EncryptFrom, StackCipherText};

struct User {
    email: String,
}

#[derive(EncryptFrom)]
#[stack_encrypt(plaintext = User)]
struct EncryptedUser {
    #[stack_encrypt(from = email, context = "")]
    email: StackCipherText,
}

fn main() {}
