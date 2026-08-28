use stack_encrypt::{EncryptFrom, StackCipherText};

#[derive(EncryptFrom)]
struct Row {
    #[stack_encrypt(from = age, context = "users/age")]
    age: StackCipherText,
}

fn main() {}
