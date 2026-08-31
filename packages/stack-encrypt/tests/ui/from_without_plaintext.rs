use stack_encrypt::{EncryptFrom, StackCipherText};

#[derive(EncryptFrom)]
struct Row {
    #[stash(from = age, context = "users/age")]
    age: StackCipherText,
}

fn main() {}
