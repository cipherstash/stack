use stack_encrypt::{EncryptFrom, StackCipherText};

#[derive(EncryptFrom)]
enum Choice {
    A(StackCipherText),
    B(StackCipherText),
}

fn main() {}
