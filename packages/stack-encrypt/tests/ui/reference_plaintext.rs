use stack_encrypt::{EncryptFrom, StackCipherText};

#[derive(EncryptFrom)]
#[stack_encrypt(plaintext = &str)]
struct Text {
    c: StackCipherText,
}

fn main() {}
