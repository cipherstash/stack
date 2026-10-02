use stack_encrypt::{EncryptFrom, StackCipherText};

#[derive(EncryptFrom)]
#[stash(plaintext = &str)]
struct Text {
    c: StackCipherText,
}

fn main() {}
