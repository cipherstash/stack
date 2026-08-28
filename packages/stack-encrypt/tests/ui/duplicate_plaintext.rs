use stack_encrypt::{EncryptFrom, StackCipherText};

#[derive(EncryptFrom)]
#[stash(plaintext = u32, plaintext = u32)]
struct Dup {
    c: StackCipherText,
}

fn main() {}
