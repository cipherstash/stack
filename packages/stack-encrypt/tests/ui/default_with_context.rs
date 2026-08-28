use stack_encrypt::{EncryptFrom, StackCipherText};

#[derive(EncryptFrom)]
struct Rec {
    c: StackCipherText,
    #[stack_encrypt(default, context = "x")]
    v: u8,
}

fn main() {}
