use stack_encrypt::{EncryptFrom, StackCipherText};

#[derive(EncryptFrom)]
struct Rec {
    c: StackCipherText,
    #[stash(default, context = "x")]
    v: u8,
}

fn main() {}
