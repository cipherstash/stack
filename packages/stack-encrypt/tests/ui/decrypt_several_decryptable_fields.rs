use stack_encrypt::{DecryptInto, StackCipherText};

#[derive(DecryptInto)]
#[stash(plaintext = u32)]
struct Rec {
    a: StackCipherText,
    b: StackCipherText,
}

fn main() {}
