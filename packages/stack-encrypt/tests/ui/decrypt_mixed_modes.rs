use stack_encrypt::{DecryptInto, StackCipherText};

struct User {
    a: u32,
    b: u32,
}

#[derive(DecryptInto)]
#[stash(plaintext = User)]
struct Rec {
    #[stash(decrypt, from = a)]
    a: StackCipherText,
    #[stash(decrypt)]
    b: StackCipherText,
}

fn main() {}
