use stack_encrypt::{DecryptInto, StackCipherText};

struct User {
    a: u32,
}

#[derive(DecryptInto)]
#[stash(plaintext = User)]
struct Rec {
    #[stash(decrypt, from = a)]
    a: StackCipherText,
    #[stash(decrypt, from = a)]
    b: StackCipherText,
}

fn main() {}
