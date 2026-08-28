use stack_encrypt::{DecryptInto, StackCipherText};

struct User {
    a: u32,
}

#[derive(DecryptInto)]
#[stack_encrypt(plaintext = User)]
struct Rec {
    #[stack_encrypt(decrypt, from = a)]
    a: StackCipherText,
    #[stack_encrypt(decrypt, from = a)]
    b: StackCipherText,
}

fn main() {}
