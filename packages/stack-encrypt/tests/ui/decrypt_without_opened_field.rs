use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::{DecryptInto, StackCipherText};

#[derive(DecryptInto)]
#[stack_encrypt(plaintext = u32)]
struct Rec {
    c: StackCipherText,
    hm: EqualityTerm,
}

fn main() {}
