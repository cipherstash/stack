use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::{DecryptInto, StackCipherText};

#[derive(DecryptInto)]
#[stash(plaintext = u32)]
struct Rec {
    c: StackCipherText,
    hm: EqualityTerm,
}

fn main() {}
