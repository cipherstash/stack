use stack_encrypt::{DecryptInto, StackCipherText};

/// A hand-written leaf that says nothing about whether it is decryptable.
struct Opaque;

#[derive(DecryptInto)]
#[stash(plaintext = u32)]
struct Rec {
    c: StackCipherText,
    o: Opaque,
}

fn main() {}
