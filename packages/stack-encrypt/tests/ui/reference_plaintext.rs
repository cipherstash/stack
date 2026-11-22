//! A `plaintext` type is owned: the generated impl has no lifetime to give
//! a reference.
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::StackCipherText;

#[derive(EncryptTarget)]
#[stash(plaintext = &str)]
struct Text {
    c: StackCipherText,
}

fn main() {}
