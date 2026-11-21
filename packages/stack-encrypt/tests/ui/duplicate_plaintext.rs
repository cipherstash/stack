//! `plaintext` can be repeated, one impl for each type, and each type is
//! listed once.
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::StackCipherText;

#[derive(EncryptTarget)]
#[stash(plaintext = u32, plaintext = u32)]
struct Dup {
    c: StackCipherText,
}

fn main() {}
