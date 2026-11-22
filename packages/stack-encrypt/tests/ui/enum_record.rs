//! A record is a struct: the derives refuse an enum.
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::StackCipherText;

#[derive(EncryptTarget)]
enum Choice {
    A(StackCipherText),
    B(StackCipherText),
}

fn main() {}
