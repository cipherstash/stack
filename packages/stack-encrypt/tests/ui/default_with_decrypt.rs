//! A `default` field is filled, not derived, so it cannot be the field that
//! decryption opens.
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::StackCipherText;

#[derive(EncryptTarget)]
struct Rec {
    c: StackCipherText,
    #[stash(default, decrypt)]
    v: u8,
}

fn main() {}
