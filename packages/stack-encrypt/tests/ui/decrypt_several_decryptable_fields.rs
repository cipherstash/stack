//! A `plaintext` record opens through one ciphertext. With two, and neither
//! marked `#[stash(decrypt)]`, the derive cannot choose.
use stack_encrypt::target::DecryptSource;
use stack_encrypt::StackCipherText;

#[derive(DecryptSource)]
#[stash(plaintext = u32)]
struct Rec {
    a: StackCipherText,
    b: StackCipherText,
}

fn main() {}
