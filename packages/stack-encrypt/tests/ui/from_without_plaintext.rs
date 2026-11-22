//! `from = ..` reaches into a field of the plaintext, which is what
//! `#[stash(struct = ..)]` means; a `plaintext` record derives every field
//! from the whole value.
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::StackCipherText;

#[derive(zeroize::Zeroize)]
struct User {
    age: u32,
}

#[derive(EncryptTarget)]
#[stash(plaintext = User)]
struct Row {
    #[stash(from = age)]
    age: StackCipherText,
}

#[derive(EncryptTarget)]
struct Unnamed {
    #[stash(from = age)]
    age: StackCipherText,
}

fn main() {}
