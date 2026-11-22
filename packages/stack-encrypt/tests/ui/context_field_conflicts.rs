//! A record stores its context in one field, and that field is metadata: it
//! is not also derived, defaulted or passed through.
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::StackCipherText;

#[derive(EncryptTarget)]
struct Twice {
    #[stash(context_field)]
    one: String,
    #[stash(context_field)]
    two: String,
    c: StackCipherText,
}

#[derive(EncryptTarget)]
struct Defaulted {
    #[stash(context_field, default)]
    i: String,
    c: StackCipherText,
}

fn main() {}
