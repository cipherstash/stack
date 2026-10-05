use stack_encrypt::{EncryptFrom, StackCipherText};
#[derive(EncryptFrom)]
struct Twice {
    #[stash(context_field)]
    one: String,
    #[stash(context_field)]
    two: String,
    c: StackCipherText,
}
#[derive(EncryptFrom)]
struct Defaulted {
    #[stash(context_field, default)]
    i: String,
    c: StackCipherText,
}
fn main() {}
