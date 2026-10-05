//! A literal context is one label segment, as a plan's context segments are.
//! `"users/email"` would be one escaped part here and two segments in a plan,
//! two different contexts, so it is refused.
use stack_encrypt::{EncryptFrom, StackCipherText};

#[derive(EncryptFrom)]
#[stash(plaintext = String)]
struct Pinned {
    #[stash(context = "users/email")]
    c: StackCipherText,
}

fn main() {}
