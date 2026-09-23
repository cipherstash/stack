//! An `AeadContext` is the context of a ciphertext-only record: nothing
//! converts it into the `CallerContext` a term's declaration wants, so a
//! record declaring it cannot hold a term.
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::AeadContext;
use stack_encrypt::{EncryptFrom, StackCipherText};

#[derive(EncryptFrom)]
#[stash(plaintext = u32, context_type = AeadContext)]
struct Indexed {
    c: StackCipherText,
    hm: EqualityTerm,
}

fn main() {}
