//! An `AeadContext` carries only the AEAD encoding, so a record declaring it
//! cannot hold a term: the term's declaration wants a `CallerContext`, and
//! nothing converts an `AeadContext` into one.
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
