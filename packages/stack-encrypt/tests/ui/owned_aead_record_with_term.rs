//! A `plaintext` owned record declared `context_type = AeadContext` requires
//! an AEAD-only context, which a term cannot derive under: the term field is
//! refused where it is declared.
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{AeadContext, EncryptTarget};
use stack_encrypt::Ciphertext;

#[derive(EncryptTarget)]
#[stash(plaintext = String, context_type = AeadContext)]
struct SealedAndIndexed {
    c: Ciphertext,
    hm: EqualityTerm,
}

fn main() {}
