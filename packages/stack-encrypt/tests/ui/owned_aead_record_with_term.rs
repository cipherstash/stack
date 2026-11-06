//! An owned record with `plaintext` and `context_type = AeadContext` requires
//! an AEAD-only context. A term cannot be derived under that context, so the
//! term field is a compile error where it is declared.
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
