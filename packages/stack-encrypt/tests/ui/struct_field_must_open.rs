//! Every field of a `struct = ..` record opens back into the plaintext
//! field it is derived from (`DecryptField<F, CallerContext>`), even when
//! the record derives `EncryptFrom` alone: the record's plan seals and
//! opens each field. A borrowed plaintext field cannot be opened into, and
//! a target with no `DecryptField` cannot open.
use stack_encrypt::target::{Decryptable, Encryption, AeadContext};
use stack_encrypt::{EncryptFrom, StackCipherText};

struct Profile {
    name: &'static str,
    bio: String,
}

/// A target with no `DecryptField`.
struct Opaque(#[allow(dead_code)] StackCipherText);
impl EncryptFrom<String> for Opaque {
    type Context = AeadContext;
    fn encryption<'s, K: stack_encrypt::KeysetRegistry + 'static>() -> Encryption<'s, String, Self, K, Self::Context> {
        <StackCipherText as EncryptFrom<String>>::encryption().map(Opaque)
    }
}
impl Decryptable for Opaque {
    const DECRYPTABLE: bool = true;
}

#[derive(EncryptFrom)]
#[stash(struct = Profile, context = "profiles")]
struct EncryptedProfile {
    name: StackCipherText,
    bio: Opaque,
}

fn main() {}
