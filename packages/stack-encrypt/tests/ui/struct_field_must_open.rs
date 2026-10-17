//! Every field of a `struct = ..` record opens back into the plaintext
//! field it is derived from (`DecryptField<F, CallerContext>`), even when
//! the record derives `EncryptFrom` alone: the record's plan seals and
//! opens each field. A plaintext field with no `Decrypt`, such as one that
//! borrows its text, cannot be opened into, and a target with no
//! `DecryptField` cannot open.
use stack_encrypt::target::{Decryptable, Encryption, AeadContext};
use stack_encrypt::{EncryptFrom, Encrypt, StackCipherText};
use vitaminc_aead::plaintext::Sink;

/// Text it borrows: it seals, and there is nothing to open it into.
#[derive(Clone)]
struct Name(&'static str);
impl Encrypt for Name {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        self.0.visit(sink)
    }
}
impl Encrypt for &Name {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        self.0.visit(sink)
    }
}

struct Profile {
    name: Name,
    bio: String,
}

/// A target with no `DecryptField`.
struct Opaque(#[allow(dead_code)] StackCipherText);
impl EncryptFrom<String> for Opaque {
    type Context = AeadContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, String, Self, K, Self::Context> {
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
