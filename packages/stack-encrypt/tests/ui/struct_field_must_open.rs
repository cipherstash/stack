//! Every field of a `struct = ..` record that derives `DecryptSource` opens
//! back into the plaintext field it is derived from
//! (`DecryptField<F, CallerContext>`). A plaintext field with no `Decrypt`,
//! such as one that borrows its text, cannot be opened into, and a target
//! with no `DecryptField` cannot open.
use stack_encrypt::target::{
    AeadContext, DecryptSource, Decryptable, EncryptTarget, Encryption, RequiredContext,
};
use stack_encrypt::{Encrypt, StackCipherText};
use vitaminc_aead::plaintext::Sink;
use zeroize::Zeroize;

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
impl Zeroize for Name {
    fn zeroize(&mut self) {
        self.0 = "";
    }
}

#[derive(Zeroize)]
struct Profile {
    name: Name,
    bio: String,
}

/// A target with no `DecryptField`.
struct Opaque(#[allow(dead_code)] StackCipherText);
impl EncryptTarget<String> for Opaque {
    type ContextInput = RequiredContext<AeadContext>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, String, Self, K, Self::ContextInput> {
        <StackCipherText as EncryptTarget<String>>::encryption().map(Opaque)
    }
}
impl Decryptable for Opaque {
    const DECRYPTABLE: bool = true;
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Profile, scope = "profiles")]
struct EncryptedProfile {
    name: StackCipherText,
    bio: Opaque,
}

fn main() {}
