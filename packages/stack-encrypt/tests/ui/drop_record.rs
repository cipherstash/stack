use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::{DecryptInto, EncryptFrom, StackCipherText};

// `DecryptInto` moves the opened field out of `self`, which a `Drop` type
// (including `ZeroizeOnDrop`) forbids. The restriction is documented; this
// pins what the user sees.
#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = u32)]
struct Rec {
    #[stash(decrypt)]
    c: StackCipherText,
    hm: EqualityTerm,
}

impl Drop for Rec {
    fn drop(&mut self) {}
}

fn main() {}
