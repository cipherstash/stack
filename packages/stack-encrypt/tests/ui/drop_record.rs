use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{DecryptSource, EncryptTarget};
use stack_encrypt::StackCipherText;

// `DecryptSource` moves the opened field out of `self`, which a `Drop` type
// (including `ZeroizeOnDrop`) forbids. The restriction is documented; this
// pins what the user sees.
#[derive(EncryptTarget, DecryptSource)]
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
