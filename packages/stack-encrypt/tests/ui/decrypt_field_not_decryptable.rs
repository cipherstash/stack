//! Every field of a record that derives `DecryptSource` says whether it is
//! decryptable (`Decryptable`) and how it opens (`DecryptField`). A field
//! type that says neither is refused at the field.
use stack_encrypt::target::DecryptSource;
use stack_encrypt::StackCipherText;

/// A hand-written leaf that says nothing about whether it is decryptable.
struct Opaque;

#[derive(DecryptSource)]
#[stash(plaintext = u32)]
struct Rec {
    c: StackCipherText,
    o: Opaque,
}

fn main() {}
