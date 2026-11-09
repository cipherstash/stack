//! `passthrough` moves a field of the plaintext struct into an owned record,
//! in the clear. The attribute is refused on the structural derives, on a
//! `plaintext` record, and beside the attributes of a derived field.
use stack_encrypt::target::{DecryptSource, EncryptTarget};
use stack_encrypt::{Ciphertext, DecryptInto, EncryptFrom, StackCipherText};

#[derive(zeroize::Zeroize)]
struct User {
    id: u64,
    email: String,
}

/// The structural derive cannot move a field, because it runs over a borrow.
#[derive(EncryptFrom, DecryptInto)]
#[stash(struct = User, scope = "users")]
struct Structural {
    #[stash(passthrough)]
    id: u64,
    email: StackCipherText,
}

/// A `plaintext` record derives every field from the whole value, so it has no
/// field to pass through.
#[derive(EncryptTarget)]
#[stash(plaintext = String)]
struct WholeValue {
    #[stash(passthrough)]
    id: u64,
    email: Ciphertext,
}

/// A passthrough field is moved as it is, so it cannot also be derived.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, scope = "users")]
struct Marked {
    #[stash(passthrough, decrypt)]
    id: u64,
    email: Ciphertext,
}

/// One plaintext field has one output.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, scope = "users")]
struct Twice {
    #[stash(passthrough, from = email)]
    plain_email: String,
    email: Ciphertext,
}

fn main() {}
