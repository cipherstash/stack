//! `passthrough` carries a field of the plaintext struct into an owned
//! record in the clear. It has no form on the structural derives, on a
//! `plaintext` record, or beside the attributes of a derived field.
use stack_encrypt::target::{DecryptSource, EncryptTarget};
use stack_encrypt::{Ciphertext, DecryptInto, EncryptFrom, StackCipherText};

#[derive(zeroize::Zeroize)]
struct User {
    id: u64,
    email: String,
}

/// The structural derive moves nothing: it runs over a borrow.
#[derive(EncryptFrom, DecryptInto)]
#[stash(struct = User, context = "users")]
struct Structural {
    #[stash(passthrough)]
    id: u64,
    email: StackCipherText,
}

/// A `plaintext` record derives every field from the whole value.
#[derive(EncryptTarget)]
#[stash(plaintext = String)]
struct WholeValue {
    #[stash(passthrough)]
    id: u64,
    email: Ciphertext,
}

/// A passthrough field is moved through as it is.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, context = "users")]
struct Marked {
    #[stash(passthrough, decrypt)]
    id: u64,
    email: Ciphertext,
}

/// One plaintext field has one output.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, context = "users")]
struct Twice {
    #[stash(passthrough, from = email)]
    plain_email: String,
    email: Ciphertext,
}

fn main() {}
