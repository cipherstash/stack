//! A field type that stores its context (`#[stash(context_field)]`) can be a
//! field of a `struct = ..` record only when the stored type can be built
//! from the field's own context (`ContextFromField`). A `String` cannot, so
//! the field is a compile error.
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{DecryptSource, EncryptTarget};
use stack_encrypt::Ciphertext;

/// A value that stores its context as text.
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String)]
struct Stored {
    #[stash(context_field)]
    column: String,
    c: Ciphertext,
    hm: EqualityTerm,
}

#[derive(zeroize::Zeroize)]
struct User {
    email: String,
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, scope = "users")]
struct EncryptedUser {
    email: Stored,
}

fn main() {}
