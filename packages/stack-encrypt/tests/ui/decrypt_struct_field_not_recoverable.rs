//! In a `struct` derive each plaintext field has one output, so a field
//! whose one output is a one-way term cannot be recovered. The refusal names
//! the plaintext field and the replacement that stores its ciphertext.
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::{DecryptInto, StackCipherText};

struct User {
    email: String,
    name: String,
}

#[derive(DecryptInto)]
#[stash(struct = User, context = "users")]
struct Opened {
    email: EqualityTerm,
    name: StackCipherText,
}

fn main() {}
