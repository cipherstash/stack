//! A plaintext field has one output in a `struct` derive. A term beside the
//! ciphertext, a second field `from` the same plaintext field, is refused,
//! naming the replacement: one field of type `Encrypted<Terms>`.
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::{DecryptInto, EncryptFrom, StackCipherText};

struct User {
    email: String,
}

#[derive(EncryptFrom)]
#[stash(struct = User, context = "users")]
struct EncryptedUser {
    email: StackCipherText,
    #[stash(from = email)]
    email_hm: EqualityTerm,
}

#[derive(DecryptInto)]
#[stash(struct = User, context = "users")]
struct Opened {
    email: StackCipherText,
    #[stash(from = email)]
    email_hm: EqualityTerm,
}

fn main() {}
