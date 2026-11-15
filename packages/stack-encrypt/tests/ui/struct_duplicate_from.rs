//! A plaintext field has one output in a `struct` derive. A term beside the
//! ciphertext, a second field `from` the same plaintext field, is refused,
//! naming the replacement: one field of type `Encrypted<Terms>`.
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{DecryptSource, EncryptTarget};
use stack_encrypt::StackCipherText;

#[derive(zeroize::Zeroize)]
struct User {
    email: String,
}

#[derive(EncryptTarget)]
#[stash(struct = User, scope = "users")]
struct EncryptedUser {
    email: StackCipherText,
    #[stash(from = email)]
    email_hm: EqualityTerm,
}

#[derive(DecryptSource)]
#[stash(struct = User, scope = "users")]
struct Opened {
    email: StackCipherText,
    #[stash(from = email)]
    email_hm: EqualityTerm,
}

fn main() {}
