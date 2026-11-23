//! In a `struct` derive each plaintext field has one output, so a field
//! whose one output is a one-way term cannot be recovered. The refusal names
//! the plaintext field and the replacement that stores its ciphertext.
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::DecryptSource;
use stack_encrypt::StackCipherText;

#[derive(zeroize::Zeroize)]
struct User {
    email: String,
    name: String,
}

#[derive(DecryptSource)]
#[stash(struct = User, scope = "users")]
struct Opened {
    email: EqualityTerm,
    name: StackCipherText,
}

fn main() {}
