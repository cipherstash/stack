//! An `identity` is one plain label segment, so an empty one is refused.
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::StackCipherText;

#[derive(zeroize::Zeroize)]
struct User {
    email: String,
}

#[derive(EncryptTarget)]
#[stash(struct = User, scope = "users")]
struct EncryptedUser {
    #[stash(identity = "")]
    email: StackCipherText,
}

fn main() {}
