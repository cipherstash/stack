use stack_encrypt::{EncryptFrom, StackCipherText};

struct User {
    email: String,
}

#[derive(EncryptFrom)]
#[stash(struct = User, context = "users")]
struct EncryptedUser {
    #[stash(identity = "")]
    email: StackCipherText,
}

fn main() {}
