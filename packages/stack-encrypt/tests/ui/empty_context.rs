use stack_encrypt::{EncryptFrom, StackCipherText};

struct User {
    email: String,
}

#[derive(EncryptFrom)]
#[stash(struct = User, context = "users")]
struct EncryptedUser {
    #[stash(context = "")]
    email: StackCipherText,
}

#[derive(EncryptFrom)]
#[stash(plaintext = u32)]
struct Pinned {
    #[stash(context = "")]
    c: StackCipherText,
}

fn main() {}
