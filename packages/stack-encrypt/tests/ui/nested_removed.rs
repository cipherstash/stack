//! `#[stash(nested)]` is removed. A field whose type is a record is an
//! ordinary field, derived under `("<context>", "<field>")`, with the
//! record's own fields under that; the message says to omit the attribute.
use stack_encrypt::{EncryptFrom, StackCipherText};

struct User {
    email: String,
}

struct Account {
    user: User,
}

#[derive(EncryptFrom)]
#[stash(struct = User, context = "users")]
struct EncryptedUser {
    email: StackCipherText,
}

#[derive(EncryptFrom)]
#[stash(struct = Account, context = "accounts")]
struct EncryptedAccount {
    #[stash(nested)]
    user: EncryptedUser,
}

fn main() {}
