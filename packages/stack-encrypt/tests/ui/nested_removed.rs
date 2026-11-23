//! `#[stash(nested)]` is removed. A field whose type is a record is an
//! ordinary field, derived under `("<context>", "<field>")`, with the
//! record's own fields under that; the message says to omit the attribute.
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::StackCipherText;

#[derive(Clone, zeroize::Zeroize)]
struct User {
    email: String,
}

#[derive(zeroize::Zeroize)]
struct Account {
    user: User,
}

#[derive(EncryptTarget)]
#[stash(struct = User, scope = "users")]
struct EncryptedUser {
    email: StackCipherText,
}

#[derive(EncryptTarget)]
#[stash(struct = Account, scope = "accounts")]
struct EncryptedAccount {
    #[stash(nested)]
    user: EncryptedUser,
}

fn main() {}
