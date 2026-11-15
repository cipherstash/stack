//! Match is defined over text, so a record cannot declare a match index on
//! an integer field.
use stack_encrypt::sem::MatchTerms;
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::Encrypted;
use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
struct User {
    age: u32,
}

#[derive(EncryptTarget)]
#[stash(struct = User, scope = "users")]
struct EncryptedUser {
    age: Encrypted<MatchTerms>,
}

fn main() {}
