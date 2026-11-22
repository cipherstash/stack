//! `#[stash(json(..))]` names the JSON index's options, so it goes on a
//! field whose type stores a JSON document.
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::Encrypted;
use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
struct User {
    email: String,
}

#[derive(EncryptTarget)]
#[stash(struct = User, scope = "users")]
struct EncryptedUser {
    #[stash(json(ordered = { "$.a": u32 }))]
    email: Encrypted<EqualityTerm>,
}

fn main() {}
