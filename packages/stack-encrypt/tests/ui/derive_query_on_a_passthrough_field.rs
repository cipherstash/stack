//! A query type is for a sealed field's marker: a passthrough field has no
//! marker, so `query = ..` on one is refused.
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::Encrypted;
use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
struct User {
    tenant: u64,
    email: String,
}

#[derive(EncryptTarget)]
#[stash(struct = User, scope = "users")]
struct EncryptedUser {
    #[stash(passthrough, query = u64)]
    tenant: u64,
    email: Encrypted<EqualityTerm>,
}

fn main() {}
