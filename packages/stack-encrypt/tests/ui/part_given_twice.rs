//! A record lists one scope and one binding: a second `scope(..)` or
//! `bind(..)` is refused at the attribute, not merged.
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::Encrypted;
use zeroize::Zeroize;

#[derive(Zeroize)]
struct User {
    email: String,
}

#[derive(EncryptTarget)]
#[stash(struct = User, scope = "users", scope(tenant: u64), scope(region: String))]
struct TwoScopes {
    email: Encrypted<EqualityTerm>,
}

#[derive(EncryptTarget)]
#[stash(struct = User, scope = "users", bind(row: u128), bind(version: u32))]
struct TwoBindings {
    email: Encrypted<EqualityTerm>,
}

fn main() {}
