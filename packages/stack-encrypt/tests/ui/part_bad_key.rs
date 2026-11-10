//! A part is `name: Type`, for one the caller passes, or `field = "name"`,
//! for one stored in the row; nothing else goes inside `scope(..)` or
//! `bind(..)`.
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::Encrypted;
use zeroize::Zeroize;

#[derive(Zeroize)]
struct User {
    email: String,
}

#[derive(EncryptTarget)]
#[stash(struct = User, scope = "users", bind(column = "id"))]
struct BadKey {
    email: Encrypted<EqualityTerm>,
}

#[derive(EncryptTarget)]
#[stash(struct = User, scope = "users", scope(tenant))]
struct NoType {
    email: Encrypted<EqualityTerm>,
}

fn main() {}
