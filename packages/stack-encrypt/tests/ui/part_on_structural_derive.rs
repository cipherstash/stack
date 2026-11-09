//! The structural derives take no scope or binding: the owned derives do.
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::{DecryptInto, EncryptFrom, Encrypted};

struct User {
    email: String,
}

#[derive(EncryptFrom)]
#[stash(struct = User, scope = "users", bind(row: u128))]
struct Bound {
    email: Encrypted<EqualityTerm>,
}

#[derive(DecryptInto)]
#[stash(struct = User, scope = "users", scope(tenant: u64))]
struct Scoped {
    email: Encrypted<EqualityTerm>,
}

fn main() {}
