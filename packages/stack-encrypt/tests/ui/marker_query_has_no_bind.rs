//! A query from a field marker takes scopes and no binding: a binding is in
//! no query context, so the query type has no `bind` method and a bare
//! `Bind` does not convert into its `scope`.
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{Bind, EncryptTarget, Scope};
use stack_encrypt::Encrypted;
use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
struct User {
    email: String,
}

#[derive(EncryptTarget)]
#[stash(struct = User, scope = "users", scope(tenant: u64), bind(row: u128))]
struct EncryptedUser {
    email: Encrypted<EqualityTerm>,
}

fn main() {
    let _ = EncryptedUser::EMAIL
        .eq("ada@example.com")
        .scope(Scope::new(42u64))
        .bind(9u128);
    let _ = EncryptedUser::EMAIL
        .eq("ada@example.com")
        .scope(Bind::new(9u128));
}
