//! A record that lists a caller scope gives its markers that scope's type:
//! a query from one has no `encrypt` until the scope is given, takes the
//! scope's type and no other, and takes it once.
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{EncryptTarget, Scope};
use stack_encrypt::{Encrypted, StackCipher};
use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
struct User {
    email: String,
}

#[derive(EncryptTarget)]
#[stash(struct = User, scope = "users", scope(tenant: u64))]
struct EncryptedUser {
    email: Encrypted<EqualityTerm>,
}

async fn query(cipher: &StackCipher<FakeDataKeySource>) {
    let keyset = cipher.default_keyset();
    // The scope is missing.
    let _ = EncryptedUser::EMAIL.eq("ada@example.com").encrypt(&keyset).await;
    // The scope has the wrong type.
    let _ = EncryptedUser::EMAIL
        .eq("ada@example.com")
        .scope(Scope::new("42"))
        .encrypt(&keyset)
        .await;
    // The scope is given twice.
    let _ = EncryptedUser::EMAIL
        .eq("ada@example.com")
        .scope(Scope::new(42u64))
        .scope(Scope::new(1u64))
        .encrypt(&keyset)
        .await;
}

fn main() {}
