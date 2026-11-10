//! A record lists the parts its caller supplies. A call that leaves a listed
//! part out, or passes a part the record does not list, does not compile.
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{Bind, DecryptSource, EncryptTarget, Scope};
use stack_encrypt::{EncryptInto, Encrypted, KeysetCipher};
use stack_kms::FakeDataKeySource;
use zeroize::Zeroize;

#[derive(Zeroize)]
struct User {
    email: String,
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, scope = "users", scope(tenant: u64))]
struct TenantScoped {
    email: Encrypted<EqualityTerm>,
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, scope = "users", bind(row: u128))]
struct RowBound {
    email: Encrypted<EqualityTerm>,
}

async fn calls(keyset: &KeysetCipher<'_, FakeDataKeySource>, user: User) {
    // The tenant is listed, so it cannot be left out.
    let _: TenantScoped = user.encrypt_into(keyset).await.unwrap();
}

async fn wrong_part(keyset: &KeysetCipher<'_, FakeDataKeySource>, user: User) {
    // A binding is listed, not a scope.
    let _: RowBound = user
        .encrypt_into_with_context(keyset, Scope::new(42u64))
        .await
        .unwrap();
}

async fn extra_part(keyset: &KeysetCipher<'_, FakeDataKeySource>, user: User) {
    // A scope is listed, and no binding.
    let _: TenantScoped = user
        .encrypt_into_with_context(keyset, Scope::new(42u64).bind(9u128))
        .await
        .unwrap();
}

fn main() {
    let _ = Bind::new(9u128);
}
