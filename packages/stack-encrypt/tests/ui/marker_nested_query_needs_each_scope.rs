//! A field of a record that lists a scope of its own, under a record that
//! lists one too, takes both scopes together, outermost first: a query
//! from its marker has no `encrypt` until both are given, takes each
//! scope's type and no other, and takes them once.
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{EncryptTarget, Scope};
use stack_encrypt::{Encrypted, StackCipher};
use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
struct Desk {
    tenant: u64,
    label: String,
}

#[derive(Clone, Zeroize)]
struct Tower {
    desk: Desk,
}

#[derive(EncryptTarget)]
#[stash(struct = Desk, scope = "desks", scope(field = "tenant"))]
struct EncryptedDesk {
    #[stash(passthrough)]
    tenant: u64,
    label: Encrypted<EqualityTerm>,
}

#[derive(EncryptTarget)]
#[stash(struct = Tower, scope = "towers", scope(region: String))]
struct EncryptedTower {
    desk: EncryptedDesk,
}

async fn query(cipher: &StackCipher<FakeDataKeySource>) {
    let keyset = cipher.default_keyset();
    let label = EncryptedTower::DESK.field(EncryptedDesk::LABEL);
    // Both scopes, outermost first.
    let _ = label
        .eq("D-7")
        .scope(Scope::new(String::from("eu")).scope(42u64))
        .encrypt(&keyset)
        .await;
    // The scopes are missing.
    let _ = label.eq("D-7").encrypt(&keyset).await;
    // One scope, where the query takes two.
    let _ = label
        .eq("D-7")
        .scope(Scope::new(String::from("eu")))
        .encrypt(&keyset)
        .await;
    // The inner record's scope first.
    let _ = label
        .eq("D-7")
        .scope(Scope::new(42u64).scope(String::from("eu")))
        .encrypt(&keyset)
        .await;
    // The scopes are given twice.
    let _ = label
        .eq("D-7")
        .scope(Scope::new(String::from("eu")).scope(42u64))
        .scope(Scope::new(String::from("eu")).scope(42u64))
        .encrypt(&keyset)
        .await;
}

fn main() {}
