//! The audited shapes that must compile: metadata on a pending, on a merged
//! pending, on an encrypt chain, on an open chain, and on a batch of chains.
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::{all, AuditMetadata, Ciphertext, Error, Pending, Plan, StackCipher};

async fn calls(
    cipher: &StackCipher<FakeDataKeySource>,
    plan: &Plan<String, FakeDataKeySource>,
) -> Result<(), Error> {
    let keyset = cipher.default_keyset();
    let facts = || AuditMetadata::new().with("purpose", "import");
    let email = String::from("bob@example.com");
    let seal = || -> Pending<'_, Ciphertext, FakeDataKeySource> { keyset.encrypt(1i64) };

    let stored = seal().audit(facts()).await?;
    let _: i64 = keyset.decrypt(stored).audit(facts()).await?;
    let _ = seal().zip(seal()).audit(facts()).await?;
    let written = cipher.encrypt(&email).using(plan).audit(facts()).await?;
    let _ = cipher.open(written).using(plan).audit(facts()).await?;
    let _ = all((
        cipher.encrypt(&email).using(plan),
        cipher.encrypt(&email).using(plan),
    ))
    .audit(facts())
    .await?;
    Ok(())
}

fn main() {}
