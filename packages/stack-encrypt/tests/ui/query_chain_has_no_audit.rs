//! A query requests no data key, so a query chain has no `.audit(..)`.
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::{op, AuditMetadata, Equality, Plan, StackCipher};

fn query(cipher: &StackCipher<FakeDataKeySource>) {
    let plan = Plan::context("users/email")
        .with::<String, _>(Equality)
        .build()
        .unwrap();
    let facts = AuditMetadata::new().with("purpose", "search");
    let _ = cipher.query(op::Eq, "bob@example.com").on(&plan).audit(facts);
}

fn main() {}
