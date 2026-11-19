//! An audited call can only be awaited. It has no `zip` and no second
//! `.audit(..)`, a batch does not take it, and it is not an `Operation`. So
//! a call is given one map of audit metadata, once, last.
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::plan::Operation;
use stack_encrypt::{all, AuditMetadata, Ciphertext, Pending, Plan, StackCipher};

fn calls(cipher: &StackCipher<FakeDataKeySource>, plan: &Plan<String, FakeDataKeySource>) {
    let keyset = cipher.default_keyset();
    let facts = || AuditMetadata::new().with("purpose", "import");
    let email = String::from("bob@example.com");
    let seal = || -> Pending<'_, Ciphertext, FakeDataKeySource> { keyset.encrypt(1i64) };

    // No `zip` after `.audit(..)`.
    let _ = seal().audit(facts()).zip(seal());
    // No second `.audit(..)` on a pending, on a chain, or on a batch.
    let _ = seal().audit(facts()).audit(facts());
    let _ = cipher.encrypt(&email).using(plan).audit(facts()).audit(facts());
    let _ = all((
        cipher.encrypt(&email).using(plan),
        cipher.encrypt(&email).using(plan),
    ))
    .audit(facts())
    .audit(facts());
    // A batch takes chains, not audited chains.
    let _ = all((
        cipher.encrypt(&email).using(plan).audit(facts()),
        cipher.encrypt(&email).using(plan),
    ));
    // An audited chain is not an `Operation`, so `prepare` cannot be called
    // on it and cannot lose its metadata.
    is_operation(&cipher.encrypt(&email).using(plan).audit(facts()));
}

fn is_operation<'a, O: Operation<'a, FakeDataKeySource>>(_: &O) {}

fn main() {}
