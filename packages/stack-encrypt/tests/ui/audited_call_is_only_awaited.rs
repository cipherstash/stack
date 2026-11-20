//! An audited call can only be awaited. It has no `zip` and no second
//! `.audit(..)`, and a batch does not take it. So a call is given one map
//! of audit metadata, once, last.
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::{AuditMetadata, Ciphertext, Pending, StackCipher};

fn calls(cipher: &StackCipher<FakeDataKeySource>) {
    let keyset = cipher.default_keyset();
    let facts = || AuditMetadata::new().with("purpose", "import");
    let seal = || -> Pending<'_, Ciphertext, FakeDataKeySource> { keyset.encrypt(1i64) };

    // No `zip` after `.audit(..)`.
    let _ = seal().audit(facts()).zip(seal());
    // No second `.audit(..)` on a pending, or on a batch.
    let _ = seal().audit(facts()).audit(facts());
    let _ = Pending::all(&keyset, vec![seal(), seal()])
        .audit(facts())
        .audit(facts());
    // A batch takes pendings, not audited calls.
    let _ = Pending::all(&keyset, vec![seal().audit(facts()), seal()]);
}

fn main() {}
