use eql_bindings::v4::text::{TextEq, TextMatch};
use stack_encrypt::op::{Probabilistic, Stats};
use stack_encrypt::{EncryptInto, EncryptTarget, StackCipher};
use stack_kms::FakeDataKeySource;
use zeroize::Zeroize;

#[derive(Zeroize)]
struct User {
    email: String,
    name: String,
}

// The record's scope names the table, and each field's name is its column:
// `users.email` and `users.name`.
#[derive(EncryptTarget)]
#[stash(struct = User, scope = "users")]
struct EncryptedUser {
    email: TextEq,
    name: TextMatch,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Local example only: these keys are held in memory, not in ZeroKMS.
    let cipher = StackCipher::builder()
        .kms(FakeDataKeySource::new())
        .init()
        .await?;
    let keyset = cipher.default_keyset();

    // Write a row.
    let user = User {
        email: "alice@example.com".into(),
        name: "Alice Nguyen".into(),
    };
    let stored: EncryptedUser = user.encrypt_into(&keyset).await?;

    // Query the `email` column from the field reference.
    // A `TextEqQuery`: bind it as `$1::eql_v4.query_text_eq`.
    let query = EncryptedUser::EMAIL
        .eq("alice@example.com")
        .encrypt(&keyset)
        .await?;
    assert_eq!(query.hm, stored.email.hm);
    assert_eq!(query.i, stored.email.i);

    // A text match: bind `query.twin()` (or the query itself, which
    // serializes as the twin) as `$1::eql_v4.query_text_match`.
    let query = EncryptedUser::NAME.matches("ali").encrypt(&keyset).await?;
    assert_eq!(query.twin().i, stored.name.i);
    // How many rows to fetch to expect 10 real matches in a million.
    let _limit = query.target_limit(10, &Stats::declared(1_000_000));
    // The server can return rows that hold every bit of the filter without
    // the text: keep the decrypted rows that verify.
    assert!(query.verify("Alice Nguyen"));
    assert!(!query.verify("Bob Li"));
    Ok(())
}
