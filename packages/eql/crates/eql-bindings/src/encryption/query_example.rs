use eql_bindings::{
    v4::text::{TextEq, TextMatch},
    Identifier,
};
use stack_encrypt::op::{self, Probabilistic, Stats};
use stack_encrypt::{Plan, StackCipher};
use stack_kms::FakeDataKeySource;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Local example only: these keys are held in memory, not in ZeroKMS.
    let cipher = StackCipher::builder()
        .kms(FakeDataKeySource::new())
        .init()
        .await?;
    let keyset = cipher.default_keyset();

    // Write a value to the `users.email` column.
    let column = Identifier::for_column("users", "email")?;
    let email = String::from("alice@example.com");
    let stored: TextEq = keyset.encrypt_as(&email, column).await?;

    // Query it: a plan for the column's type, under the label that names
    // the same column, table then column.
    let email_plan = Plan::value::<String>()
        .context("users/email")
        .encrypt_into::<TextEq>()
        .build()?;
    // A `TextEqQuery`: bind it as `$1::eql_v4.query_text_eq`.
    let query = cipher
        .query(op::Eq, "alice@example.com")
        .on(&email_plan)
        .await?;
    assert_eq!(query.hm, stored.hm);
    assert_eq!(query.i, stored.i);

    // A text match: bind `query.twin()` (or the query itself, which
    // serializes as the twin) as `$1::eql_v4.query_text_match`.
    let name_plan = Plan::value::<String>()
        .context("users/name")
        .encrypt_into::<TextMatch>()
        .build()?;
    let query = cipher.query(op::Matches, "ali").on(&name_plan).await?;
    // How many rows to fetch to expect 10 real matches in a million.
    let _limit = query.target_limit(10, &Stats::declared(1_000_000));
    // The server can return rows that hold every bit of the filter without
    // the text: keep the decrypted rows that verify.
    assert!(query.verify("Alice Nguyen"));
    assert!(!query.verify("Bob Li"));
    Ok(())
}
