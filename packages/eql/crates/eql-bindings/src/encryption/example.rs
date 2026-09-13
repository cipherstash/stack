use eql_bindings::{
    v3::text::{TextEq, TextEqQuery},
    Identifier,
};
use stack_encrypt::StackCipher;
use stack_kms::FakeDataKeySource;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Local example only: these keys are held in memory, not in ZeroKMS.
    let cipher = StackCipher::builder()
        .kms(FakeDataKeySource::new())
        .init()
        .await?;
    let keyset = cipher.default_keyset();
    let column = Identifier::for_column("users", "email")?;
    let email = String::from("alice@example.com");

    // The output type selects ciphertext plus the equality term.
    let stored: TextEq = keyset.encrypt_as(&email, column.clone()).await?;
    assert_eq!(stored.i.t, "users");
    assert_eq!(stored.i.c, "email");

    // Use the same identifier to produce an equality query for this column.
    let query: TextEqQuery = keyset.encrypt_as(&email, column.clone()).await?;
    assert_eq!(stored.hm, query.hm);

    // Decrypt to String, also checking the expected table and column.
    let opened: String = cipher.decrypt_as(stored, column.into()).await?;
    assert_eq!(opened, email);
    Ok(())
}
