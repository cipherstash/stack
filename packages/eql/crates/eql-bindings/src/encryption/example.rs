use eql_bindings::{
    v4::text::{TextEq, TextEqQuery},
    Identifier,
};
use stack_encrypt::{DecryptFrom, EncryptInto, StackCipher};
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

    // The output type selects ciphertext plus the equality term. Encryption
    // takes the plaintext by value and wipes it.
    let stored: TextEq = String::from("alice@example.com")
        .encrypt_into_with_context(&keyset, column.clone())
        .await?;
    assert_eq!(stored.i.t, "users");
    assert_eq!(stored.i.c, "email");

    // Use the same identifier to produce an equality query for this column.
    let query: TextEqQuery = String::from("alice@example.com")
        .encrypt_into_with_context(&keyset, column.clone())
        .await?;
    assert_eq!(stored.hm, query.hm);

    // Decrypt to String, also checking the expected table and column.
    let opened = String::decrypt_from_with_context(stored, &keyset, column).await?;
    assert_eq!(opened, "alice@example.com");
    Ok(())
}
