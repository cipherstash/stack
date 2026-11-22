use eql_bindings::{v4::json_tree::JsonTreeDocument, Identifier};
use serde_json::json;
use stack_encrypt::json::JsonPlaintext;
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
    let column = Identifier::for_column("customers", "profile")?;

    // Encryption takes the document by value and wipes it. The stored
    // document records its column in `i`.
    let profile = JsonPlaintext::from(json!({"name": "Ada", "age": 36}));
    let document: JsonTreeDocument = profile
        .encrypt_into_with_context(&keyset, column.clone())
        .await?;
    assert_eq!(document.i.t, "customers");
    assert_eq!(document.i.c, "profile");

    // Decrypt to the document, also checking the expected table and column.
    let opened = JsonPlaintext::decrypt_from_with_context(document, &keyset, column).await?;
    assert_eq!(opened.value(), &json!({"name": "Ada", "age": 36}));
    Ok(())
}
