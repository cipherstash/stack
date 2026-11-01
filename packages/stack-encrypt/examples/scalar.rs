//! Run with ZeroKMS credentials: `cargo run -p stack-encrypt --example scalar`.
//! Authenticate with `npx stash auth login`, or configure the `CS_*` credentials
//! described in the crate's quick start. Initialization fails without credentials.
use stack_encrypt::{Ciphertext, DecryptFrom, EncryptInto, StackCipher};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cipher = StackCipher::new().await?;
    let keyset = cipher.default_keyset();

    let encrypted = keyset.encrypt(42i32).await?;
    let stored = encrypted.to_bytes();
    let restored = Ciphertext::from_bytes(&stored)?;
    let value: i32 = keyset.decrypt(restored).await?;
    assert_eq!(value, 42);

    let encrypted = keyset.encrypt_with_context(42i32, ("users", "age")).await?;
    let value: i32 = keyset
        .decrypt_with_context(encrypted, ("users", "age"))
        .await?;
    assert_eq!(value, 42);

    let encrypted: Ciphertext = 42i32.encrypt_into(&keyset).await?;
    let value = i32::decrypt_from(encrypted, &keyset).await?;
    assert_eq!(value, 42);

    let encrypted: Ciphertext = 42i32
        .encrypt_into_with_context(&keyset, ("users", "age"))
        .await?;
    let value = i32::decrypt_from_with_context(encrypted, &keyset, ("users", "age")).await?;
    assert_eq!(value, 42);
    Ok(())
}
