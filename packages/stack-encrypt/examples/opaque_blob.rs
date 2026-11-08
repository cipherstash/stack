//! Encrypt a whole struct as one ciphertext with `OpaqueBlob`.
//!
//! Run with ZeroKMS credentials: `cargo run -p stack-encrypt --example opaque_blob`.
//! Authenticate with `npx stash auth login`, or configure the `CS_*` credentials
//! described in the crate's quick start. Initialization fails without credentials.
use serde::{Deserialize, Serialize};
use stack_encrypt::{BlobError, Ciphertext, Error, OpaqueBlob, StackCipher};
use zeroize::Zeroize;

/// An ordinary application struct. `Serialize` and `Deserialize` give it a
/// storage encoding; `Zeroize` lets the library wipe the owned source once
/// it has been encoded, and lets a caller wipe a decrypted copy.
#[derive(Serialize, Deserialize, Zeroize, PartialEq, Debug)]
struct Profile {
    name: String,
    age: u32,
    tags: Vec<String>,
    nickname: Option<String>,
}

/// The same data in a later shape: a field added with a default and one
/// renamed under an alias. An old blob still reads into it.
#[derive(Serialize, Deserialize, Zeroize, PartialEq, Debug)]
struct ProfileV2 {
    name: String,
    age: u32,
    #[serde(alias = "tags")]
    labels: Vec<String>,
    nickname: Option<String>,
    #[serde(default)]
    verified: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cipher = StackCipher::new().await?;
    let keyset = cipher.default_keyset();

    let profile = Profile {
        name: "Ada Lovelace".into(),
        age: 36,
        tags: vec!["maths".into(), "engines".into()],
        nickname: Some("ada".into()),
    };

    // One ciphertext for the whole value: one data key, one leaf. The owned
    // struct is consumed and wiped before the request is awaited.
    let encrypted = keyset
        .encrypt_with_context(OpaqueBlob::new(profile), ("users", "profile"))
        .await?;

    // Store and restore it like any other ciphertext.
    let stored = encrypted.to_bytes();
    let restored = Ciphertext::from_bytes(&stored)?;

    // Decrypt to the wrapper and take the value out. `into_inner` returns
    // a `Zeroizing<Profile>`, which derefs to the `Profile` and wipes it
    // when `profile` goes out of scope.
    let opened: OpaqueBlob<Profile> = keyset
        .decrypt_with_context(restored.clone(), ("users", "profile"))
        .await?;
    let profile = opened.into_inner();
    assert_eq!(profile.name, "Ada Lovelace");
    assert_eq!(profile.age, 36);

    // Schema evolution is serde's: the blob written as a `Profile` reads
    // into the later `ProfileV2`.
    let later: OpaqueBlob<ProfileV2> = keyset
        .decrypt_with_context(restored.clone(), ("users", "profile"))
        .await?;
    assert_eq!(later.get().labels, ["maths", "engines"]);
    assert!(!later.get().verified);

    // The errors tell an authentic blob of another shape from tampering.
    // A type the blob does not fit is a mismatch after authentication...
    #[derive(Deserialize, Zeroize)]
    struct Other {
        #[allow(dead_code)]
        id: u64,
    }
    match keyset
        .decrypt_with_context::<OpaqueBlob<Other>>(restored.clone(), ("users", "profile"))
        .await
    {
        Err(Error::Blob(BlobError::Mismatch(_))) => {}
        other => panic!("expected a blob mismatch, got {other:?}"),
    }
    // ...while the wrong context never reaches the blob at all.
    match keyset
        .decrypt_with_context::<OpaqueBlob<Profile>>(restored, ("users", "other"))
        .await
    {
        // ZeroKMS refuses the key under the wrong context; a key source
        // that ignores descriptors would fail the AEAD instead.
        Err(Error::Kms(_) | Error::Aead) => {}
        other => panic!("expected a refusal before decoding, got {other:?}"),
    }

    println!("encrypted, stored, reopened and evolved one opaque blob");
    Ok(())
}
