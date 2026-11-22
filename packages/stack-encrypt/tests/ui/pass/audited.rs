//! The audited shapes that must compile: metadata on a pending, on a merged
//! pending, on a batch, and on a derived record's encrypt and decrypt.
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::{
    nonempty, AuditMetadata, Ciphertext, DecryptFrom, DecryptSource, EncryptInto, EncryptTarget,
    Error, Pending, StackCipher, StackCipherText,
};

#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String)]
struct EncryptedEmail {
    c: StackCipherText,
    hm: EqualityTerm,
}

async fn calls(cipher: &StackCipher<FakeDataKeySource>) -> Result<(), Error> {
    let keyset = cipher.default_keyset();
    let facts = || AuditMetadata::new().with("purpose", "import");
    let seal = || -> Pending<'_, Ciphertext, FakeDataKeySource> { keyset.encrypt(1i64) };

    let stored = seal().audit(facts()).await?;
    let _: i64 = keyset.decrypt(stored).audit(facts()).await?;
    let _ = seal().zip(seal()).audit(facts()).await?;
    let _ = Pending::all(&keyset, vec![seal(), seal()])
        .audit(facts())
        .await?;
    let written: EncryptedEmail = String::from("bob@example.com")
        .encrypt_into_with_context(&keyset, nonempty!("users/email"))
        .audit(facts())
        .await?;
    let _ = String::decrypt_from_with_context(written, cipher, nonempty!("users/email"))
        .audit(facts())
        .await?;
    Ok(())
}

fn main() {}
