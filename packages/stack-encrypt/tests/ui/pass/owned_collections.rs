//! The owned collection forms that must compile: a `Vec` of opaque scalars
//! into a `Vec` of any owned target, with the element's caller-context
//! capability, and back. A `Vec<u8>` is one byte leaf, so it is one
//! `Ciphertext`, and a `Vec<Vec<u8>>` is a column of them. `tests/ui/owned_collection_elements.rs` and
//! `tests/ui/owned_collection_context.rs` pin the forms that must not.
use stack_encrypt::target::{
    AcceptsContext, DecryptSource, Decryption, EncryptTarget, Encryption, NoCallerContext,
    OptionalContext, RequiredContext, ScalarContext,
};
use stack_encrypt::{Ciphertext, DecryptFrom, EncryptInto, KeysetCipher, StackCipher};
use stack_kms::FakeDataKeySource;

struct Required(Ciphertext);
impl EncryptTarget<i32> for Required {
    type ContextInput = RequiredContext<u64>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, i32, Self, K, Self::ContextInput> {
        stack_encrypt::target::scalar_ciphertext().map(Self).accepting()
    }
}
impl DecryptSource<i32> for Required {
    type ContextInput = RequiredContext<u64>;
    fn decryption<K: 'static>(self, context: Self::ContextInput) -> Decryption<i32, K> {
        self.0.decryption(OptionalContext::<ScalarContext>::supplied(
            context.into_inner().into(),
        ))
    }
}
struct Fixed(Ciphertext);
impl EncryptTarget<i32> for Fixed {
    type ContextInput = NoCallerContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, i32, Self, K, Self::ContextInput> {
        stack_encrypt::target::scalar_ciphertext()
            .map(Self)
            .under(stack_encrypt::nonempty!("users/fixed"))
            .accepting()
    }
}
impl DecryptSource<i32> for Fixed {
    type ContextInput = NoCallerContext;
    fn decryption<K: 'static>(self, _: Self::ContextInput) -> Decryption<i32, K> {
        self.0.decryption(OptionalContext::<ScalarContext>::supplied(
            "users/fixed".into(),
        ))
    }
}

/// `Tracked` is deliberately not `Clone`: a column of owned values is held
/// by the conversion's guard and handed to each element by reference.
struct Tracked(String);
impl zeroize::Zeroize for Tracked {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
struct TrackedCiphertext(Ciphertext);
impl EncryptTarget<Tracked> for TrackedCiphertext {
    type ContextInput = OptionalContext<ScalarContext>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, Tracked, Self, K, Self::ContextInput> {
        stack_encrypt::target::scalar_ciphertext::<String, K>()
            .project(|source: &Tracked| &source.0)
            .map(Self)
    }
}

async fn columns(
    cipher: &StackCipher<FakeDataKeySource>,
    keyset: &KeysetCipher<'_, FakeDataKeySource>,
) -> Result<(), stack_encrypt::Error> {
    // Context-free, with a context, and through the client scope.
    let ages: Vec<Ciphertext> = vec![1i32, 2].encrypt_into(keyset).await?;
    let _: Vec<i32> = Vec::decrypt_from(ages, cipher).await?;
    let names: Vec<Ciphertext> = vec![String::from("a")]
        .encrypt_into_with_context(keyset, ("users", "name"))
        .await?;
    let _: Vec<String> = Vec::decrypt_from_with_context(names, keyset, ("users", "name")).await?;
    // A byte string is one leaf, and a column of byte strings is a column.
    let blob: Ciphertext = vec![1u8, 2].encrypt_into(keyset).await?;
    let _: Vec<u8> = Vec::decrypt_from(blob, keyset).await?;
    let fixed_bytes: Ciphertext = [7u8; 4].encrypt_into(keyset).await?;
    let _: [u8; 4] = <[u8; 4]>::decrypt_from(fixed_bytes, keyset).await?;
    let blobs: Vec<Ciphertext> = vec![vec![1u8], vec![]].encrypt_into(keyset).await?;
    let _: Vec<Vec<u8>> = Vec::decrypt_from(blobs, keyset).await?;
    // Nested columns, and a column of a non-`Clone` owned plaintext.
    let nested: Vec<Vec<Ciphertext>> = vec![vec![1i32], vec![]].encrypt_into(keyset).await?;
    let _: Vec<Vec<i32>> = Vec::decrypt_from(nested, keyset).await?;
    let _: Vec<TrackedCiphertext> = vec![Tracked(String::from("x"))].encrypt_into(keyset).await?;
    // The element's capability is the column's.
    let required: Vec<Required> = vec![1i32].encrypt_into_with_context(keyset, 7u64).await?;
    let _: Vec<i32> = Vec::decrypt_from_with_context(required, keyset, 7u64).await?;
    let fixed: Vec<Fixed> = vec![1i32].encrypt_into(keyset).await?;
    let _: Vec<i32> = Vec::decrypt_from(fixed, keyset).await?;
    Ok(())
}

fn main() {
    let _ = columns;
}
