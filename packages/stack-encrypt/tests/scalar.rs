//! The first owned public API slice; no service credentials are needed.
use stack_encrypt::target::{
    AcceptsContext, DecryptSource, Decryption, EncryptTarget, Encryption, OptionalContext,
    RequiredContext, ScalarContext,
};
use stack_encrypt::{Ciphertext, DecryptFrom, EncryptInto, Error};
mod common;

#[tokio::test]
async fn scalar_entry_points_cross_open_with_empty_and_supplied_context() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let ct = keyset.encrypt(42i32).await.unwrap();
    let value = i32::decrypt_from(ct, &keyset).await.unwrap();
    assert_eq!(value, 42);

    let ct: Ciphertext = (-42i32).encrypt_into(&keyset).await.unwrap();
    assert_eq!(keyset.decrypt::<i32>(ct).await.unwrap(), -42);

    let ct = keyset
        .encrypt_with_context(42i32, ("users", "age"))
        .await
        .unwrap();
    assert_eq!(
        i32::decrypt_from_with_context(ct, &keyset, ("users", "age"))
            .await
            .unwrap(),
        42
    );

    let ct: Ciphertext = 42i32
        .encrypt_into_with_context(&keyset, ("users", "age"))
        .await
        .unwrap();
    assert_eq!(
        keyset
            .decrypt_with_context::<i32>(ct, ("users", "age"))
            .await
            .unwrap(),
        42
    );
}

#[tokio::test]
async fn rejects_wrong_context_type_and_tampered_ciphertext() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let ct = keyset
        .encrypt_with_context(42i32, "users/age")
        .await
        .unwrap();
    assert!(matches!(
        keyset.decrypt::<i32>(ct.clone()).await,
        Err(Error::Aead)
    ));
    assert!(matches!(
        keyset
            .decrypt_with_context::<i32>(ct.clone(), "users/name")
            .await,
        Err(Error::Aead)
    ));
    assert!(matches!(
        keyset
            .decrypt_with_context::<String>(ct.clone(), "users/age")
            .await,
        Err(Error::OpenedType { .. })
    ));
    let mut bytes = ct.to_bytes();
    *bytes.last_mut().unwrap() ^= 1;
    let tampered = Ciphertext::from_bytes(&bytes).unwrap();
    assert!(matches!(
        keyset
            .decrypt_with_context::<i32>(tampered, "users/age")
            .await,
        Err(Error::Aead)
    ));
}

#[tokio::test]
async fn scalar_storage_cross_opens_with_existing_leaf_format() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    // Existing structural writer -> new reader, same envelope and AAD.
    let node = keyset.encrypt_node(42i32, "users/age").await.unwrap();
    let stack_encrypt::CipherText::Single(leaf) = node else {
        panic!("scalar leaf")
    };
    let bytes = leaf.to_bytes();
    let ct = Ciphertext::from_bytes(&bytes).unwrap();
    assert_eq!(ct.to_bytes(), bytes);
    assert_eq!(ct.tag(), leaf.tag());
    assert_eq!(
        keyset
            .decrypt_with_context::<i32>(ct, "users/age")
            .await
            .unwrap(),
        42
    );

    // New writer -> existing structural reader.
    let ct = keyset
        .encrypt_with_context(42i32, "users/age")
        .await
        .unwrap();
    let leaf = stack_encrypt::SealedValue::from_bytes(&ct.to_bytes()).unwrap();
    let opened: i32 = cipher
        .decrypt(stack_encrypt::CipherText::Single(leaf), "users/age")
        .await
        .unwrap();
    assert_eq!(opened, 42);

    let omitted = keyset.encrypt(7i32).await.unwrap();
    assert_eq!(
        keyset
            .decrypt_with_context::<i32>(omitted, ())
            .await
            .unwrap(),
        7
    );
    let explicit = keyset.encrypt_with_context(7i32, ()).await.unwrap();
    assert_eq!(keyset.decrypt::<i32>(explicit).await.unwrap(), 7);
}

// A target author can require a context even for u64, which implements Default.
struct BoundInteger(Ciphertext);
impl EncryptTarget<i32> for BoundInteger {
    type ContextInput = RequiredContext<u64>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, i32, Self, K, Self::ContextInput> {
        stack_encrypt::target::scalar_ciphertext()
            .map(Self)
            .accepting()
    }
}
impl DecryptSource<i32> for BoundInteger {
    type ContextInput = RequiredContext<u64>;
    fn decryption<K: 'static>(self, context: Self::ContextInput) -> Decryption<i32, K> {
        self.0
            .decryption(OptionalContext::<ScalarContext>::supplied(
                context.into_inner().into(),
            ))
    }
}
#[tokio::test]
async fn required_context_target_uses_the_same_engine() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let ct: BoundInteger = 42i32
        .encrypt_into_with_context(&keyset, 0u64)
        .await
        .unwrap();
    assert_eq!(
        i32::decrypt_from_with_context(ct, &keyset, 0u64)
            .await
            .unwrap(),
        42
    );
}

#[tokio::test]
async fn supported_scalar_kinds_round_trip() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    macro_rules! check { ($($value:expr => $ty:ty),* $(,)?) => {$(
        let value: $ty = $value;
        let expected = value.clone();
        let ct = keyset.encrypt(value).await.unwrap();
        assert_eq!(keyset.decrypt::<$ty>(ct).await.unwrap(), expected);
    )*}; }
    check!(true => bool, i8::MIN => i8, i16::MIN => i16, i32::MIN => i32,
        i64::MIN => i64, i128::MIN => i128, u16::MAX => u16,
        u32::MAX => u32, u64::MAX => u64, u128::MAX => u128,
        1.25 => f32, -2.5 => f64, "secret".to_owned() => String);
}

#[tokio::test]
async fn wrong_keyset_is_rejected_before_retrieval() {
    use std::sync::atomic::Ordering;
    let (cipher, _, retrieves) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let other = cipher
        .keyset(stack_encrypt::kms::IdentifiedBy::Uuid(uuid::Uuid::new_v4()))
        .await
        .unwrap();
    let ct = keyset.encrypt(42i32).await.unwrap();
    assert!(matches!(
        other.decrypt::<i32>(ct).await,
        Err(Error::ForeignKeyset { .. })
    ));
    assert_eq!(retrieves.load(Ordering::SeqCst), 0);
}

// Deliberately not Clone: selecting a scalar field must not copy its owner.
struct Tracked {
    value: String,
    wiped: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
impl zeroize::Zeroize for Tracked {
    fn zeroize(&mut self) {
        self.value.zeroize();
        self.wiped.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}
impl Drop for Tracked {
    fn drop(&mut self) {
        assert!(self.value.is_empty(), "owned source dropped without wiping");
    }
}
struct TrackedCiphertext(Ciphertext);
impl EncryptTarget<Tracked> for TrackedCiphertext {
    type ContextInput = OptionalContext<ScalarContext>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, Tracked, Self, K, Self::ContextInput> {
        stack_encrypt::target::scalar_ciphertext::<String, K>()
            .project(|source: &Tracked| &source.value)
            .map(Self)
    }
}
fn tracked() -> (Tracked, std::sync::Arc<std::sync::atomic::AtomicBool>) {
    let wiped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    (
        Tracked {
            value: "secret".to_owned(),
            wiped: wiped.clone(),
        },
        wiped,
    )
}
#[tokio::test]
async fn owned_source_is_wiped_before_await_or_discard() {
    use std::sync::atomic::Ordering;
    let (cipher, generates, _) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let (source, wiped) = tracked();
    let pending = source.encrypt_into::<TrackedCiphertext, _>(&keyset);
    assert!(wiped.load(Ordering::SeqCst));
    assert_eq!(generates.load(Ordering::SeqCst), 0);
    drop(pending);
    assert_eq!(generates.load(Ordering::SeqCst), 0);

    let (source, wiped) = tracked();
    let pending = source.encrypt_into::<TrackedCiphertext, _>(&keyset);
    assert!(wiped.load(Ordering::SeqCst));
    let encrypted = pending.await.unwrap();
    assert_eq!(
        keyset.decrypt::<String>(encrypted.0).await.unwrap(),
        "secret"
    );
}
#[tokio::test]
async fn owned_source_is_wiped_when_context_validation_fails() {
    use std::sync::atomic::Ordering;
    let (cipher, generates, _) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let (source, wiped) = tracked();
    let pending =
        source.encrypt_into_with_context::<TrackedCiphertext, _>(&keyset, "x".repeat(65536));
    assert!(wiped.load(Ordering::SeqCst));
    assert!(pending.await.is_err());
    assert_eq!(generates.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn owned_source_is_guarded_during_context_conversion() {
    struct Panics;
    impl From<Panics> for ScalarContext {
        fn from(_: Panics) -> Self {
            panic!("conversion failed")
        }
    }
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let (source, wiped) = tracked();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        source.encrypt_into_with_context::<TrackedCiphertext, _>(&keyset, Panics)
    }));
    assert!(result.is_err());
    assert!(wiped.load(std::sync::atomic::Ordering::SeqCst));
}

struct FixedInteger(Ciphertext);
impl EncryptTarget<i32> for FixedInteger {
    type ContextInput = stack_encrypt::target::NoCallerContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, i32, Self, K, Self::ContextInput> {
        stack_encrypt::target::scalar_ciphertext()
            .map(Self)
            .under(stack_encrypt::nonempty!("users/fixed-age"))
            .accepting()
    }
}
impl DecryptSource<i32> for FixedInteger {
    type ContextInput = stack_encrypt::target::NoCallerContext;
    fn decryption<K: 'static>(self, _: Self::ContextInput) -> Decryption<i32, K> {
        self.0
            .decryption(OptionalContext::<ScalarContext>::supplied(
                "users/fixed-age".into(),
            ))
    }
}
#[tokio::test]
async fn no_caller_context_preserves_the_declared_context() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let encrypted: FixedInteger = 42i32.encrypt_into(&keyset).await.unwrap();
    // A fixed declaration has exactly the same context as the direct API.
    assert_eq!(
        keyset
            .decrypt_with_context::<i32>(encrypted.0.clone(), "users/fixed-age")
            .await
            .unwrap(),
        42
    );
    assert_eq!(i32::decrypt_from(encrypted, &keyset).await.unwrap(), 42);
}
