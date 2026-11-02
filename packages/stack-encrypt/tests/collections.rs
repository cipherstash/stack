//! Owned collections: `Vec<S>` encrypts into `Vec<T>` and back as one
//! logical batch of independently authenticated elements. No service
//! credentials are needed.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use stack_encrypt::target::{
    AcceptsContext, DecryptSource, Decryption, EncryptTarget, Encryption, NoCallerContext,
    OptionalContext, RequiredContext, ScalarContext,
};
use stack_encrypt::{Ciphertext, DecryptFrom, EncryptInto, Error};
mod common;

#[tokio::test]
async fn a_column_round_trips_without_caller_context_in_one_batch() {
    let (cipher, generates, retrieves) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let ages = vec![3i32, -1, 42, 0, 7];

    let column: Vec<Ciphertext> = ages.clone().encrypt_into(&keyset).await.unwrap();
    assert_eq!(column.len(), ages.len());
    assert_eq!(
        generates.load(Ordering::SeqCst),
        1,
        "five elements share one generate_keys call"
    );

    let opened = Vec::<i32>::decrypt_from(column.clone(), &keyset)
        .await
        .unwrap();
    assert_eq!(opened, ages, "order is preserved");
    assert_eq!(
        retrieves.load(Ordering::SeqCst),
        1,
        "five elements share one retrieve_keys call"
    );

    // Every element is an ordinary opaque ciphertext: the scalar API opens
    // it on its own, under the same empty context.
    for (element, age) in column.into_iter().zip(ages) {
        assert_eq!(keyset.decrypt::<i32>(element).await.unwrap(), age);
    }

    let names = vec!["ada".to_owned(), "grace".to_owned()];
    let column: Vec<Ciphertext> = names.clone().encrypt_into(&keyset).await.unwrap();
    assert_eq!(
        Vec::<String>::decrypt_from(column, &cipher).await.unwrap(),
        names
    );
}

#[tokio::test]
async fn a_column_round_trips_with_caller_context() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let ages = vec![29i32, 34, 41];

    let column: Vec<Ciphertext> = ages
        .clone()
        .encrypt_into_with_context(&keyset, ("users", "age"))
        .await
        .unwrap();
    assert_eq!(
        Vec::<i32>::decrypt_from_with_context(column.clone(), &keyset, ("users", "age"))
            .await
            .unwrap(),
        ages
    );
    // The context is each element's own AAD, as the scalar API binds it.
    assert_eq!(
        keyset
            .decrypt_with_context::<i32>(column[1].clone(), ("users", "age"))
            .await
            .unwrap(),
        34
    );
    assert!(matches!(
        Vec::<i32>::decrypt_from(column.clone(), &keyset).await,
        Err(Error::Aead)
    ));
    assert!(matches!(
        Vec::<i32>::decrypt_from_with_context(column, &keyset, ("users", "name")).await,
        Err(Error::Aead)
    ));
}

#[tokio::test]
async fn an_empty_column_makes_no_key_request() {
    let (cipher, generates, retrieves) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let column: Vec<Ciphertext> = Vec::<i32>::new().encrypt_into(&keyset).await.unwrap();
    assert!(column.is_empty());
    let opened = Vec::<i32>::decrypt_from(column, &keyset).await.unwrap();
    assert!(opened.is_empty());
    assert_eq!(generates.load(Ordering::SeqCst), 0);
    assert_eq!(retrieves.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn elements_are_authenticated_on_their_own_not_as_a_sequence() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let column: Vec<Ciphertext> = vec![1i32, 2, 3].encrypt_into(&keyset).await.unwrap();

    // Neither order nor length is authenticated: stored values are rows,
    // which come back in any order and in part.
    let mut reordered = column.clone();
    reordered.reverse();
    assert_eq!(
        Vec::<i32>::decrypt_from(reordered, &keyset).await.unwrap(),
        [3, 2, 1]
    );
    assert_eq!(
        Vec::<i32>::decrypt_from(column[..2].to_vec(), &keyset)
            .await
            .unwrap(),
        [1, 2]
    );

    // Each element is: one altered byte fails the column.
    let mut bytes = column[1].to_bytes();
    *bytes.last_mut().unwrap() ^= 1;
    let mut tampered = column.clone();
    tampered[1] = Ciphertext::from_bytes(&bytes).unwrap();
    assert!(matches!(
        Vec::<i32>::decrypt_from(tampered, &keyset).await,
        Err(Error::Aead)
    ));

    // The element's type is its own too: an element of another type in
    // the column is a shape refusal, not tampering.
    let mut mixed = column.clone();
    mixed[2] = keyset.encrypt("three".to_owned()).await.unwrap();
    assert!(matches!(
        Vec::<i32>::decrypt_from(mixed, &keyset).await,
        Err(Error::OpenedType { .. })
    ));
}

#[tokio::test]
async fn a_foreign_keyset_element_is_refused_before_retrieval() {
    let (cipher, _, retrieves) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let other = cipher
        .keyset(stack_encrypt::kms::IdentifiedBy::Uuid(uuid::Uuid::new_v4()))
        .await
        .unwrap();
    let column: Vec<Ciphertext> = vec![1i32, 2].encrypt_into(&keyset).await.unwrap();
    assert!(matches!(
        Vec::<i32>::decrypt_from(column, &other).await,
        Err(Error::ForeignKeyset { .. })
    ));
    assert_eq!(retrieves.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_byte_string_is_one_ciphertext_and_a_column_of_them_is_a_column() {
    let (cipher, generates, retrieves) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();

    // One byte leaf: one ciphertext, one key.
    let blob: Ciphertext = vec![0u8, 1, 255].encrypt_into(&keyset).await.unwrap();
    assert_eq!(
        Vec::<u8>::decrypt_from(blob.clone(), &keyset)
            .await
            .unwrap(),
        [0, 1, 255]
    );
    // A byte leaf opened as a `String` is a type mismatch, not tampering.
    assert!(matches!(
        keyset.decrypt::<String>(blob).await,
        Err(Error::OpenedType { .. })
    ));
    assert_eq!(generates.load(Ordering::SeqCst), 1);
    assert_eq!(retrieves.load(Ordering::SeqCst), 2);

    // A column of byte strings, the empty one included, is one batch.
    let blobs = vec![vec![1u8, 2, 3], vec![], vec![9]];
    let column: Vec<Ciphertext> = blobs.clone().encrypt_into(&keyset).await.unwrap();
    assert_eq!(column.len(), 3);
    assert_eq!(generates.load(Ordering::SeqCst), 2);
    assert_eq!(
        Vec::<Vec<u8>>::decrypt_from(column.clone(), &keyset)
            .await
            .unwrap(),
        blobs
    );
    assert_eq!(retrieves.load(Ordering::SeqCst), 3);
    // Each element is an ordinary byte-string ciphertext.
    assert_eq!(
        keyset.decrypt::<Vec<u8>>(column[2].clone()).await.unwrap(),
        [9]
    );

    // A fixed-width byte array is a byte leaf too.
    let key: Ciphertext = [7u8; 16].encrypt_into(&keyset).await.unwrap();
    assert_eq!(
        <[u8; 16]>::decrypt_from(key, &keyset).await.unwrap(),
        [7u8; 16]
    );
}

#[tokio::test]
async fn nested_columns_settle_in_one_batch_and_keep_their_shape() {
    let (cipher, generates, retrieves) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let rows = vec![vec![1i32, 2], vec![], vec![3]];
    let column: Vec<Vec<Ciphertext>> = rows.clone().encrypt_into(&keyset).await.unwrap();
    assert_eq!(column.iter().map(Vec::len).collect::<Vec<_>>(), [2, 0, 1]);
    assert_eq!(generates.load(Ordering::SeqCst), 1);
    assert_eq!(
        Vec::<Vec<i32>>::decrypt_from(column, &keyset)
            .await
            .unwrap(),
        rows
    );
    assert_eq!(retrieves.load(Ordering::SeqCst), 1);
}

// A target that requires a caller context, even though `u64: Default`.
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
async fn a_column_of_a_required_context_target_takes_the_elements_requirement() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let column: Vec<BoundInteger> = vec![1i32, 2, 3]
        .encrypt_into_with_context(&keyset, 7u64)
        .await
        .unwrap();
    assert_eq!(
        keyset
            .decrypt_with_context::<i32>(column[0].0.clone(), 7u64)
            .await
            .unwrap(),
        1
    );
    let wrong: Vec<BoundInteger> = column.iter().map(|b| BoundInteger(b.0.clone())).collect();
    assert!(matches!(
        Vec::<i32>::decrypt_from_with_context(wrong, &keyset, 8u64).await,
        Err(Error::Aead)
    ));
    assert_eq!(
        Vec::<i32>::decrypt_from_with_context(column, &keyset, 7u64)
            .await
            .unwrap(),
        [1, 2, 3]
    );
}

// A target that declares its whole context and accepts none from the caller.
struct FixedInteger(Ciphertext);
impl EncryptTarget<i32> for FixedInteger {
    type ContextInput = NoCallerContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, i32, Self, K, Self::ContextInput> {
        stack_encrypt::target::scalar_ciphertext()
            .map(Self)
            .under(stack_encrypt::nonempty!("users/fixed-age"))
            .accepting()
    }
}
impl DecryptSource<i32> for FixedInteger {
    type ContextInput = NoCallerContext;
    fn decryption<K: 'static>(self, _: Self::ContextInput) -> Decryption<i32, K> {
        self.0
            .decryption(OptionalContext::<ScalarContext>::supplied(
                "users/fixed-age".into(),
            ))
    }
}
#[tokio::test]
async fn a_column_of_a_no_caller_context_target_keeps_the_declared_context() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let column: Vec<FixedInteger> = vec![5i32, 6].encrypt_into(&keyset).await.unwrap();
    assert_eq!(
        keyset
            .decrypt_with_context::<i32>(column[1].0.clone(), "users/fixed-age")
            .await
            .unwrap(),
        6
    );
    assert_eq!(
        Vec::<i32>::decrypt_from(column, &keyset).await.unwrap(),
        [5, 6]
    );
}

// Deliberately not Clone: a column of these is held by the conversion's
// guard and handed to each element's declaration by reference.
struct Tracked {
    value: String,
    wiped: Arc<AtomicBool>,
}
impl zeroize::Zeroize for Tracked {
    fn zeroize(&mut self) {
        self.value.zeroize();
        self.wiped.store(true, Ordering::SeqCst);
    }
}
impl Drop for Tracked {
    fn drop(&mut self) {
        assert!(
            self.value.is_empty(),
            "owned plaintext dropped without wiping"
        );
    }
}
fn tracked(value: &str) -> (Tracked, Arc<AtomicBool>) {
    let wiped = Arc::new(AtomicBool::new(false));
    (
        Tracked {
            value: value.to_owned(),
            wiped: wiped.clone(),
        },
        wiped,
    )
}
fn tracked_column(values: &[&str]) -> (Vec<Tracked>, Vec<Arc<AtomicBool>>) {
    values.iter().map(|value| tracked(value)).unzip()
}
fn all_wiped(flags: &[Arc<AtomicBool>]) -> bool {
    flags.iter().all(|flag| flag.load(Ordering::SeqCst))
}
struct TrackedCiphertext {
    ciphertext: Ciphertext,
    /// Set when the plaintext this opens to is wiped.
    wiped: Arc<AtomicBool>,
}
impl TrackedCiphertext {
    fn new(ciphertext: Ciphertext) -> Self {
        Self {
            ciphertext,
            wiped: Arc::default(),
        }
    }
}
impl EncryptTarget<Tracked> for TrackedCiphertext {
    type ContextInput = OptionalContext<ScalarContext>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, Tracked, Self, K, Self::ContextInput> {
        stack_encrypt::target::scalar_ciphertext::<String, K>()
            .project(|source: &Tracked| &source.value)
            .map(Self::new)
    }
}
/// Opens to a [`Tracked`], so wiping of recovered plaintext is observable.
impl DecryptSource<Tracked> for TrackedCiphertext {
    type ContextInput = OptionalContext<ScalarContext>;
    fn decryption<K: 'static>(self, context: Self::ContextInput) -> Decryption<Tracked, K> {
        let wiped = self.wiped;
        self.ciphertext
            .decryption(context)
            .map(move |value: String| Tracked { value, wiped })
    }
}

#[tokio::test]
async fn owned_elements_are_wiped_before_the_pending_is_returned() {
    let (cipher, generates, _) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();

    let (column, wiped) = tracked_column(&["one", "two", "three"]);
    let pending = column.encrypt_into::<Vec<TrackedCiphertext>, _>(&keyset);
    assert!(all_wiped(&wiped), "every element is wiped before any await");
    assert_eq!(generates.load(Ordering::SeqCst), 0);
    drop(pending);
    assert_eq!(generates.load(Ordering::SeqCst), 0);

    let (column, wiped) = tracked_column(&["one", "two", "three"]);
    let pending = column.encrypt_into::<Vec<TrackedCiphertext>, _>(&keyset);
    assert!(all_wiped(&wiped));
    let encrypted = pending.await.unwrap();
    assert_eq!(generates.load(Ordering::SeqCst), 1);
    let opened: Vec<String> = Vec::<String>::decrypt_from(
        encrypted
            .into_iter()
            .map(|t| t.ciphertext)
            .collect::<Vec<_>>(),
        &keyset,
    )
    .await
    .unwrap();
    assert_eq!(opened, ["one", "two", "three"]);
}

#[tokio::test]
async fn owned_elements_are_wiped_when_the_context_is_refused() {
    let (cipher, generates, _) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let (column, wiped) = tracked_column(&["one", "two"]);
    let pending =
        column.encrypt_into_with_context::<Vec<TrackedCiphertext>, _>(&keyset, "x".repeat(65536));
    assert!(all_wiped(&wiped));
    assert!(pending.await.is_err());
    assert_eq!(generates.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn owned_elements_are_guarded_during_context_conversion() {
    struct Panics;
    impl From<Panics> for ScalarContext {
        fn from(_: Panics) -> Self {
            panic!("conversion failed")
        }
    }
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let (column, wiped) = tracked_column(&["one", "two"]);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        column.encrypt_into_with_context::<Vec<TrackedCiphertext>, _>(&keyset, Panics)
    }));
    assert!(result.is_err());
    assert!(all_wiped(&wiped));
}

#[tokio::test]
async fn a_late_element_failure_wipes_the_plaintext_recovered_before_it() {
    let (cipher, _, retrieves) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let first = keyset.encrypt("recovered first".to_owned()).await.unwrap();
    // The second element is sealed under another context, so it fails
    // authentication only once its key has arrived: the first element has
    // been recovered by then.
    let second = keyset
        .encrypt_with_context("never recovered".to_owned(), "elsewhere")
        .await
        .unwrap();
    let column = vec![
        TrackedCiphertext::new(first),
        TrackedCiphertext::new(second),
    ];
    let wiped: Vec<_> = column.iter().map(|t| t.wiped.clone()).collect();
    // `Tracked::drop` also fails the test if the recovered prefix is
    // dropped unwiped.
    let result = Vec::<Tracked>::decrypt_from(column, &keyset).await;
    assert!(matches!(result, Err(Error::Aead)), "{:?}", result.err());
    assert!(
        wiped[0].load(Ordering::SeqCst),
        "the recovered prefix is wiped"
    );
    assert!(
        !wiped[1].load(Ordering::SeqCst),
        "nothing was recovered to wipe"
    );
    assert_eq!(retrieves.load(Ordering::SeqCst), 1, "both keys in one call");
}

// Opens to a `Flagged`, and panics in its conversion when told to. `Flagged`
// has no drop check of its own, so an unwiped drop during the unwind is seen
// through the flag rather than as an abort.
struct Flagged {
    value: String,
    wiped: Arc<AtomicBool>,
}
impl zeroize::Zeroize for Flagged {
    fn zeroize(&mut self) {
        self.value.zeroize();
        self.wiped.store(true, Ordering::SeqCst);
    }
}
struct PanickingCiphertext {
    ciphertext: Ciphertext,
    panics: bool,
    wiped: Arc<AtomicBool>,
}
impl DecryptSource<Flagged> for PanickingCiphertext {
    type ContextInput = OptionalContext<ScalarContext>;
    fn decryption<K: 'static>(self, context: Self::ContextInput) -> Decryption<Flagged, K> {
        let (panics, wiped) = (self.panics, self.wiped);
        self.ciphertext
            .decryption(context)
            .map(move |value: String| {
                assert!(!panics, "element conversion failed");
                Flagged { value, wiped }
            })
    }
}

#[test]
fn a_panicking_element_conversion_wipes_the_plaintext_recovered_before_it() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let cipher = rt.block_on(common::stack_cipher());
    let keyset = cipher.default_keyset();
    let column: Vec<_> = rt
        .block_on(async {
            vec![
                keyset.encrypt("recovered first".to_owned()).await.unwrap(),
                keyset.encrypt("never recovered".to_owned()).await.unwrap(),
            ]
        })
        .into_iter()
        .enumerate()
        .map(|(row, ciphertext)| PanickingCiphertext {
            ciphertext,
            panics: row == 1,
            wiped: Arc::default(),
        })
        .collect();
    let wiped: Vec<_> = column.iter().map(|c| c.wiped.clone()).collect();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.block_on(async { Vec::<Flagged>::decrypt_from(column, &keyset).await })
    }));
    assert!(result.is_err(), "the element conversion panicked");
    assert!(
        wiped[0].load(Ordering::SeqCst),
        "the prefix recovered before the panic is wiped during the unwind"
    );
}

// --- The structural `Vec` declarations wipe what they recovered too --------

/// The same column, declared the structural way (`DecryptInto`), so the
/// legacy `Vec<T>: DecryptInto<Vec<P>>` path is the one under test.
impl stack_encrypt::DecryptInto<Tracked> for TrackedCiphertext {
    type Context = stack_encrypt::target::AeadContext;
    fn decryption<K: 'static>(self, context: Self::Context) -> Decryption<Tracked, K> {
        let wiped = self.wiped;
        self.ciphertext
            .decryption(OptionalContext::<ScalarContext>::supplied(context.into()))
            .map(move |value: String| Tracked { value, wiped })
    }
}

#[tokio::test]
async fn a_late_element_failure_wipes_the_recovered_prefix_on_the_structural_path_too() {
    let (cipher, _, retrieves) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let context = stack_encrypt::nonempty!("rows");
    let first = keyset
        .encrypt_with_context("recovered first".to_owned(), context)
        .await
        .unwrap();
    // Sealed under another context: fails authentication only once its key
    // has arrived, by which time the first element has been recovered.
    let second = keyset
        .encrypt_with_context("never recovered".to_owned(), "elsewhere")
        .await
        .unwrap();
    let column = vec![
        TrackedCiphertext::new(first),
        TrackedCiphertext::new(second),
    ];
    let wiped: Vec<_> = column.iter().map(|t| t.wiped.clone()).collect();
    // `Tracked::drop` fails the test if the recovered prefix is dropped
    // unwiped, which is what the structural path did before it opened
    // through the wiping collection.
    let result = cipher
        .decrypt_as::<Vec<Tracked>, _>(column, stack_encrypt::target::AeadContext::from(context))
        .await;
    assert!(matches!(result, Err(Error::Aead)), "{:?}", result.err());
    assert!(
        wiped[0].load(Ordering::SeqCst),
        "the recovered prefix is wiped"
    );
    assert!(
        !wiped[1].load(Ordering::SeqCst),
        "nothing was recovered to wipe"
    );
    assert_eq!(retrieves.load(Ordering::SeqCst), 1, "both keys in one call");
}
