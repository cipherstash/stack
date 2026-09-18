//! What reaches ZeroKMS: every data-key request carries the requesting
//! context as its descriptor, on generate and on retrieve alike.
//!
//! The fake source ignores descriptors (see `FakeDataKeySource`'s docs), so
//! these tests assert what is *sent*. The real service HMACs the descriptor
//! into the key tag and refuses to re-derive under a different one — the
//! examples exercise that against a live ZeroKMS.

mod common;

use common::recording_cipher;
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{DecryptFrom, EncryptInto};
use stack_encrypt::{nonempty, DecryptInto, Descriptor, EncryptFrom, Error, StackCipherText};

#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = u32)]
struct EncryptedAge {
    c: StackCipherText,
}

#[derive(Debug, PartialEq, Clone)]
struct User {
    email: String,
    name: String,
    age: u32,
}

#[derive(EncryptFrom, DecryptInto)]
#[stash(struct = User, context = "users")]
struct EncryptedUser {
    email: StackCipherText,
    #[stash(from = email)]
    email_hm: EqualityTerm,
    #[stash(context = "people/name")]
    name: StackCipherText,
    age: EncryptedAge,
}

fn user() -> User {
    User {
        email: "alice@example.com".into(),
        name: "Alice".into(),
        age: 34,
    }
}

#[tokio::test]
async fn a_leaf_sends_its_context_as_the_descriptor_both_ways() -> Result<(), Error> {
    let (cipher, sent) = recording_cipher().await;
    let keyset = cipher.default_keyset();

    let ct: StackCipherText = "alice"
        .encrypt_into_with_context(&keyset, nonempty!("users/email"))
        .await?;
    let _: String = ct.decrypt_into(&cipher, nonempty!("users/email")).await?;

    let sent = sent.lock().expect("lock").clone();
    assert_eq!(sent.generated(), ["users/email"]);
    assert_eq!(sent.retrieved(), ["users/email"]);
    Ok(())
}

#[tokio::test]
async fn a_struct_sends_one_descriptor_per_field_context() -> Result<(), Error> {
    let (cipher, sent) = recording_cipher().await;
    let keyset = cipher.default_keyset();

    let row: EncryptedUser = user().encrypt_into(&keyset).await?;
    let back = User::decrypt_from(row, &cipher).await?;
    assert_eq!(back, user());

    // Inferred `users/email`, the field's own `people/name`, and the inner
    // record under `users/age`; the term derives no key. One call each way.
    let sent = sent.lock().expect("lock").clone();
    assert_eq!(sent.generate.len(), 1, "one generate_keys call");
    assert_eq!(sent.retrieve.len(), 1, "one retrieve_keys call");
    assert_eq!(
        sent.generated(),
        ["users/email", "people/name", "users/age"]
    );
    assert_eq!(
        sent.retrieved(),
        ["users/email", "people/name", "users/age"]
    );
    Ok(())
}

#[tokio::test]
async fn a_callers_context_extends_every_fields_descriptor() -> Result<(), Error> {
    let (cipher, sent) = recording_cipher().await;
    let keyset = cipher.default_keyset();

    let row: EncryptedUser = user().encrypt_into_with_context(&keyset, 7u64).await?;
    let back = User::decrypt_from_with_context(row, &cipher, 7u64).await?;
    assert_eq!(back, user());

    // The extended contexts are composites, rendered part by part — the
    // same value the leaf AAD and the term context are built from.
    let expected: Vec<String> = [
        Descriptor::of(nonempty!("users/email").with(7u64)),
        Descriptor::of(nonempty!("people/name").with(7u64)),
        Descriptor::of(nonempty!("users/age").with(7u64)),
    ]
    .iter()
    .map(|d| d.as_str().to_owned())
    .collect();
    assert_eq!(
        expected,
        ["users/email|7u64", "people/name|7u64", "users/age|7u64"],
        "a composite context renders readably"
    );
    let sent = sent.lock().expect("lock").clone();
    assert_eq!(sent.generated(), expected);
    assert_eq!(sent.retrieved(), expected);
    Ok(())
}

#[tokio::test]
async fn every_leaf_of_a_tree_shares_the_root_descriptor() -> Result<(), Error> {
    let (cipher, sent) = recording_cipher().await;
    let keyset = cipher.default_keyset();

    let column: Vec<StackCipherText> = vec![1u32, 2, 3]
        .encrypt_into_with_context(&keyset, nonempty!("users/age"))
        .await?;
    let _: Vec<u32> = column.decrypt_into(&cipher, nonempty!("users/age")).await?;

    // Per-element AAD derivation is vitaminc's and stays inside the AEAD;
    // ZeroKMS sees the field, not the element.
    let sent = sent.lock().expect("lock").clone();
    assert_eq!(sent.generated(), ["users/age"; 3]);
    assert_eq!(sent.retrieved(), ["users/age"; 3]);
    Ok(())
}

#[tokio::test]
async fn the_cipher_directed_path_renders_its_aad_the_same_way() -> Result<(), Error> {
    let (cipher, sent) = recording_cipher().await;
    let keyset = cipher.default_keyset();

    let ct = keyset.encrypt(42u32, "users/age").await?;
    let _: u32 = cipher.decrypt(ct, "users/age").await?;
    // No AAD at all is the empty descriptor: ZeroKMS binds nothing.
    let ct = keyset.encrypt(42u32, ()).await?;
    let _: u32 = cipher.decrypt(ct, ()).await?;

    let sent = sent.lock().expect("lock").clone();
    assert_eq!(sent.generated(), ["users/age", ""]);
    assert_eq!(sent.retrieved(), ["users/age", ""]);
    Ok(())
}

/// A column renders its context once to check it, then refuses the whole
/// column: an over-long context under ten thousand elements is one
/// rendering, not ten thousand, on either path.
#[tokio::test]
async fn a_column_renders_an_over_long_context_once() -> Result<(), Error> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// A context that counts how often it is encoded. Over the limit once
    /// rendered, so every path refuses it.
    #[derive(Clone)]
    struct Counted(Arc<AtomicUsize>);

    impl<'a> stack_encrypt::IntoAad<'a> for Counted {
        fn into_aad(self) -> stack_encrypt::Aad<'a> {
            self.0.fetch_add(1, Ordering::SeqCst);
            stack_encrypt::Aad::new_owned("a".repeat(Descriptor::MAX_LEN + 1).into_bytes())
        }
    }
    impl stack_encrypt::MaybeEmpty for Counted {
        fn is_empty(&self) -> bool {
            false
        }
    }

    let (cipher, sent) = recording_cipher().await;
    let keyset = cipher.default_keyset();
    let renders = Arc::new(AtomicUsize::new(0));
    let context = stack_encrypt::NonEmpty::new(Counted(renders.clone())).unwrap();

    let values: Vec<u32> = (0..10_000).collect();
    let result: Result<Vec<StackCipherText>, Error> = values
        .encrypt_into_with_context(&keyset, context.clone())
        .await;
    assert!(
        matches!(result, Err(Error::DescriptorTooLong { .. })),
        "{result:?}"
    );
    assert_eq!(
        renders.load(Ordering::SeqCst),
        1,
        "one rendering on encrypt"
    );

    let column: Vec<StackCipherText> = vec![1u32, 2, 3]
        .encrypt_into_with_context(&keyset, nonempty!("users/age"))
        .await?;
    let opened: Result<Vec<u32>, Error> = column.decrypt_into(&cipher, context).await;
    assert!(
        matches!(opened, Err(Error::DescriptorTooLong { .. })),
        "{opened:?}"
    );
    assert_eq!(
        renders.load(Ordering::SeqCst),
        2,
        "one rendering on decrypt"
    );

    let sent = sent.lock().expect("lock").clone();
    assert_eq!(
        sent.generated(),
        ["users/age"; 3],
        "only the good seal was sent"
    );
    assert!(sent.retrieved().is_empty(), "nothing retrieved");
    Ok(())
}

/// The column check is for columns that bind keys. A column of terms
/// derives locally under any context, however long, and an empty column
/// binds nothing — neither is held to the descriptor limit.
#[tokio::test]
async fn a_column_with_nothing_to_bind_takes_any_context() -> Result<(), Error> {
    let (cipher, sent) = recording_cipher().await;
    let keyset = cipher.default_keyset();
    let long = stack_encrypt::NonEmpty::new("a".repeat(Descriptor::MAX_LEN + 1)).unwrap();

    let names = vec!["alice".to_string(), "bob".to_string()];
    let terms: Vec<EqualityTerm> = names
        .encrypt_into_with_context(&keyset, long.clone())
        .await?;
    assert_eq!(terms.len(), 2);

    let none: Vec<u32> = Vec::new();
    let sealed: Vec<StackCipherText> = none
        .encrypt_into_with_context(&keyset, long.clone())
        .await?;
    assert!(sealed.is_empty());
    let opened: Vec<u32> = sealed.decrypt_into(&cipher, long).await?;
    assert!(opened.is_empty());

    let sent = sent.lock().expect("lock").clone();
    assert!(sent.generated().is_empty() && sent.retrieved().is_empty());
    Ok(())
}

/// A context that renders past ZeroKMS's descriptor limit is refused before
/// a single request is built — not after one per leaf — and nothing is sent:
/// the size of the tree does not multiply the cost of an over-long context.
#[tokio::test]
async fn an_over_long_context_is_refused_before_any_request_on_either_path() -> Result<(), Error> {
    let (cipher, sent) = recording_cipher().await;
    let keyset = cipher.default_keyset();
    let long = stack_encrypt::NonEmpty::new("a".repeat(Descriptor::MAX_LEN + 1)).unwrap();

    let values: Vec<u32> = (0..10_000).collect();
    let result: Result<Vec<StackCipherText>, Error> = values
        .encrypt_into_with_context(&keyset, long.clone())
        .await;
    assert!(
        matches!(result, Err(Error::DescriptorTooLong { len }) if len == Descriptor::MAX_LEN + 1),
        "{result:?}"
    );

    let sealed: StackCipherText = 7u32
        .encrypt_into_with_context(&keyset, nonempty!("users/age"))
        .await?;
    let opened: Result<u32, Error> = sealed.decrypt_into(&cipher, long).await;
    assert!(
        matches!(opened, Err(Error::DescriptorTooLong { .. })),
        "{opened:?}"
    );

    let sent = sent.lock().expect("lock").clone();
    assert_eq!(
        sent.generated(),
        ["users/age"],
        "only the good seal was sent"
    );
    assert!(sent.retrieved().is_empty(), "nothing retrieved");
    Ok(())
}
