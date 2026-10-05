//! A consumer outside the crate: typed EQL-shaped records, native readers, and
//! cross-opening through the canonical cipher path. No plaintext Serde fallback.
mod common;
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::transcode::{MapReader, Reader, SequenceReader, Transcode, Visitor};
use stack_encrypt::target::{self, CallerContext, ExpectedContext};
use stack_encrypt::KeysetRegistry;
use stack_encrypt::{
    nonempty, Cipher, CipherText, ContextPiece, DecryptField, DecryptInto, Decryptable, Decryption,
    Encrypt, EncryptFrom, Encryption, Error, IntoAad, IntoContext, MaybeEmpty, NonEmpty,
    SealedValue, StackCipherText,
};

#[derive(Clone, Debug, PartialEq)]
struct Identifier {
    table: String,
    column: String,
}
impl Identifier {
    fn email() -> NonEmpty<Self> {
        NonEmpty::new(Self {
            table: "users".into(),
            column: "email".into(),
        })
        .unwrap()
    }
}
impl MaybeEmpty for Identifier {
    fn is_empty(&self) -> bool {
        self.table.is_empty() || self.column.is_empty()
    }
}
impl<'a> IntoContext<'a> for Identifier {
    fn into_context(self) -> ContextPiece<'a> {
        (self.table, self.column).into_context()
    }
}

struct StoredLeaf(Vec<u8>);
struct LeafVisitor;
impl Visitor for LeafVisitor {
    type Value = StoredLeaf;
    fn sealed(self, leaf: SealedValue) -> Result<StoredLeaf, Error> {
        Ok(StoredLeaf(leaf.to_bytes()))
    }
}
impl Transcode for StoredLeaf {
    type Visitor = LeafVisitor;
    fn visitor() -> LeafVisitor {
        LeafVisitor
    }
}
impl<S: Encrypt + Clone> EncryptFrom<S> for StoredLeaf {
    type Context = CallerContext;
    fn encryption<'s, K: KeysetRegistry + 'static>() -> Encryption<'s, S, Self, K, Self::Context>
    where
        S: 's,
    {
        target::ciphertext().accepting().transcode()
    }
}
impl<P: stack_encrypt::Decrypt<'static> + 'static> DecryptInto<P> for StoredLeaf {
    type Context = CallerContext;
    fn decryption<K: KeysetRegistry + 'static>(self, context: Self::Context) -> Decryption<P, K> {
        match SealedValue::from_bytes(&self.0) {
            Ok(leaf) => target::open(CipherText::Single(leaf), context),
            Err(error) => Decryption::failed(Error::Other(Box::new(error))),
        }
    }
}
impl Decryptable for StoredLeaf {
    const DECRYPTABLE: bool = true;
}
impl<P, Ctx> DecryptField<P, Ctx> for StoredLeaf
where
    Self: DecryptInto<P>,
    Ctx: Into<<Self as DecryptInto<P>>::Context>,
{
    fn decryption_field<K: KeysetRegistry + 'static>(self, ctx: Ctx) -> Option<Decryption<P, K>> {
        Some(self.decryption(ctx.into()))
    }
}

#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = String)]
struct TextEq {
    #[stash(context_field)]
    i: Identifier,
    c: StoredLeaf,
    hm: EqualityTerm,
    #[stash(default = 3)]
    v: u8,
}

fn other_column() -> NonEmpty<Identifier> {
    NonEmpty::new(Identifier {
        table: "users".into(),
        column: "other".into(),
    })
    .unwrap()
}

#[tokio::test]
async fn stored_identifier_supplies_every_operations_context() {
    let (cipher, provider) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let email = "alice@example.com".to_owned();
    let record: TextEq = keyset
        .encrypt_as(&email, Identifier::email())
        .await
        .unwrap();
    assert_eq!(
        record.i,
        Identifier::email().into_inner(),
        "the identifier is stored in the record as given"
    );
    assert_eq!(record.v, 3, "a defaulted field is filled, not derived");
    assert_eq!(
        provider.call_counts().0,
        1,
        "one ciphertext leaf means one data key, in one batch"
    );
    let probe = keyset
        .equality_term(email.clone(), Identifier::email())
        .await
        .unwrap();
    assert_eq!(
        record.hm, probe,
        "the term is derived under the stored identifier, so a probe under it matches"
    );
    // Storage envelope names c/hm add no extra AAD; the canonical path opens it.
    let opened: String = cipher
        .decrypt(
            CipherText::Single(SealedValue::from_bytes(&record.c.0).unwrap()),
            Identifier::email(),
        )
        .await
        .unwrap();
    assert_eq!(
        opened, email,
        "the canonical path opens a leaf the record sealed under the identifier alone"
    );
}

#[tokio::test]
async fn canonical_ciphertext_opens_through_the_record() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let email = "alice@example.com".to_owned();
    let canonical = keyset
        .encrypt(email.clone(), Identifier::email())
        .await
        .unwrap();
    let probe = keyset
        .equality_term(email.clone(), Identifier::email())
        .await
        .unwrap();
    let record = TextEq {
        i: Identifier::email().into_inner(),
        c: canonical.read(LeafVisitor).unwrap(),
        hm: probe,
        v: 3,
    };
    let opened: String = cipher
        .decrypt_as(record, ExpectedContext::default())
        .await
        .unwrap();
    assert_eq!(
        opened, email,
        "a record assembled from canonical output opens under its stored identifier"
    );
}

#[tokio::test]
async fn expected_identifier_is_checked_before_any_key_is_retrieved() {
    let (cipher, provider) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let email = "alice@example.com".to_owned();
    let record: TextEq = keyset
        .encrypt_as(&email, Identifier::email())
        .await
        .unwrap();
    let before = provider.call_counts().1;
    let result = cipher
        .decrypt_as::<String, _>(record, other_column().into())
        .await;
    assert!(
        matches!(result, Err(Error::ContextMismatch { .. })),
        "a stored identifier that differs from the expected one is a mismatch, got {result:?}"
    );
    assert_eq!(
        provider.call_counts().1,
        before,
        "the mismatch is refused before ZeroKMS is asked for a key"
    );
}

#[tokio::test]
async fn empty_stored_identifier_is_refused_before_any_key_is_retrieved() {
    let (cipher, provider) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let email = "alice@example.com".to_owned();
    let mut record: TextEq = keyset
        .encrypt_as(&email, Identifier::email())
        .await
        .unwrap();
    record.i.column.clear();
    let before = provider.call_counts().1;
    let result = cipher
        .decrypt_as::<String, _>(record, Default::default())
        .await;
    assert!(
        result.is_err(),
        "a stored identifier is data, not a proof: an empty one fails validation"
    );
    assert_eq!(
        provider.call_counts().1,
        before,
        "validation runs before ZeroKMS is asked for a key"
    );
}

#[derive(Clone)]
struct WithoutSerde(String);
impl Encrypt for WithoutSerde {
    fn encrypt_with_aad<'a, C: Cipher, A: IntoAad<'a>>(
        self,
        cipher: C,
        aad: A,
    ) -> Result<C::Ok, C::Error> {
        self.0.encrypt_with_aad(cipher, aad)
    }
}
#[tokio::test]
async fn ciphertext_uses_plaintexts_native_contract_without_serde() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let result: StoredLeaf = keyset
        .encrypt_as(&WithoutSerde("native".into()), nonempty!("value").into())
        .await
        .unwrap();
    let opened: String = cipher
        .decrypt(
            CipherText::Single(SealedValue::from_bytes(&result.0).unwrap()),
            nonempty!("value"),
        )
        .await
        .unwrap();
    assert_eq!(
        opened, "native",
        "a plaintext without Serde seals through its own Encrypt impl and opens canonically"
    );
    let text = String::from("borrowed");
    let result: StoredLeaf = keyset
        .encrypt_as(&text.as_str(), nonempty!("value").into())
        .await
        .unwrap();
    let opened: String = cipher
        .decrypt(
            CipherText::Single(SealedValue::from_bytes(&result.0).unwrap()),
            nonempty!("value"),
        )
        .await
        .unwrap();
    assert_eq!(opened, text, "a borrowed plaintext seals the same way");
}

#[tokio::test]
async fn scalar_destination_refuses_a_sequence() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    // A scalar destination must refuse a sequence rather than flatten or serialize it.
    let result = keyset
        .encrypt_as::<_, StoredLeaf>(&vec![1u32, 2], nonempty!("value").into())
        .await;
    assert!(
        matches!(result, Err(Error::UnsupportedShape)),
        "a visitor that only takes `sealed` refuses a sequence by type, got {:?}",
        result.err()
    );
}

// A target whose declaration carries every context it needs asks its caller
// for none: `Context = ()`.
struct FixedLeaf(StoredLeaf);
impl<S: Encrypt + Clone> EncryptFrom<S> for FixedLeaf {
    type Context = ();
    fn encryption<'s, K: KeysetRegistry + 'static>() -> Encryption<'s, S, Self, K, Self::Context>
    where
        S: 's,
    {
        // The declaration names its own context with `under`; `()` then
        // satisfies the `DeclaredContext` that leaves.
        target::ciphertext()
            .transcode()
            .map(Self)
            .under(nonempty!("fixed/leaf"))
            .accepting()
    }
}
impl<P: stack_encrypt::Decrypt<'static> + 'static> DecryptInto<P> for FixedLeaf {
    type Context = ();
    fn decryption<K: KeysetRegistry + 'static>(self, (): ()) -> Decryption<P, K> {
        self.0.decryption(nonempty!("fixed/leaf").into())
    }
}

#[tokio::test]
async fn unit_context_target_supplies_its_own_context() {
    use stack_encrypt::EncryptInto;
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let text = String::from("fixed");
    let stored: FixedLeaf = text.encrypt_into(&keyset).await.unwrap();
    let opened: String = cipher
        .decrypt(
            CipherText::Single(SealedValue::from_bytes(&stored.0 .0).unwrap()),
            nonempty!("fixed/leaf"),
        )
        .await
        .unwrap();
    assert_eq!(
        opened, text,
        "the leaf was sealed under the context the declaration named, not one the caller gave"
    );
    let stored: FixedLeaf = keyset.encrypt_as(&text, ()).await.unwrap();
    let opened: String = cipher.decrypt_as(stored, ()).await.unwrap();
    assert_eq!(
        opened, text,
        "and it opens back through the declaration alone"
    );
}

// An illustrative final storage format. Each native child is consumed directly
// into its destination; no intermediate universal tree or byte buffer is built.
enum Stored {
    Value(SealedValue),
    List(Vec<Stored>),
    Object(Vec<(String, Stored)>),
    Absent(SealedValue),
    EmptyList(SealedValue),
    EmptyObject(SealedValue),
    Metadata(stack_encrypt::BoxedPassthrough),
}
struct TreeVisitor;
impl Visitor for TreeVisitor {
    type Value = Stored;
    fn sealed(self, leaf: SealedValue) -> Result<Stored, Error> {
        Ok(Stored::Value(leaf))
    }
    fn sequence<R: SequenceReader>(self, mut reader: R) -> Result<Stored, Error> {
        let mut output = Vec::with_capacity(reader.remaining());
        while let Some(child) = reader.next() {
            output.push(child.read(TreeVisitor)?);
        }
        Ok(Stored::List(output))
    }
    fn map<R: MapReader>(self, mut reader: R) -> Result<Stored, Error> {
        let mut output = Vec::with_capacity(reader.remaining());
        while let Some((key, child)) = reader.next() {
            output.push((key, child.read(TreeVisitor)?));
        }
        Ok(Stored::Object(output))
    }
    fn absent(self, marker: SealedValue) -> Result<Stored, Error> {
        Ok(Stored::Absent(marker))
    }
    fn empty_sequence(self, marker: SealedValue) -> Result<Stored, Error> {
        Ok(Stored::EmptyList(marker))
    }
    fn empty_map(self, marker: SealedValue) -> Result<Stored, Error> {
        Ok(Stored::EmptyObject(marker))
    }
    fn passthrough(self, value: stack_encrypt::BoxedPassthrough) -> Result<Stored, Error> {
        Ok(Stored::Metadata(value))
    }
}
impl Stored {
    fn native(self) -> StackCipherText {
        match self {
            Self::Value(v) => CipherText::Single(v),
            Self::List(v) => CipherText::Sequence(v.into_iter().map(Self::native).collect()),
            Self::Object(v) => {
                CipherText::Map(v.into_iter().map(|(k, v)| (k, v.native())).collect())
            }
            Self::Absent(v) => CipherText::None(v),
            Self::EmptyList(v) => CipherText::EmptySequence(v),
            Self::EmptyObject(v) => CipherText::EmptyMap(v),
            Self::Metadata(v) => CipherText::Passthrough(v),
        }
    }
}

#[test]
fn native_readers_report_the_number_of_remaining_entries() {
    struct LengthVisitor;

    impl Visitor for LengthVisitor {
        type Value = usize;

        fn sequence<R: SequenceReader>(self, mut reader: R) -> Result<usize, Error> {
            let length = reader.remaining();
            assert_eq!(
                length, 3,
                "sequence should initially report all three entries"
            );
            for consumed in 1..=length {
                assert!(
                    reader.next().is_some(),
                    "sequence entry {consumed} should exist"
                );
                assert_eq!(
                    reader.remaining(),
                    length - consumed,
                    "sequence should report its remaining length after entry {consumed}"
                );
            }
            assert!(
                reader.next().is_none(),
                "sequence should end after three entries"
            );
            Ok(length)
        }

        fn map<R: MapReader>(self, mut reader: R) -> Result<usize, Error> {
            let length = reader.remaining();
            assert_eq!(length, 3, "map should initially report all three entries");
            for consumed in 1..=length {
                assert!(reader.next().is_some(), "map entry {consumed} should exist");
                assert_eq!(
                    reader.remaining(),
                    length - consumed,
                    "map should report its remaining length after entry {consumed}"
                );
            }
            assert!(
                reader.next().is_none(),
                "map should end after three entries"
            );
            Ok(length)
        }
    }

    let value = || CipherText::Passthrough(Box::new(7_u32) as stack_encrypt::BoxedPassthrough);
    let sequence: StackCipherText = CipherText::Sequence(vec![value(), value(), value()]);
    assert_eq!(
        sequence.read(LengthVisitor).unwrap(),
        3,
        "sequence should yield three entries"
    );

    let map: StackCipherText = CipherText::Map(vec![
        ("first".into(), value()),
        ("second".into(), value()),
        ("third".into(), value()),
    ]);
    assert_eq!(
        map.read(LengthVisitor).unwrap(),
        3,
        "map should yield three entries"
    );
}

#[tokio::test]
async fn native_readers_preserve_map_keys_and_authenticated_markers() {
    use std::collections::HashMap;
    let (cipher, provider) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let value: HashMap<String, Vec<Option<String>>> = HashMap::from([
        ("entries".into(), vec![Some("secret".into()), None]),
        ("empty".into(), vec![]),
    ]);
    let tree = keyset
        .encrypt(value.clone(), nonempty!("document"))
        .await
        .unwrap();
    let stored = tree.read(TreeVisitor).unwrap();
    let opened: HashMap<String, Vec<Option<String>>> = cipher
        .decrypt(stored.native(), nonempty!("document"))
        .await
        .unwrap();
    assert_eq!(
        opened, value,
        "a tree read into a destination and back opens as the original value"
    );
    assert_eq!(
        provider.call_counts().0,
        1,
        "the whole document sealed under one data key"
    );
    assert_eq!(provider.call_counts().1, 1, "and opened with one retrieval");
    // Transcoding keeps the authentication: changing a cryptographic map key fails.
    let tree = keyset.encrypt(value, nonempty!("document")).await.unwrap();
    let Stored::Object(mut entries) = tree.read(TreeVisitor).unwrap() else {
        panic!("object")
    };
    entries[0].0 = "renamed".into();
    let opened: Result<HashMap<String, Vec<Option<String>>>, _> = cipher
        .decrypt(Stored::Object(entries).native(), nonempty!("document"))
        .await;
    assert!(
        opened.is_err(),
        "a map key is part of its entry's authenticated context: renaming it fails to open"
    );
    let tree = keyset
        .encrypt(HashMap::<String, String>::new(), nonempty!("document"))
        .await
        .unwrap();
    let Stored::EmptyObject(marker) = tree.read(TreeVisitor).unwrap() else {
        panic!("empty map marker")
    };
    // A marker is sealed data, not an unauthenticated empty container.
    let opened: Result<HashMap<String, String>, _> = cipher
        .decrypt(CipherText::EmptyMap(marker), nonempty!("wrong"))
        .await;
    assert!(
        opened.is_err(),
        "an empty-map marker is sealed under its context, not an unauthenticated empty container"
    );
    let stored = CipherText::Passthrough(Box::new(17u32) as stack_encrypt::BoxedPassthrough)
        .read(TreeVisitor)
        .unwrap();
    let Stored::Metadata(value) = stored else {
        panic!("metadata")
    };
    assert_eq!(
        *value.downcast::<u32>().unwrap(),
        17,
        "passthrough metadata reaches the destination as it was given"
    );
}
