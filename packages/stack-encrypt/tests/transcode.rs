//! A consumer outside the crate: typed EQL-shaped records, native readers, and
//! cross-opening through the canonical cipher path. No plaintext Serde fallback.
mod common;
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::transcode::{MapReader, Reader, SequenceReader, Transcode, Visitor};
use stack_encrypt::target::{self, CallerContext, ExpectedContext};
use stack_encrypt::{
    nonempty, Aad, AadPiece, Cipher, CipherText, DecryptField, DecryptInto, Decryptable,
    Decryption, Encrypt, EncryptFrom, Encryption, Error, IntoAad, IntoPrfContext, MaybeEmpty,
    NonEmpty, PrfContext, SealedValue, StackCipherText,
};
use std::sync::atomic::Ordering;

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
impl<'a> IntoAad<'a> for Identifier {
    fn into_aad(self) -> Aad<'a> {
        (self.table, self.column).into_aad()
    }
    fn into_aad_piece(self) -> AadPiece<'a> {
        (self.table, self.column).into_aad_piece()
    }
}
impl<'a> IntoPrfContext<'a> for Identifier {
    fn into_prf_context(self) -> PrfContext<'a> {
        (self.table, self.column).into_prf_context()
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
    fn encryption<'s, K: 'static>(context: Self::Context) -> Encryption<'s, S, Self, K>
    where
        S: 's,
    {
        target::ciphertext(context).transcode()
    }
}
impl<P: stack_encrypt::Decrypt<'static> + 'static> DecryptInto<P> for StoredLeaf {
    type Context = CallerContext;
    fn decryption<K: 'static>(self, context: Self::Context) -> Decryption<P, K> {
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
    fn decryption_field<K: 'static>(self, ctx: Ctx) -> Option<Decryption<P, K>> {
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

#[tokio::test]
async fn stored_identifier_supplies_all_operations_and_checks_before_retrieval() {
    let (cipher, generates, retrieves) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let email = "alice@example.com".to_owned();
    let record: TextEq = keyset
        .encrypt_as(&email, Identifier::email())
        .await
        .unwrap();
    assert_eq!(record.i, Identifier::email().into_inner());
    assert_eq!(record.v, 3);
    assert_eq!(generates.load(Ordering::SeqCst), 1);
    let probe = keyset
        .equality_term(email.clone(), Identifier::email())
        .await
        .unwrap();
    assert_eq!(record.hm, probe);
    // Storage envelope names c/hm add no extra AAD; the canonical path opens it.
    let opened: String = cipher
        .decrypt(
            CipherText::Single(SealedValue::from_bytes(&record.c.0).unwrap()),
            Identifier::email(),
        )
        .await
        .unwrap();
    assert_eq!(opened, email);

    // The reverse direction starts with canonical ciphertext.
    let canonical = keyset
        .encrypt(email.clone(), Identifier::email())
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
    assert_eq!(opened, email);
    let before = retrieves.load(Ordering::SeqCst);
    let record: TextEq = keyset
        .encrypt_as(&email, Identifier::email())
        .await
        .unwrap();
    let wrong = NonEmpty::new(Identifier {
        table: "users".into(),
        column: "other".into(),
    })
    .unwrap();
    assert!(cipher
        .decrypt_as::<String, _>(record, wrong.into())
        .await
        .is_err());
    assert_eq!(retrieves.load(Ordering::SeqCst), before);
    let mut record: TextEq = keyset
        .encrypt_as(&email, Identifier::email())
        .await
        .unwrap();
    record.i.column.clear();
    assert!(cipher
        .decrypt_as::<String, _>(record, Default::default())
        .await
        .is_err());
    assert_eq!(retrieves.load(Ordering::SeqCst), before);
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
    assert_eq!(opened, "native");
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
    assert_eq!(opened, text);
    // A scalar destination must refuse a sequence rather than flatten or serialize it.
    let result = keyset
        .encrypt_as::<_, StoredLeaf>(&vec![1u32, 2], nonempty!("value").into())
        .await;
    assert!(result.is_err());
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
#[tokio::test]
async fn native_readers_preserve_map_keys_and_authenticated_markers() {
    use std::collections::HashMap;
    let (cipher, generates, retrieves) = common::counting_cipher().await;
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
    assert_eq!(opened, value);
    assert_eq!(generates.load(Ordering::SeqCst), 1);
    assert_eq!(retrieves.load(Ordering::SeqCst), 1);
    // Transcoding keeps the authentication: changing a cryptographic map key fails.
    let tree = keyset.encrypt(value, nonempty!("document")).await.unwrap();
    let Stored::Object(mut entries) = tree.read(TreeVisitor).unwrap() else {
        panic!("object")
    };
    entries[0].0 = "renamed".into();
    let opened: Result<HashMap<String, Vec<Option<String>>>, _> = cipher
        .decrypt(Stored::Object(entries).native(), nonempty!("document"))
        .await;
    assert!(opened.is_err());
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
    assert!(opened.is_err());
    let stored = CipherText::Passthrough(Box::new(17u32) as stack_encrypt::BoxedPassthrough)
        .read(TreeVisitor)
        .unwrap();
    let Stored::Metadata(value) = stored else {
        panic!("metadata")
    };
    assert_eq!(*value.downcast::<u32>().unwrap(), 17);
}
