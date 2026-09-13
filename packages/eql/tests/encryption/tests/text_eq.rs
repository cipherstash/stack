mod common;

use eql_bindings::v3::terms::{Ciphertext, Hmac256};
use eql_bindings::v3::text::{TextEq, TextEqQuery};
use eql_bindings::{Identifier, SchemaVersion};
use stack_encrypt::target::transcode::{Reader, Transcode, Visitor};
use stack_encrypt::{
    Cipher, CipherText, Encrypt, Error, IntoAad, NonEmpty, SealedValue, StackCipherText,
};

fn column() -> NonEmpty<Identifier> {
    Identifier::for_column("users", "email").unwrap()
}
struct NativeLeaf;
impl Visitor for NativeLeaf {
    type Value = StackCipherText;
    fn sealed(self, leaf: SealedValue) -> Result<Self::Value, Error> {
        Ok(CipherText::Single(leaf))
    }
}

#[tokio::test]
async fn text_round_trips_through_json_and_both_canonical_directions() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    for text in [
        "alice@example.com",
        "",
        "雪☃",
        "caf\u{e9}",
        "cafe\u{301}",
        "a\0b",
    ] {
        let value = text.to_owned();
        let stored: TextEq = keyset.encrypt_as(&value, column()).await.unwrap();
        let json = serde_json::to_value(&stored).unwrap();
        assert_eq!(json["v"], 3);
        assert_eq!(json["i"], serde_json::json!({"t":"users", "c":"email"}));
        assert_eq!(json.as_object().unwrap().len(), 4);
        let stored: TextEq = serde_json::from_value(json).unwrap();
        let native = stored.c.clone().read(NativeLeaf).unwrap();
        let opened: String = cipher.decrypt(native, column()).await.unwrap();
        assert_eq!(
            opened, value,
            "EQL adds no plaintext encoding or envelope-field AAD"
        );
        let opened: String = cipher.decrypt_as(stored, Default::default()).await.unwrap();
        assert_eq!(opened, value);

        let native = keyset.encrypt(value.clone(), column()).await.unwrap();
        let stored = TextEq {
            v: SchemaVersion::CURRENT,
            i: column().into_inner(),
            c: native.read(Ciphertext::visitor()).unwrap(),
            hm: keyset
                .equality_term(value.clone(), column())
                .await
                .unwrap()
                .read(Hmac256::visitor())
                .unwrap(),
        };
        let opened: String = cipher.decrypt_as(stored, column().into()).await.unwrap();
        assert_eq!(
            opened, value,
            "native ciphertext opens through the EQL target"
        );
    }
}

#[tokio::test]
async fn independent_queries_match_native_terms_without_requesting_data_keys() {
    let (writer, _) = common::cipher().await;
    let (reader, calls) = common::cipher().await;
    let value = "café".to_owned();
    let stored: TextEq = writer
        .default_keyset()
        .encrypt_as(&value, column())
        .await
        .unwrap();
    let query: TextEqQuery = reader
        .default_keyset()
        .encrypt_as(&value, column())
        .await
        .unwrap();
    assert_eq!(query.hm, stored.hm);
    let canonical = reader
        .default_keyset()
        .equality_term(value.clone(), column())
        .await
        .unwrap()
        .read(Hmac256::visitor())
        .unwrap();
    assert_eq!(query.hm, canonical);
    assert_eq!(query.hm.0.len(), 64);
    assert!(query.hm.0.bytes().all(|b| b.is_ascii_hexdigit()));
    let json = serde_json::to_value(&query).unwrap();
    assert!(json.get("c").is_none());
    assert_eq!(serde_json::from_value::<TextEqQuery>(json).unwrap(), query);
    for different in ["CAFÉ", "cafe\u{301}", "café "] {
        let probe: TextEqQuery = reader
            .default_keyset()
            .encrypt_as(&different.to_owned(), column())
            .await
            .unwrap();
        assert_ne!(query.hm, probe.hm, "no added normalization or case folding");
    }
    let calls = calls.lock().unwrap();
    assert!(calls.generate.is_empty());
    assert!(calls.retrieve.is_empty());
}

#[tokio::test]
async fn identifier_components_are_nonempty_and_keep_their_boundaries() {
    assert!(Identifier::for_column("", "email").is_err());
    assert!(Identifier::for_column("users", "").is_err());
    let (cipher, calls) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let value = "text".to_owned();
    let mut outputs = Vec::new();
    for (t, c) in [
        ("ab", "c"),
        ("a", "bc"),
        ("users", "email"),
        ("users", "name"),
        ("other", "email"),
    ] {
        let stored: TextEq = keyset
            .encrypt_as(&value, Identifier::for_column(t, c).unwrap())
            .await
            .unwrap();
        for previous in &outputs {
            assert_ne!(previous, &stored.hm);
        }
        outputs.push(stored.hm);
    }
    let calls = calls.lock().unwrap();
    let descriptors: std::collections::HashSet<_> = calls.generate.iter().flatten().collect();
    assert_eq!(
        descriptors.len(),
        5,
        "ZeroKMS descriptors also preserve identifier boundaries"
    );
}

#[tokio::test]
async fn context_and_encoding_failures_are_rejected_before_retrieving_keys() {
    let (cipher, calls) = common::cipher().await;
    let stored: TextEq = cipher
        .default_keyset()
        .encrypt_as(&"secret".to_owned(), column())
        .await
        .unwrap();
    let wrong = Identifier::for_column("users", "name").unwrap();
    assert!(cipher
        .decrypt_as::<String, _>(stored.clone(), wrong.clone().into())
        .await
        .is_err());
    for empty_table in [true, false] {
        let mut invalid = stored.clone();
        if empty_table {
            invalid.i.t.clear();
        } else {
            invalid.i.c.clear();
        }
        assert!(cipher
            .decrypt_as::<String, _>(invalid, Default::default())
            .await
            .is_err());
    }
    for encoded in [
        "legacy-ciphertext",
        "stack-encrypt:2:00000",
        "stack-encrypt:1:",
        "stack-encrypt:1:~",
        "stack-encrypt:1:00000",
        "stack-encrypt:1:AAAA",
        "stack-encrypt:1:雪",
    ] {
        let mut invalid = stored.clone();
        invalid.c = Ciphertext(encoded.into());
        assert!(cipher
            .decrypt_as::<String, _>(invalid, Default::default())
            .await
            .is_err());
    }
    assert!(calls.lock().unwrap().retrieve.is_empty());
    let mut moved = stored;
    moved.i = wrong.into_inner();
    assert!(
        cipher
            .decrypt_as::<String, _>(moved, Default::default())
            .await
            .is_err(),
        "a different nonempty stored identifier fails authentication"
    );
    assert_eq!(calls.lock().unwrap().retrieve.len(), 1);
}

#[tokio::test]
async fn a_column_batches_generation_and_retrieval_under_the_same_descriptors() {
    let (cipher, calls) = common::cipher().await;
    let values = vec!["one".to_owned(), "two".to_owned(), "three".to_owned()];
    let records: Vec<TextEq> = cipher
        .default_keyset()
        .encrypt_as(&values, column())
        .await
        .unwrap();
    let json = serde_json::to_string(&records).unwrap();
    let records: Vec<TextEq> = serde_json::from_str(&json).unwrap();
    let opened: Vec<String> = cipher.decrypt_as(records, column().into()).await.unwrap();
    assert_eq!(opened, values);
    let calls = calls.lock().unwrap();
    assert_eq!(calls.generate.len(), 1);
    assert_eq!(calls.retrieve.len(), 1);
    assert_eq!(calls.generate[0].len(), 3);
    assert_eq!(calls.generate, calls.retrieve);
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
async fn leaf_transcoding_requires_no_serde_and_refuses_container_shapes() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let leaf: Ciphertext = keyset
        .encrypt_as(&WithoutSerde("native".into()), column().into())
        .await
        .unwrap();
    let text: String = cipher.decrypt_as(leaf, column().into()).await.unwrap();
    assert_eq!(text, "native");
    assert!(keyset
        .encrypt_as::<_, Ciphertext>(&vec!["one".to_owned()], column().into())
        .await
        .is_err());
}

/// Needs an EQL v3 installation; uses fresh real ciphertext with a fake key source.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v3 database"]
fn postgres_stores_queries_indexes_and_returns_decryptable_text() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = runtime.block_on(common::cipher());
    let keyset = cipher.default_keyset();
    let mut db = postgres::Client::connect(
        &std::env::var("EQL_TEST_DATABASE_URL").expect("EQL_TEST_DATABASE_URL"),
        postgres::NoTls,
    )
    .unwrap();
    db.batch_execute(
        "CREATE TEMP TABLE text_eq_roundtrip (id int PRIMARY KEY, email public.eql_v3_text_eq);
        CREATE INDEX text_eq_email_idx ON text_eq_roundtrip (eql_v3.eq_term(email));",
    )
    .unwrap();
    for (id, value) in [
        (1, "alice@example.com"),
        (2, "bob@example.com"),
        (3, "alice@example.com"),
        (4, "ALICE@example.com"),
    ] {
        let record: TextEq = runtime
            .block_on(async { keyset.encrypt_as(&value.to_owned(), column()).await })
            .unwrap();
        let json = serde_json::to_string(&record).unwrap();
        db.execute(
            "INSERT INTO text_eq_roundtrip VALUES ($1, $2::text::jsonb::public.eql_v3_text_eq)",
            &[&id, &json],
        )
        .unwrap();
    }
    let (query_cipher, _) = runtime.block_on(common::cipher());
    let query: TextEqQuery = runtime
        .block_on(async {
            query_cipher
                .default_keyset()
                .encrypt_as(&"alice@example.com".to_owned(), column())
                .await
        })
        .unwrap();
    let json = serde_json::to_string(&query).unwrap();
    let rows = db.query("SELECT id, email::text FROM text_eq_roundtrip WHERE email = $1::text::jsonb::eql_v3.query_text_eq ORDER BY id", &[&json]).unwrap();
    assert_eq!(
        rows.iter().map(|r| r.get::<_, i32>(0)).collect::<Vec<_>>(),
        [1, 3]
    );
    for row in rows {
        let record: TextEq = serde_json::from_str(row.get::<_, &str>(1)).unwrap();
        let value: String = runtime
            .block_on(async { cipher.decrypt_as(record, column().into()).await })
            .unwrap();
        assert_eq!(value, "alice@example.com");
    }
    let different = db.query("SELECT id FROM text_eq_roundtrip WHERE email <> $1::text::jsonb::eql_v3.query_text_eq ORDER BY id", &[&json]).unwrap();
    assert_eq!(
        different
            .iter()
            .map(|r| r.get::<_, i32>(0))
            .collect::<Vec<_>>(),
        [2, 4]
    );
    db.batch_execute("SET enable_seqscan = off").unwrap();
    let plan = db.query("EXPLAIN SELECT * FROM text_eq_roundtrip WHERE email = $1::text::jsonb::eql_v3.query_text_eq", &[&json]).unwrap();
    assert!(
        plan.iter()
            .any(|r| r.get::<_, &str>(0).contains("text_eq_email_idx")),
        "equality can use the extractor index"
    );
}
