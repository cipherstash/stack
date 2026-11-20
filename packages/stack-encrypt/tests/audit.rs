//! Audit metadata reaches ZeroKMS as the key requests' unverified context:
//! on encrypt and decrypt, through every public way to make a call, on
//! every request a call makes, and not at all when the caller gives none.
//!
//! Every test runs against a fake key source that records the context each
//! request carried, so none needs the network.

use std::borrow::Cow;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use stack_encrypt::kms::{
    DataKey, DataKeySource, DataKeyWithTag, FakeDataKeySource, GenerateKeyPayload, IdentifiedBy,
    IndexKey, IndexKeySource, RetrieveKeyPayload, UnverifiedContext,
};
use stack_encrypt::plan::{Field, Fields};
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::legacy::{DecryptFrom, EncryptInto};
use stack_encrypt::{
    all, nonempty, AuditMetadata, Ciphertext, Decrypt, DecryptInto, EncryptFrom, Equality, Error,
    Pending, Plan, StackCipher, StackCipherText,
};
use uuid::Uuid;

/// Which key call a request was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Call {
    Generate,
    Retrieve,
}

/// One key request as the key source received it: the call, and the audit
/// metadata it carried as JSON (`None` when it carried none).
type Sent = (Call, Option<Value>);

/// A fake key source that records the audit metadata of every key request.
#[derive(Clone)]
struct RecordingSource {
    inner: Arc<FakeDataKeySource>,
    sent: Arc<Mutex<Vec<Sent>>>,
}

impl RecordingSource {
    fn new() -> Self {
        Self {
            inner: Arc::new(FakeDataKeySource::new()),
            sent: Arc::default(),
        }
    }

    fn record(&self, call: Call, unverified: Option<&UnverifiedContext>) {
        let metadata = unverified.map(|unverified| serde_json::to_value(unverified).unwrap());
        self.sent.lock().unwrap().push((call, metadata));
    }

    /// The requests made so far, cleared.
    fn take(&self) -> Vec<Sent> {
        std::mem::take(&mut *self.sent.lock().unwrap())
    }
}

impl DataKeySource for RecordingSource {
    async fn generate_keys(
        &self,
        payloads: Vec<GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'_, UnverifiedContext>>,
    ) -> Result<Vec<DataKeyWithTag>, stack_encrypt::kms::Error> {
        self.record(Call::Generate, unverified_context.as_deref());
        self.inner
            .generate_keys(payloads, keyset_id, unverified_context)
            .await
    }

    async fn retrieve_keys(
        &self,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<&UnverifiedContext>,
    ) -> Result<Vec<DataKey>, stack_encrypt::kms::Error> {
        self.record(Call::Retrieve, unverified_context);
        self.inner
            .retrieve_keys(payloads, keyset_id, unverified_context)
            .await
    }
}

impl IndexKeySource for RecordingSource {
    async fn load_index_key(
        &self,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<(Uuid, IndexKey), stack_encrypt::kms::Error> {
        self.inner.load_index_key(keyset_id).await
    }
}

async fn cipher() -> (StackCipher<RecordingSource>, RecordingSource) {
    let source = RecordingSource::new();
    let cipher = StackCipher::builder()
        .kms(source.clone())
        .init()
        .await
        .expect("build cipher");
    (cipher, source)
}

fn list_issues() -> AuditMetadata {
    AuditMetadata::new()
        .with("purpose", "list issues")
        .with("request_id", "req_01J9Z3")
}

fn list_issues_json() -> Value {
    json!({ "purpose": "list issues", "request_id": "req_01J9Z3" })
}

#[tokio::test]
async fn a_scalar_encrypt_and_decrypt_send_their_metadata() {
    let (cipher, source) = cipher().await;
    let keyset = cipher.default_keyset();

    let stored: Ciphertext = keyset
        .encrypt(String::from("sk_live_1234"))
        .audit(AuditMetadata::new().with("purpose", "store api key"))
        .await
        .unwrap();
    assert_eq!(
        source.take(),
        vec![(Call::Generate, Some(json!({ "purpose": "store api key" })))]
    );

    let back: String = keyset.decrypt(stored).audit(list_issues()).await.unwrap();
    assert_eq!(back, "sk_live_1234");
    assert_eq!(
        source.take(),
        vec![(Call::Retrieve, Some(list_issues_json()))]
    );
}

/// With no metadata the key source receives `None`, as it did before audit
/// metadata existed, and empty metadata is the same as none.
#[tokio::test]
async fn no_metadata_sends_none() {
    let (cipher, source) = cipher().await;
    let keyset = cipher.default_keyset();

    let stored: Ciphertext = keyset.encrypt(7i64).await.unwrap();
    let back: i64 = keyset
        .decrypt(stored)
        .audit(AuditMetadata::new())
        .await
        .unwrap();
    assert_eq!(back, 7);
    assert_eq!(
        source.take(),
        vec![(Call::Generate, None), (Call::Retrieve, None)]
    );
}

/// The metadata is not bound into anything, so a decrypt may send other
/// metadata than the encrypt did, or none.
#[tokio::test]
async fn decrypt_metadata_need_not_match_encrypt_metadata() {
    let (cipher, source) = cipher().await;
    let keyset = cipher.default_keyset();

    let stored: Ciphertext = keyset
        .encrypt_with_context(42i64, "users/age")
        .audit(AuditMetadata::new().with("purpose", "signup"))
        .await
        .unwrap();
    let back: i64 = keyset
        .decrypt_with_context(stored.clone(), "users/age")
        .audit(AuditMetadata::new().with("purpose", "profile page"))
        .await
        .unwrap();
    assert_eq!(back, 42);
    let back: i64 = keyset
        .decrypt_with_context(stored, "users/age")
        .await
        .unwrap();
    assert_eq!(back, 42);
    assert_eq!(
        source.take(),
        vec![
            (Call::Generate, Some(json!({ "purpose": "signup" }))),
            (Call::Retrieve, Some(json!({ "purpose": "profile page" }))),
            (Call::Retrieve, None),
        ]
    );
}

/// A batch is one key request, and metadata attached to the merged call
/// goes on it once.
#[tokio::test]
async fn a_batch_sends_its_metadata_on_its_one_request() {
    let (cipher, source) = cipher().await;
    let keyset = cipher.default_keyset();

    let stored = Pending::all(
        &keyset,
        vec![
            keyset.encrypt(1i64),
            keyset.encrypt(2i64),
            keyset.encrypt(3i64),
        ],
    )
    .audit(list_issues())
    .await
    .unwrap();
    assert_eq!(
        source.take(),
        vec![(Call::Generate, Some(list_issues_json()))]
    );

    let opened: Vec<i64> = Pending::all(
        &keyset,
        stored
            .into_iter()
            .map(|ciphertext| keyset.decrypt(ciphertext))
            .collect(),
    )
    .audit(list_issues())
    .await
    .unwrap();
    assert_eq!(opened, vec![1, 2, 3]);
    assert_eq!(
        source.take(),
        vec![(Call::Retrieve, Some(list_issues_json()))]
    );
}

/// Calls are merged first, and the merged call takes the metadata: its one
/// request carries the one map.
#[tokio::test]
async fn a_zipped_call_sends_its_metadata_on_its_one_request() {
    let (cipher, source) = cipher().await;
    let keyset = cipher.default_keyset();

    let _: (Ciphertext, Ciphertext) = keyset
        .encrypt(1i64)
        .zip(keyset.encrypt(2i64))
        .audit(list_issues())
        .await
        .unwrap();
    assert_eq!(
        source.take(),
        vec![(Call::Generate, Some(list_issues_json()))]
    );
}

/// A pending that already failed gives its error when its audited form is
/// awaited, and makes no request.
#[tokio::test]
async fn an_audited_call_that_failed_gives_its_error() {
    let (cipher, source) = cipher().await;
    let failed: Pending<'_, i64, _> = Pending::failed(&cipher, Error::NoKeyset);
    let result = failed.audit(list_issues()).await;
    assert!(matches!(result, Err(Error::NoKeyset)));
    assert_eq!(source.take(), vec![]);
}

/// Audit metadata goes with data-key requests. A call that makes none sends
/// nothing and still succeeds. The test covers a query term, a record of
/// passthrough fields only, an absent value, and an empty list. The last
/// two depend on the data, so an error there would fail a program on an
/// empty page of rows.
#[tokio::test]
async fn an_audited_call_that_requests_no_data_key_succeeds_and_sends_nothing() {
    let (cipher, source) = cipher().await;
    let keyset = cipher.default_keyset();
    let email = String::from("bob@example.com");

    // A query term is derived from the keyset's index key.
    let audited = keyset
        .equality_term(email.clone(), nonempty!("users/email"))
        .audit(list_issues())
        .await
        .unwrap();
    let plain = keyset
        .equality_term(email.clone(), nonempty!("users/email"))
        .await
        .unwrap();
    assert_eq!(audited, plain);

    // A record whose only field is stored in the clear.
    let account = Account { email };
    let _ = cipher
        .encrypt(&account)
        .context("accounts")
        .fields()
        .passthrough::<String>("email")
        .audit(list_issues())
        .await
        .unwrap();

    // An absent value, and an empty list.
    let absent: Option<EncryptedEmail> = None::<String>
        .encrypt_into_with_context(&keyset, nonempty!("users/email"))
        .audit(list_issues())
        .await
        .unwrap();
    assert!(absent.is_none());
    let empty: Vec<EncryptedEmail> = Vec::<String>::new()
        .encrypt_into_with_context(&keyset, nonempty!("users/email"))
        .audit(list_issues())
        .await
        .unwrap();
    assert!(empty.is_empty());
    let opened: Vec<String> = empty
        .decrypt_into(&cipher, nonempty!("users/email"))
        .audit(list_issues())
        .await
        .unwrap();
    assert!(opened.is_empty());

    assert_eq!(source.take(), vec![]);
}

/// The tree entry points return a `Pending` too, so they take metadata.
/// Opening leaves from two keysets is one retrieve call per keyset, and
/// each carries the metadata.
#[tokio::test]
async fn trees_send_their_metadata_on_every_request() {
    let (cipher, source) = cipher().await;
    let first = cipher.default_keyset();
    let second = cipher
        .keyset(IdentifiedBy::Name("tenant-b".to_string().into()))
        .await
        .unwrap();

    let a = first
        .encrypt_tree(String::from("alice"), "users/name")
        .audit(list_issues())
        .await
        .unwrap();
    let b = second
        .encrypt_tree(String::from("bob"), "users/name")
        .await
        .unwrap();
    assert_eq!(
        source.take(),
        vec![
            (Call::Generate, Some(list_issues_json())),
            (Call::Generate, None),
        ]
    );

    let name: String = first
        .decrypt_tree(a, "users/name")
        .audit(list_issues())
        .await
        .unwrap();
    assert_eq!(name, "alice");
    assert_eq!(
        source.take(),
        vec![(Call::Retrieve, Some(list_issues_json()))]
    );

    let a = first
        .encrypt_tree(String::from("alice"), "users/name")
        .await
        .unwrap();
    let _ = source.take();

    let both: (String, String) = cipher
        .decrypt(a, "users/name")
        .zip(cipher.decrypt(b, "users/name"))
        .audit(list_issues())
        .await
        .unwrap();
    assert_eq!(both, ("alice".into(), "bob".into()));
    assert_eq!(
        source.take(),
        vec![
            (Call::Retrieve, Some(list_issues_json())),
            (Call::Retrieve, Some(list_issues_json())),
        ]
    );
}

/// Open one tree through the keyset, and another through the client, into
/// any target. `T` has no `Send` bound here, so this compiles only while
/// the tree decrypts ask for none.
async fn open_trees<T: Decrypt>(
    cipher: &StackCipher<RecordingSource>,
    first: StackCipherText,
    second: StackCipherText,
) -> (T, T) {
    let keyset = cipher.default_keyset();
    (
        keyset.decrypt_tree(first, "users/name").await.unwrap(),
        cipher.decrypt(second, "users/name").await.unwrap(),
    )
}

/// The tree decrypts were `async fn`s whose target did not have to be
/// `Send`. Returning a `Pending` did not add that requirement.
#[tokio::test]
async fn a_tree_decrypt_takes_a_target_that_need_not_be_send() {
    let (cipher, _source) = cipher().await;
    let keyset = cipher.default_keyset();
    let seal = |name: &str| keyset.encrypt_tree(name.to_owned(), "users/name");
    let (first, second) = (seal("alice").await.unwrap(), seal("bob").await.unwrap());

    let (alice, bob): (String, String) = open_trees(&cipher, first, second).await;
    assert_eq!((alice.as_str(), bob.as_str()), ("alice", "bob"));
}

#[tokio::test]
async fn plan_chains_send_their_metadata() {
    let (cipher, source) = cipher().await;
    let email_plan = Plan::context("users/email").with(Equality).build().unwrap();
    let email = String::from("bob@example.com");

    let written = cipher
        .encrypt(&email)
        .using(&email_plan)
        .audit(list_issues())
        .await
        .unwrap();
    assert_eq!(
        source.take(),
        vec![(Call::Generate, Some(list_issues_json()))]
    );

    let back: String = cipher
        .open(written)
        .using(&email_plan)
        .audit(AuditMetadata::new().with("purpose", "send receipt"))
        .await
        .unwrap();
    assert_eq!(back, email);
    assert_eq!(
        source.take(),
        vec![(Call::Retrieve, Some(json!({ "purpose": "send receipt" })))]
    );
}

/// `all` makes one request for its chains, and metadata on the batch goes
/// on it.
#[tokio::test]
async fn a_batch_of_chains_sends_its_metadata() {
    let (cipher, source) = cipher().await;
    let email_plan = Plan::context("users/email").with(Equality).build().unwrap();
    let (alice, bob) = (
        String::from("alice@example.com"),
        String::from("bob@example.com"),
    );

    let _ = all((
        cipher.encrypt(&alice).using(&email_plan),
        cipher.encrypt(&bob).using(&email_plan),
    ))
    .audit(list_issues())
    .await
    .unwrap();
    assert_eq!(
        source.take(),
        vec![(Call::Generate, Some(list_issues_json()))]
    );

    // With none on the batch, its request carries none.
    let _ = all((
        cipher.encrypt(&alice).using(&email_plan),
        cipher.encrypt(&bob).using(&email_plan),
    ))
    .await
    .unwrap();
    assert_eq!(source.take(), vec![(Call::Generate, None)]);
}

/// A record with one encrypted field, for the `.fields()` chain.
struct Account {
    email: String,
}
impl Fields for Account {
    fn field_names(&self) -> Vec<&str> {
        vec!["email"]
    }
}
impl Field<String> for Account {
    fn field(&self, name: &str) -> Option<&String> {
        (name == "email").then_some(&self.email)
    }
}

/// Every encrypt chain that can be awaited takes `.audit(..)`: a context
/// alone, a context with indexes, and fields.
#[tokio::test]
async fn every_encrypt_chain_sends_its_metadata() {
    let (cipher, source) = cipher().await;
    let email = String::from("bob@example.com");

    let _ = cipher
        .encrypt(&email)
        .context("users/email")
        .audit(list_issues())
        .await
        .unwrap();
    let _ = cipher
        .encrypt(&email)
        .context("users/email")
        .with(Equality)
        .audit(list_issues())
        .await
        .unwrap();
    let account = Account {
        email: email.clone(),
    };
    let _ = cipher
        .encrypt(&account)
        .context("accounts")
        .fields()
        .encrypt::<String>("email")
        .audit(list_issues())
        .await
        .unwrap();
    assert_eq!(
        source.take(),
        vec![(Call::Generate, Some(list_issues_json())); 3]
    );
}

/// `all(..)` settles chains that open leaves from any keyset in a request
/// of their own, beside the batch. Both requests carry the batch's one map.
#[tokio::test]
async fn a_batch_of_encrypt_and_open_chains_sends_one_map_on_every_request() {
    let (cipher, source) = cipher().await;
    let email_plan = Plan::context("users/email").with(Equality).build().unwrap();
    let (alice, bob) = (
        String::from("alice@example.com"),
        String::from("bob@example.com"),
    );
    let stored = cipher.encrypt(&alice).using(&email_plan).await.unwrap();
    let _ = source.take();

    let (_, opened): (_, String) = all((
        cipher.encrypt(&bob).using(&email_plan),
        cipher.open(stored).using(&email_plan),
    ))
    .audit(list_issues())
    .await
    .unwrap();
    assert_eq!(opened, alice);
    assert_eq!(
        source.take(),
        vec![
            (Call::Generate, Some(list_issues_json())),
            (Call::Retrieve, Some(list_issues_json())),
        ]
    );
}

/// A batch that fails its check gives that error when its audited form is
/// awaited, and makes no request.
#[tokio::test]
async fn an_audited_batch_that_fails_its_check_makes_no_request() {
    let (cipher, source) = cipher().await;
    let email_plan = Plan::context("users/email").with(Equality).build().unwrap();
    let email = String::from("bob@example.com");

    let refused = all((
        cipher.encrypt(&email).using(&email_plan),
        cipher.encrypt(&email).context("not a label//"),
    ))
    .audit(list_issues())
    .await;
    assert!(matches!(refused, Err(Error::Plan(_))));
    assert_eq!(source.take(), vec![]);
}

/// A chain that names a keyset still sends its metadata: the keyset is
/// loaded, then the one request carries the map.
#[tokio::test]
async fn a_chain_that_names_a_keyset_sends_its_metadata() {
    let (cipher, source) = cipher().await;
    let email_plan = Plan::context("users/email").with(Equality).build().unwrap();
    let email = String::from("bob@example.com");

    let _ = cipher
        .encrypt(&email)
        .using(&email_plan)
        .keyset("tenant-b")
        .audit(list_issues())
        .await
        .unwrap();
    assert_eq!(
        source.take(),
        vec![(Call::Generate, Some(list_issues_json()))]
    );
}

/// A derived record's fields settle as one `Pending`, which takes the
/// metadata like any other.
#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = String)]
struct EncryptedEmail {
    c: StackCipherText,
    hm: EqualityTerm,
}

#[tokio::test]
async fn a_derived_record_sends_its_metadata() {
    let (cipher, source) = cipher().await;
    let keyset = cipher.default_keyset();

    let record: EncryptedEmail = String::from("bob@example.com")
        .encrypt_into_with_context(&keyset, nonempty!("users/email"))
        .audit(list_issues())
        .await
        .unwrap();
    let email: String = record
        .decrypt_into(&cipher, nonempty!("users/email"))
        .audit(list_issues())
        .await
        .unwrap();
    assert_eq!(email, "bob@example.com");
    assert_eq!(
        source.take(),
        vec![
            (Call::Generate, Some(list_issues_json())),
            (Call::Retrieve, Some(list_issues_json())),
        ]
    );
}

/// The dynamic path: the plan and the record arrive as data, as a language
/// binding sends them.
#[cfg(feature = "dynamic")]
mod dynamic_path {
    use serde_json::json;
    use stack_encrypt::dynamic::{record, ValueFrame};
    use stack_encrypt::AsProtectedRef as _;

    use super::{cipher, list_issues, list_issues_json, Call};

    #[tokio::test]
    async fn a_dynamic_record_sends_its_metadata() {
        let (cipher, source) = cipher().await;
        let plan = vitaminc_aead_frame::serde::to_vec(&json!({
            "email": { "context": ["users", "email"], "outputs": ["c", "eq"], "type": "string" },
            "notes": { "context": ["users", "notes"], "outputs": ["c"], "type": "string" },
        }))
        .expect("the plan is a frame");
        let plan = record::plan(plan.as_protected_ref()).expect("the plan parses");
        let user = vitaminc_aead_frame::serde::to_vec(&json!({
            "email": "bob@example.com",
            "notes": "likes cats",
        }))
        .expect("the record is a frame");
        let user = ValueFrame::from_bytes(user.as_protected_ref()).expect("the record is a value");

        let sealed = record::encrypt(&cipher.default_keyset(), user, &plan)
            .expect("the record fits the plan")
            .audit(list_issues())
            .await
            .expect("the record seals");
        assert_eq!(
            source.take(),
            vec![(Call::Generate, Some(list_issues_json()))]
        );

        record::decrypt(&cipher, sealed, &plan, None)
            .expect("the record fits the plan")
            .audit(list_issues())
            .await
            .expect("the record opens");
        assert_eq!(
            source.take(),
            vec![(Call::Retrieve, Some(list_issues_json()))]
        );
    }
}
