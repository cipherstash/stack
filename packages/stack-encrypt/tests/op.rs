//! Operator-typed queries (`stack_encrypt::op`, ADR-0009): a query names an
//! operator through the field reference of a record field, the field's target type
//! names the index that answers it, and the term that comes back is the
//! query term for that operator, which for a match index is not the stored
//! term.
//!
//! The records at the top of the file give the fields the tests query: a
//! field's type says which indexes it stores, and so which operators its
//! field reference has. `tests/field_references.rs` states what a field reference is and how it takes
//! its scope; this file states what each operator sends, what it refuses,
//! and how a probabilistic term is verified and sized.
mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use common::{stack_cipher, CountingSource};
use stack_encrypt::field_reference::Root;
use stack_encrypt::kms::IdentifiedBy;
use stack_encrypt::op::{self, Limit, Probabilistic, Stats};
use stack_encrypt::sem::{
    EqualityTerm, MatchConfig, MatchOptions, MatchQuery, MatchTerms, OpeTerm, OreTerm, RangeQuery,
    TermError, Tokenizer,
};
use stack_encrypt::target::{
    CallerContext, DecryptSource, EncryptTarget, Encryption, Index, IndexSpec, NoScope, Scope,
    SourceMode,
};
use stack_encrypt::{
    nonempty, DecryptFrom, EncryptInto, Encrypted, Equality, Error, FieldReference, Label,
    StackCipher,
};
use zeroize::Zeroize;

/// A match configuration that keeps case: its index cuts stored text and
/// queries as written, so `Nguyen` and `nguyen` are different tokens.
struct Exact;
impl MatchConfig for Exact {
    fn options() -> MatchOptions {
        MatchOptions {
            downcase: false,
            ..Default::default()
        }
    }
}

/// A match configuration the index cannot use: an n-gram length of zero.
struct ZeroGram;
impl MatchConfig for ZeroGram {
    fn options() -> MatchOptions {
        MatchOptions {
            tokenizer: Tokenizer::Ngram { length: 0 },
            ..Default::default()
        }
    }
}

/// A match configuration with the smallest filter allowed, so a long value
/// sets nearly every bit and false positives are easy to find.
struct Tiny;
impl MatchConfig for Tiny {
    fn options() -> MatchOptions {
        MatchOptions {
            m: 32,
            ..Default::default()
        }
    }
}

/// Whole words, as the v1 match indexer's standard tokenizer splits them.
struct Words;
impl MatchConfig for Words {
    fn options() -> MatchOptions {
        MatchOptions {
            tokenizer: stack_encrypt::sem::Tokenizer::Standard,
            ..Default::default()
        }
    }
}

/// EQL v4's filter size and slices (`k = 6`, `m = 2048`; its match types
/// also turn on short words, which this prior's arithmetic does not need),
/// with a notes column's prior.
struct Notes;
impl MatchConfig for Notes {
    fn options() -> MatchOptions {
        MatchOptions {
            k: 6,
            m: 2048,
            ..Default::default()
        }
    }
    fn expected_tokens() -> Option<u32> {
        Some(200)
    }
}

#[derive(Clone, Zeroize)]
struct Person {
    email: String,
    name: String,
}

fn person() -> Person {
    Person {
        email: "bob@example.com".into(),
        name: "Alice Nguyen".into(),
    }
}

/// A person: the email under the equality index and the default match
/// index, the name under a match index that keeps case.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Person, scope = "people")]
struct EncryptedPerson {
    email: Encrypted<(EqualityTerm, MatchTerms)>,
    name: Encrypted<MatchTerms<Exact>>,
}

/// The same person under the same labels, in a record whose caller
/// supplies a tenant scope on every call.
#[derive(EncryptTarget)]
#[stash(struct = Person, scope = "people", scope(tenant: u64))]
#[allow(dead_code)]
struct TenantPerson {
    email: Encrypted<(EqualityTerm, MatchTerms)>,
    name: Encrypted<MatchTerms<Exact>>,
}

#[derive(Clone, Zeroize)]
struct Contact {
    email: String,
    bio: String,
    phone: String,
}

fn contact() -> Contact {
    Contact {
        email: "bob@example.com".into(),
        bio: "bob builds bridges".into(),
        phone: "555 0100".into(),
    }
}

/// A record whose fields are each one term: two terms alone, with no
/// ciphertext, and one beside its ciphertext.
#[derive(EncryptTarget)]
#[stash(struct = Contact, scope = "contacts")]
struct EncryptedContact {
    email: EqualityTerm,
    bio: MatchTerms,
    phone: Encrypted<EqualityTerm>,
}

#[derive(Clone, Zeroize)]
struct Note {
    body: String,
}

fn note(body: &str) -> Note {
    Note { body: body.into() }
}

/// A note under a 32-bit filter.
#[derive(EncryptTarget)]
#[stash(struct = Note, scope = "notes")]
struct TinyNote {
    body: Encrypted<MatchTerms<Tiny>>,
}

/// A note cut into whole words.
#[derive(EncryptTarget)]
#[stash(struct = Note, scope = "notes")]
struct WordNote {
    body: Encrypted<MatchTerms<Words>>,
}

/// A note whose index declares a prior.
#[derive(EncryptTarget)]
#[stash(struct = Note, scope = "notes")]
#[allow(dead_code)]
struct PriorNote {
    body: Encrypted<MatchTerms<Notes>>,
}

/// A note under options the match index cannot use.
#[derive(EncryptTarget)]
#[stash(struct = Note, scope = "notes")]
#[allow(dead_code)]
struct ZeroGramNote {
    body: Encrypted<MatchTerms<ZeroGram>>,
}

#[derive(Clone, Zeroize)]
struct Profile {
    age: u32,
    surname: String,
    score: f64,
}

fn profile(age: u32) -> Profile {
    Profile {
        age,
        surname: "Nguyen".into(),
        score: 1.5,
    }
}

/// A profile whose order index is ORE: an integer beside an equality
/// term, text and a float.
#[derive(EncryptTarget)]
#[stash(struct = Profile, scope = "profiles")]
#[allow(dead_code)]
struct OreProfile {
    age: Encrypted<(EqualityTerm, OreTerm<u32>)>,
    surname: Encrypted<OreTerm<String>>,
    score: Encrypted<OreTerm<f64>>,
}

/// The same profile under the same labels, whose order index is OPE.
#[derive(EncryptTarget)]
#[stash(struct = Profile, scope = "profiles")]
#[allow(dead_code)]
struct OpeProfile {
    age: Encrypted<(EqualityTerm, OpeTerm<u32>)>,
    surname: Encrypted<OpeTerm<String>>,
    score: Encrypted<OpeTerm<f64>>,
}

#[derive(Clone, Zeroize)]
struct Member {
    age: u32,
    balance: i64,
}

/// A member whose fields are each one order term: an OPE term beside its
/// ciphertext, and an ORE term alone, of a signed integer.
#[derive(EncryptTarget)]
#[stash(struct = Member, scope = "members")]
struct EncryptedMember {
    age: Encrypted<OpeTerm<u32>>,
    balance: OreTerm<i64>,
}

/// The requests a cipher has sent its key source.
struct KeyRequests {
    loads: Arc<AtomicUsize>,
    generates: Arc<AtomicUsize>,
    retrieves: Arc<AtomicUsize>,
}

impl KeyRequests {
    /// Keyset loads, data keys generated and data keys retrieved.
    fn total(&self) -> usize {
        [&self.loads, &self.generates, &self.retrieves]
            .into_iter()
            .map(|count| count.load(Ordering::SeqCst))
            .sum()
    }
}

/// A cipher that counts the requests it sends its key source. The count
/// starts after the cipher has loaded its default keyset.
async fn counted_cipher() -> (StackCipher<CountingSource>, KeyRequests) {
    let source = CountingSource::new();
    let loads = source.loads();
    let (generates, retrieves) = source.counters();
    let cipher = StackCipher::builder()
        .kms(source)
        .init()
        .await
        .expect("build cipher");
    loads.store(0, Ordering::SeqCst);
    let requests = KeyRequests {
        loads,
        generates,
        retrieves,
    };
    (cipher, requests)
}

/// A field reference written by hand for the label `scope/identity`, of the target
/// type `T` and the scope type `C`. No record declares it, so it states
/// nothing about a stored value: the tests that use it are about what the
/// index of `T` is told of the query's context.
fn field_reference_of<T, C>(
    scope: &'static str,
    identity: &'static str,
) -> FieldReference<Root<()>, T, C> {
    FieldReference::new(identity, scope, identity, || {
        unreachable!("a query does not read its record's contexts")
    })
}

#[tokio::test]
async fn an_eq_query_is_the_stored_equality_term() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let row: EncryptedPerson = person().encrypt_into(&keyset).await.unwrap();

    let query: EqualityTerm = EncryptedPerson::EMAIL
        .eq("bob@example.com")
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_eq!(
        query, row.email.terms.0,
        "HMAC equality sends what it stores"
    );
}

#[tokio::test]
async fn a_matches_query_is_a_filter_over_the_query_value_that_the_stored_filter_holds() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let row: EncryptedPerson = person().encrypt_into(&keyset).await.unwrap();
    let stored = row.email.terms.1;

    let query: MatchQuery = EncryptedPerson::EMAIL
        .matches("BOB")
        .encrypt(&keyset)
        .await
        .unwrap();
    assert!(stored.matches(&query), "a case-folding index matches BOB");
    assert!(
        query.positions().len() < stored.positions().len(),
        "the query is the query value's filter, not the stored value's"
    );

    // The query's filter is the filter the index would store for the same
    // text, under the same label.
    let same_text: EncryptedPerson = Person {
        email: "BOB".into(),
        name: "x".into(),
    }
    .encrypt_into(&keyset)
    .await
    .unwrap();
    let as_stored = same_text.email.terms.1;
    assert_eq!(query.to_bytes(), as_stored.to_bytes());
    assert_eq!(query.positions(), as_stored.positions());
    assert_eq!(query.clone(), query);

    let elsewhere: MatchQuery = EncryptedPerson::EMAIL
        .matches("zzz")
        .encrypt(&keyset)
        .await
        .unwrap();
    assert!(!stored.matches(&elsewhere));
    assert_ne!(elsewhere, query);
}

/// A field's match index is its type's, so a query on the field is cut
/// under the field's own configuration and no other.
#[tokio::test]
async fn a_match_field_with_its_own_configuration_is_queried_under_it() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let row: EncryptedPerson = person().encrypt_into(&keyset).await.unwrap();
    let name = row.name.terms;

    let hit: MatchQuery<Exact> = EncryptedPerson::NAME
        .matches("Nguyen")
        .encrypt(&keyset)
        .await
        .unwrap();
    assert!(name.matches(&hit));
    let miss: MatchQuery<Exact> = EncryptedPerson::NAME
        .matches("nguyen")
        .encrypt(&keyset)
        .await
        .unwrap();
    assert!(
        !name.matches(&miss),
        "a case-sensitive index does not fold the query"
    );
}

#[tokio::test]
async fn a_target_answers_an_operator_through_the_index_it_names() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let stored: EncryptedContact = contact().encrypt_into(&keyset).await.unwrap();

    let query = EncryptedContact::EMAIL
        .eq("bob@example.com")
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_eq!(query, stored.email);

    let query = EncryptedContact::BIO
        .matches("bob")
        .encrypt(&keyset)
        .await
        .unwrap();
    assert!(stored.bio.matches(&query));
}

#[tokio::test]
async fn a_target_with_several_terms_answers_through_the_term_that_answers() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let stored: EncryptedPerson = person().encrypt_into(&keyset).await.unwrap();
    let (equality, matching) = &stored.email.terms;

    // Each operator has one term that answers it.
    let eq = EncryptedPerson::EMAIL
        .eq("bob@example.com")
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_eq!(&eq, equality);
    let matches = EncryptedPerson::EMAIL
        .matches("bob")
        .encrypt(&keyset)
        .await
        .unwrap();
    assert!(matching.matches(&matches));

    // One term answers what the term answers.
    let one_term: EncryptedContact = contact().encrypt_into(&keyset).await.unwrap();
    let eq = EncryptedContact::PHONE
        .eq("555 0100")
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_eq!(eq, one_term.phone.terms);
}

/// A target type that no record here encrypts into, queried through a
/// field reference written by hand, as an EQL type is queried under its column. It
/// states that its terms are derived under the field reference's label
/// (`op::LabelledTarget`) and names the index that answers `Eq` for it. A
/// query derives through that index alone and never runs the target's own
/// encryption.
struct Tagged;

impl op::LabelledTarget for Tagged {}

/// The equality index, its query term sent with the context it was derived
/// under, as an EQL query value stores its column: what a query term that
/// records its context reads from the token. The index serves the table
/// `users` alone. A label under another table names none of its columns,
/// and is refused before any term exists.
#[derive(Clone, Copy, Debug, Default)]
struct Labelled;

#[derive(Debug, PartialEq)]
struct LabelledTerm {
    label: String,
    extended: bool,
    term: EqualityTerm,
}

impl op::QueryTerm for LabelledTerm {}

impl Index<String> for Labelled {
    type Term = EqualityTerm;
    fn spec(&self) -> IndexSpec {
        Index::<String>::spec(&Equality)
    }
    fn operation<'s, K: 'static, M: SourceMode<'s, String>>(
        &self,
    ) -> Encryption<'s, String, EqualityTerm, K, CallerContext, M> {
        Index::<String>::operation(&Equality)
    }
}

impl op::Supports<op::Eq, String> for Labelled {
    type Query = LabelledTerm;
    type Verifier = ();
    fn prepare(&self, value: &String) -> Result<(), Error> {
        <Equality as op::Supports<op::Eq, String>>::prepare(&Equality, value)
    }
    fn check_label(&self, label: &Label, _: bool) -> Result<(), Error> {
        if label.segments().next() == Some("users") {
            Ok(())
        } else {
            Err(Error::Other("not a column".into()))
        }
    }
    fn query((): (), term: EqualityTerm, token: op::QueryToken) -> LabelledTerm {
        LabelledTerm {
            label: token.label().to_string(),
            extended: token.is_extended(),
            term,
        }
    }
}

impl op::Answers<op::Eq, String> for Tagged {
    type Via = Labelled;
}

fn refused_as_not_a_column<T: std::fmt::Debug>(result: Result<T, Error>) {
    assert!(
        matches!(&result, Err(Error::Other(reason)) if reason.to_string() == "not a column"),
        "{result:?}"
    );
}

/// A target whose index refuses an extended context: what an EQL column
/// is, stored under its table and column alone.
struct Column;

impl op::LabelledTarget for Column {}

/// The equality index that refuses an extended context.
#[derive(Default)]
struct Unextendable;

impl Index<String> for Unextendable {
    type Term = EqualityTerm;
    fn spec(&self) -> IndexSpec {
        Index::<String>::spec(&Equality)
    }
    fn operation<'s, K: 'static, M: SourceMode<'s, String>>(
        &self,
    ) -> Encryption<'s, String, EqualityTerm, K, CallerContext, M> {
        Index::<String>::operation(&Equality)
    }
}

impl op::Supports<op::Eq, String> for Unextendable {
    type Query = EqualityTerm;
    type Verifier = ();
    fn prepare(&self, value: &String) -> Result<(), Error> {
        <Equality as op::Supports<op::Eq, String>>::prepare(&Equality, value)
    }
    fn check_label(&self, _: &Label, extended: bool) -> Result<(), Error> {
        if extended {
            Err(Error::Other("no extension".into()))
        } else {
            Ok(())
        }
    }
    fn query((): (), term: EqualityTerm, _: op::QueryToken) -> EqualityTerm {
        term
    }
}

impl op::Answers<op::Eq, String> for Column {
    type Via = Unextendable;
}

/// The label check is about the whole context of the query. A scope
/// extends that context, so an index that takes no extension refuses a
/// query under a scope, before any key is requested, and derives its term
/// for the same label with no scope.
#[tokio::test]
async fn an_index_that_takes_no_extension_refuses_a_query_under_a_scope() {
    let (cipher, requests) = counted_cipher().await;
    let keyset = cipher.default_keyset();
    let refused = field_reference_of::<Column, Scope<u64>>("users", "email")
        .eq("bob@example.com")
        .scope(Scope::new(7u64))
        .encrypt(&keyset)
        .await;
    assert!(
        matches!(&refused, Err(Error::Other(reason)) if reason.to_string() == "no extension"),
        "{refused:?}"
    );
    assert_eq!(requests.total(), 0, "refused before any key is requested");

    let term = field_reference_of::<Column, NoScope>("users", "email")
        .eq("bob@example.com")
        .encrypt(&keyset)
        .await
        .unwrap();
    let stored: EqualityTerm = String::from("bob@example.com")
        .encrypt_into_with_context(&keyset, nonempty!("users").with("email"))
        .await
        .unwrap();
    assert_eq!(term, stored);
}

/// A `LabelledTarget` is queried through a field reference though nothing is
/// encrypted into it, and its query term reads the context its terms were
/// derived under from the token: the field reference's label, and whether a scope
/// extended it.
#[tokio::test]
async fn a_labelled_target_is_queried_under_the_field_references_label() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let stored: EqualityTerm = String::from("bob@example.com")
        .encrypt_into_with_context(&keyset, nonempty!("users").with("email"))
        .await
        .unwrap();

    let query = field_reference_of::<Tagged, NoScope>("users", "email")
        .eq("bob@example.com")
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_eq!(
        query,
        LabelledTerm {
            label: "users/email".into(),
            extended: false,
            term: stored,
        }
    );

    let query = field_reference_of::<Tagged, NoScope>("users", "name")
        .eq("bob@example.com")
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_eq!(query.label, "users/name");

    // Under a scope, the terms are derived under the label and the scope,
    // and the token says so: a term that records only the label must
    // refuse it.
    let extended = field_reference_of::<Tagged, Scope<u64>>("users", "email")
        .eq("bob@example.com")
        .scope(Scope::new(7u64))
        .encrypt(&keyset)
        .await
        .unwrap();
    let stored_extended: EqualityTerm = String::from("bob@example.com")
        .encrypt_into_with_context(&keyset, nonempty!("users").with("email").with(7u64))
        .await
        .unwrap();
    assert!(extended.extended);
    assert_eq!(extended.label, "users/email", "the label, before the scope");
    assert_eq!(extended.term, stored_extended);
}

/// A context the index refuses is refused when the query is encrypted,
/// before any keyset or key is requested and before any term is derived.
#[tokio::test]
async fn a_label_the_index_refuses_is_refused_before_any_keyset_or_term() {
    let (cipher, requests) = counted_cipher().await;
    let keyset = cipher.default_keyset();
    refused_as_not_a_column(
        field_reference_of::<Tagged, NoScope>("orders", "email")
            .eq("bob@example.com")
            .encrypt(&keyset)
            .await,
    );
    assert_eq!(requests.total(), 0, "refused before any key is requested");

    // A label the index takes derives the term, so the refusal above is
    // the label's.
    let query = field_reference_of::<Tagged, NoScope>("users", "email")
        .eq("bob@example.com")
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_eq!(query.label, "users/email");
}

#[tokio::test]
async fn operator_queries_settle_together_under_the_scope_of_the_write() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let row: TenantPerson = person()
        .encrypt_into_with_context(&keyset, Scope::new(7u64))
        .await
        .unwrap();
    let (equality, matching) = &row.email.terms;

    let (eq, matches) = TenantPerson::EMAIL
        .eq("bob@example.com")
        .scope(Scope::new(7u64))
        .encrypt(&keyset)
        .zip(
            TenantPerson::EMAIL
                .matches("bob")
                .scope(Scope::new(7u64))
                .encrypt(&keyset),
        )
        .await
        .unwrap();
    assert_eq!(&eq, equality);
    assert!(matching.matches(&matches));

    // The same label with no scope is another context.
    let unscoped = EncryptedPerson::EMAIL
        .eq("bob@example.com")
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_ne!(
        &unscoped, equality,
        "the query is derived under the label and the scope"
    );
}

#[tokio::test]
async fn an_operator_query_runs_under_the_keyset_it_is_given() {
    let cipher = stack_cipher().await;
    let tenant = cipher
        .keyset(IdentifiedBy::Name("tenant".to_string().into()))
        .await
        .unwrap();
    let stored: EncryptedPerson = person().encrypt_into(&tenant).await.unwrap();
    let under_tenant = EncryptedPerson::EMAIL
        .eq("bob@example.com")
        .encrypt(&tenant)
        .await
        .unwrap();
    assert_eq!(under_tenant, stored.email.terms.0);
    let under_default = EncryptedPerson::EMAIL
        .eq("bob@example.com")
        .encrypt(&cipher.default_keyset())
        .await
        .unwrap();
    assert_ne!(
        under_default, stored.email.terms.0,
        "another keyset, another key"
    );
}

#[tokio::test]
async fn verify_keeps_every_real_match_and_folds_case_as_the_index_does() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();

    let query = EncryptedPerson::EMAIL
        .matches("BOB@Example")
        .encrypt(&keyset)
        .await
        .unwrap();
    assert!(query.verify("bob@example.com"));
    assert!(query.verify(&String::from("say hi to Bob@example.org")));
    assert!(!query.verify("alice@example.com"));
    assert!(query.clone().verify("bob@example.com"));

    let exact = EncryptedPerson::NAME
        .matches("Nguyen")
        .encrypt(&keyset)
        .await
        .unwrap();
    assert!(exact.verify("Alice Nguyen"));
    assert!(
        !exact.verify("alice nguyen"),
        "a case-sensitive index keeps case"
    );
}

/// A match query is cut in Unicode 16 NFC, as the stored value is, so a
/// query and a row that spell one string in its two normal forms match and
/// verify. Text holding a code point unassigned in Unicode 16 has no normal
/// form: the query is refused, and such a row verifies against nothing.
#[tokio::test]
async fn a_match_query_is_cut_in_nfc_and_refuses_text_with_no_normal_form() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();

    let query = EncryptedPerson::EMAIL
        .matches("Rene\u{301}e")
        .encrypt(&keyset)
        .await
        .unwrap();
    let precomposed = EncryptedPerson::EMAIL
        .matches("Ren\u{e9}e")
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_eq!(query, precomposed, "one string, one filter");
    assert!(query.verify("Ren\u{e9}e Martin"));
    assert!(precomposed.verify("Rene\u{301}e Martin"));
    assert!(
        !query.verify("Ren\u{e9}e \u{378}"),
        "a value with no normal form verifies against nothing"
    );

    let refused = EncryptedPerson::EMAIL
        .matches("Ren\u{378}e")
        .encrypt(&keyset)
        .await;
    assert!(
        matches!(
            refused,
            Err(Error::Term(TermError::Normalize(
                vitaminc_normalize::NormalizeError::UnassignedCodePoint
            )))
        ),
        "{refused:?}"
    );
}

#[tokio::test]
async fn verify_drops_a_row_the_filter_matched_by_chance() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let value = "the quick brown fox jumps over the lazy dog and keeps running";
    let stored: TinyNote = note(value).encrypt_into(&keyset).await.unwrap();
    let stored = stored.body.terms;

    let real = TinyNote::BODY
        .matches("lazy dog")
        .encrypt(&keyset)
        .await
        .unwrap();
    assert!(stored.matches(&real) && real.verify(value));

    // The value holds no digit, so no query with one is in it; a 32-bit
    // filter this full holds some of their filters anyway.
    let mut false_positive = None;
    for i in 0..1000 {
        let digits = format!("{i:04}");
        let query = TinyNote::BODY
            .matches(&digits)
            .encrypt(&keyset)
            .await
            .unwrap();
        if stored.matches(&query) {
            false_positive = Some(query);
            break;
        }
    }
    let query = false_positive.expect("a 32-bit filter this full matches some query by chance");
    assert!(
        !query.verify(value),
        "the server would return this row; verify does not keep it"
    );
}

#[tokio::test]
async fn a_match_query_debugs_without_its_tokens() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let query = EncryptedPerson::EMAIL
        .matches("needle")
        .encrypt(&keyset)
        .await
        .unwrap();
    let shown = format!("{query:?}");
    assert_eq!(
        shown,
        format!("MatchQuery {{ positions: {:?}, .. }}", query.positions())
    );
    for token in ["nee", "eed", "edl", "dle", "needle"] {
        assert!(!shown.contains(token), "{shown}");
    }
}

/// A Bloom match asks for the query's tokens, in any order and anywhere;
/// it is not a substring test, and `verify` must not become one, or it
/// would drop rows the index rightly returned.
#[tokio::test]
async fn verify_is_a_token_test_not_a_substring_test() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let query = EncryptedPerson::EMAIL
        .matches("abcd")
        .encrypt(&keyset)
        .await
        .unwrap();
    assert!(query.verify("abc bcd"), "both 3-grams, never adjacent");
    assert!(!query.verify("abc"), "one 3-gram of two");

    let stored: WordNote = note("Hello, big World!")
        .encrypt_into(&keyset)
        .await
        .unwrap();
    let query = WordNote::BODY
        .matches("world hello")
        .encrypt(&keyset)
        .await
        .unwrap();
    assert!(stored.body.terms.matches(&query));
    assert!(query.verify("Hello, big World!"));
    assert!(
        !query.verify("worldly hello"),
        "a word is a token, not a prefix"
    );
}

#[tokio::test]
async fn target_limit_sizes_the_fetch_from_the_query_and_the_prior() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let query = |text: &'static str| PriorNote::BODY.matches(text).encrypt(&keyset);
    let stats = Stats::declared(1_000_000);

    let short = query("ali").await.unwrap();
    let long = query("alice nguyen").await.unwrap();
    let (Limit::Rows(short_rows), Limit::Rows(long_rows)) = (
        short.target_limit(10, &stats),
        long.target_limit(10, &stats),
    ) else {
        panic!("a declared prior gives a finite fetch");
    };
    assert!(
        short_rows > 1_000,
        "three letters against long text match thousands of rows by chance: {short_rows}"
    );
    assert!(long_rows < 20, "a long query sets enough bits: {long_rows}");
    assert!(long_rows >= 10, "never fewer than `want`");

    // A tighter confidence asks for more.
    let strict = short.target_limit(10, &stats.clone().with_confidence(0.9999));
    assert!(strict.rows().unwrap() > short_rows);
}

#[tokio::test]
async fn target_limit_without_a_prior_needs_a_measured_column() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let query = EncryptedPerson::EMAIL
        .matches("bob")
        .encrypt(&keyset)
        .await
        .unwrap();

    // The default configuration declares no prior.
    assert_eq!(
        query.target_limit(10, &Stats::declared(1_000)),
        Limit::Unbounded
    );

    // Measure the column: the set-bit count of each stored filter.
    let mut histogram = std::collections::BTreeMap::<u32, u64>::new();
    for email in [
        "bob@example.com",
        "alice@example.org",
        "carol.smith@example.net",
    ] {
        let row: EncryptedPerson = Person {
            email: email.into(),
            name: "x".repeat(4),
        }
        .encrypt_into(&keyset)
        .await
        .unwrap();
        *histogram
            .entry(row.email.terms.1.positions().len() as u32)
            .or_default() += 1;
    }
    // The pass rate the histogram gives this query, over a large table.
    let bits = query.positions().len() as i32;
    let rows_seen: u64 = histogram.values().sum();
    let p = histogram
        .iter()
        .map(|(&set, &n)| n as f64 * (f64::from(set) / 256.0).powi(bits))
        .sum::<f64>()
        / rows_seen as f64;
    let lambda = p * 1_000_000.0;
    let stats = Stats::measured(1_000_000, histogram);
    let Limit::Rows(rows) = query.target_limit(10, &stats) else {
        panic!("a measured column gives a finite fetch");
    };
    let extra = (rows - 10) as f64;
    assert!(
        extra >= lambda && extra <= lambda + 4.0 * lambda.sqrt() + 3.0,
        "10 wanted, λ = {lambda}: {rows}"
    );
}

/// A value too short to cut a token (two letters under 3-grams, or nothing
/// at all) is a valid thing to store in a match column. ADR-0009: the
/// stored term is the empty filter, which no query matches, and the value
/// itself seals and opens as any other.
#[tokio::test]
async fn a_short_match_value_stores_as_the_empty_filter_and_no_query_finds_it() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let query = EncryptedPerson::EMAIL
        .matches("alice")
        .encrypt(&keyset)
        .await
        .unwrap();
    let short_person = |email: &str| Person {
        email: email.into(),
        name: "Alice Nguyen".into(),
    };

    for short in ["Al", "", " "] {
        let stored: EncryptedPerson = short_person(short)
            .encrypt_into(&keyset)
            .await
            .unwrap_or_else(|error| panic!("{short:?} stores: {error}"));
        let filter = &stored.email.terms.1;
        assert!(
            filter.positions().is_empty(),
            "{short:?} is stored as the empty filter"
        );
        assert!(
            !filter.matches(&query),
            "{short:?}: the empty filter holds none of a query's positions"
        );
        assert!(!query.verify(short));
        let back = Person::decrypt_from(stored, &keyset).await.unwrap();
        assert_eq!(back.email, short, "{short:?} opens as written");
    }

    // The equality term still finds it: only the match term is empty.
    let stored: EncryptedPerson = short_person("Al").encrypt_into(&keyset).await.unwrap();
    let eq = EncryptedPerson::EMAIL
        .eq("Al")
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_eq!(eq, stored.email.terms.0);
}

/// A query with no tokens would match every row, so it is the one query
/// value the library refuses: when the query is encrypted, before a term
/// exists and before any keyset or key is requested.
#[tokio::test]
async fn a_match_query_with_no_tokens_is_refused_before_any_term_or_keyset() {
    let (cipher, requests) = counted_cipher().await;
    let keyset = cipher.default_keyset();

    for text in ["", "  ", "bo"] {
        let refused = EncryptedPerson::EMAIL.matches(text).encrypt(&keyset).await;
        assert!(
            matches!(refused, Err(Error::Term(TermError::EmptyTermText))),
            "{text:?}: {refused:?}"
        );
    }
    // Under another configuration, and in a batch.
    let refused = EncryptedPerson::NAME.matches("Al").encrypt(&keyset).await;
    assert!(matches!(
        refused,
        Err(Error::Term(TermError::EmptyTermText))
    ));
    let refused = EncryptedPerson::EMAIL
        .eq("bob@example.com")
        .encrypt(&keyset)
        .zip(EncryptedPerson::EMAIL.matches("bo").encrypt(&keyset))
        .await;
    assert!(matches!(
        refused,
        Err(Error::Term(TermError::EmptyTermText))
    ));
    assert_eq!(requests.total(), 0, "refused before any key is requested");
    assert_eq!(
        TermError::EmptyTermText.to_string(),
        "the query's text produces no match tokens (empty, separator-only, or shorter than the n-gram length)"
    );

    // The same text is a fine equality query, and a fine stored value.
    assert!(EncryptedPerson::EMAIL.eq("").encrypt(&keyset).await.is_ok());
    let row: Result<EncryptedPerson, Error> = Person {
        email: "bo".into(),
        name: "Al".into(),
    }
    .encrypt_into(&keyset)
    .await;
    assert!(row.is_ok(), "short values store: {:?}", row.err());
    assert_eq!(
        requests.total(),
        1,
        "storing a row asks for its data keys, so the count above is the refusals'"
    );
}

/// A match query under options the index cannot use is refused with
/// `InvalidOptions`, as storing under them is, and never reaches the
/// tokenizer: an n-gram length of zero would panic there.
#[tokio::test]
async fn a_match_query_under_invalid_options_is_refused_not_tokenised() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let refused = ZeroGramNote::BODY.matches("alice").encrypt(&keyset).await;
    assert!(
        matches!(refused, Err(Error::Term(TermError::InvalidOptions(_)))),
        "{refused:?}"
    );
    let stored: Result<ZeroGramNote, Error> = note("alice").encrypt_into(&keyset).await;
    assert!(
        matches!(stored, Err(Error::Term(TermError::InvalidOptions(_)))),
        "{:?}",
        stored.err()
    );
}

/// An ordering query sends the index's own term for the value: this
/// crate's ORE is CLLW, whose ciphertext has no left half to send alone,
/// so what is sent is what is stored, as for an HMAC. The field's type
/// names its order index: an `OreTerm` field sends an ORE term and an
/// `OpeTerm` field an OPE term.
#[tokio::test]
async fn an_ordering_query_is_the_index_term_of_the_value() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let stored: OreProfile = profile(34).encrypt_into(&keyset).await.unwrap();
    let stored = &stored.age.terms.1;

    let lt: OreTerm<u32> = OreProfile::AGE.lt(34u32).encrypt(&keyset).await.unwrap();
    let lte = OreProfile::AGE.lte(34u32).encrypt(&keyset).await.unwrap();
    let gt = OreProfile::AGE.gt(34u32).encrypt(&keyset).await.unwrap();
    let gte = OreProfile::AGE.gte(34u32).encrypt(&keyset).await.unwrap();
    for (name, term) in [("Lt", &lt), ("Lte", &lte), ("Gt", &gt), ("Gte", &gte)] {
        assert_eq!(term, stored, "{name} sends the ORE term");
    }
    let above = OreProfile::AGE.lt(35u32).encrypt(&keyset).await.unwrap();
    let below = OreProfile::AGE.lt(33u32).encrypt(&keyset).await.unwrap();
    assert!(
        &below < stored && stored < &above,
        "ORE terms order as the values"
    );

    let stored_ope: OpeProfile = profile(34).encrypt_into(&keyset).await.unwrap();
    let ope: OpeTerm<u32> = OpeProfile::AGE.gte(34u32).encrypt(&keyset).await.unwrap();
    assert_eq!(
        ope, stored_ope.age.terms.1,
        "an OPE field sends the OPE term"
    );
    let ope_above = OpeProfile::AGE.gt(35u32).encrypt(&keyset).await.unwrap();
    assert!(
        ope.as_bytes() < ope_above.as_bytes(),
        "OPE terms order as bytes"
    );

    // A field of one term answers the orderings through the index it names.
    let stored: EncryptedMember = Member { age: 5, balance: 0 }
        .encrypt_into(&keyset)
        .await
        .unwrap();
    let query = EncryptedMember::AGE
        .lte(5u32)
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_eq!(query, stored.age.terms);
}

/// `Between` is one term carrying both bounds, inclusive, derived under
/// the one label; each bound is the term the index sends for that value
/// alone (ADR-0009, decision 7).
#[tokio::test]
async fn a_between_query_is_one_term_carrying_both_bounds() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();

    let range: RangeQuery<OreTerm<u32>> = OreProfile::AGE
        .between(18u32, 65)
        .encrypt(&keyset)
        .await
        .unwrap();
    let lo = OreProfile::AGE.gte(18u32).encrypt(&keyset).await.unwrap();
    let hi = OreProfile::AGE.lte(65u32).encrypt(&keyset).await.unwrap();
    assert_eq!(range.lo(), &lo);
    assert_eq!(range.hi(), &hi);
    assert_eq!(range.clone().into_bounds(), (lo, hi));

    // A stored value inside the range orders between the bounds.
    let inside: OreProfile = profile(30).encrypt_into(&keyset).await.unwrap();
    let outside: OreProfile = profile(70).encrypt_into(&keyset).await.unwrap();
    let (inside, outside) = (&inside.age.terms.1, &outside.age.terms.1);
    assert!(range.lo() <= inside && inside <= range.hi());
    assert!(outside > range.hi());

    // Inclusive at both ends: one value is `(v, v)`.
    let one = OreProfile::AGE
        .between(40u32, 40)
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_eq!(one.lo(), one.hi());
    assert_ne!(one, range);

    // An OPE field's range carries OPE terms, and a field of one term
    // answers a range through the index it names.
    let ope: RangeQuery<OpeTerm<u32>> = OpeProfile::AGE
        .between(18u32, 65)
        .encrypt(&keyset)
        .await
        .unwrap();
    assert!(ope.lo().as_bytes() < ope.hi().as_bytes());
    let alone = EncryptedMember::BALANCE
        .between(1i64, 2)
        .encrypt(&keyset)
        .await
        .unwrap();
    assert!(alone.lo() < alone.hi());
}

/// A range whose low bound is above its high bound is not refused, as
/// SQL's `BETWEEN` is not: both bounds' terms are derived like any other
/// range's, in the order given, and the range matches nothing.
#[tokio::test]
async fn an_inverted_range_is_a_query_like_any_other() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let inverted = OreProfile::AGE
        .between(65u32, 18)
        .encrypt(&keyset)
        .await
        .unwrap();
    assert!(inverted.lo() > inverted.hi(), "the bounds as given");
    let one = OreProfile::AGE
        .between(18u32, 18)
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_eq!(one.lo(), one.hi());
}

/// A field answers the orderings through the index its type names, under
/// the field's own label. A field that is a term alone needs no sealing,
/// so it can hold the integer types the cipher does not seal on its own.
#[tokio::test]
async fn a_field_answers_the_orderings_through_its_declared_index() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let row: EncryptedMember = Member {
        age: 34,
        balance: -250,
    }
    .encrypt_into(&keyset)
    .await
    .unwrap();
    let age = &row.age.terms;
    let balance = &row.balance;

    let query = EncryptedMember::AGE
        .lte(34u32)
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_eq!(&query, age);
    let range = EncryptedMember::AGE
        .between(30u32, 40)
        .encrypt(&keyset)
        .await
        .unwrap();
    assert!(range.lo().as_bytes() <= age.as_bytes() && age.as_bytes() <= range.hi().as_bytes());

    // A signed value, ordered as a signed value.
    let owed = EncryptedMember::BALANCE
        .lt(-250i64)
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_eq!(&owed, balance);
    let zero = EncryptedMember::BALANCE
        .gte(0i64)
        .encrypt(&keyset)
        .await
        .unwrap();
    assert!(balance < &zero, "a negative balance is below zero");
    let overdrawn = EncryptedMember::BALANCE
        .between(-1_000i64, -1)
        .encrypt(&keyset)
        .await
        .unwrap();
    assert!(overdrawn.lo() <= balance && balance <= overdrawn.hi());
}

/// Text orders by its order key, ADR-0002's fold: the orderings are
/// answered over text, a query term of `Café` is the term of `cafe`, `alice`
/// orders before `Zoe` and `élan` between `eclair` and `emu`.
#[tokio::test]
async fn text_orders_by_its_folded_key() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let lt = |text: &str| OreProfile::SURNAME.lt(text).encrypt(&keyset);
    let ope = |text: &str| OpeProfile::SURNAME.lt(text).encrypt(&keyset);
    let cafe: OreTerm<String> = lt("cafe").await.unwrap();
    for text in ["Caf\u{e9}", "CAF\u{c9}", "cafe\u{301}"] {
        assert_eq!(lt(text).await.unwrap(), cafe, "{text:?}");
    }

    // OPE terms compare as bytes, so the order is visible here directly.
    let order = ["alice", "eclair", "\u{c9}lan", "emu", "Zoe"];
    let mut terms = Vec::new();
    for text in order {
        let term: OpeTerm<String> = ope(text).await.unwrap();
        terms.push(term.as_bytes().to_vec());
    }
    assert!(terms.windows(2).all(|pair| pair[0] < pair[1]), "{order:?}");
    // And ORE terms compare through their own comparison.
    let alice: OreTerm<String> = lt("alice").await.unwrap();
    let zoe: OreTerm<String> = lt("Zoe").await.unwrap();
    assert!(alice < zoe);

    let between = |lo: &str, hi: &str| OreProfile::SURNAME.between(lo, hi).encrypt(&keyset);
    let tie = between("A", "a").await.unwrap();
    assert_eq!(tie.lo(), tie.hi(), "one folded value");
    assert!(between("a", "B").await.is_ok());
    assert!(
        matches!(
            between("a\u{378}", "b").await,
            Err(Error::Term(TermError::Normalize(_)))
        ),
        "a bound with no fold"
    );
}

/// Floats order by their ADR-0002 order key, as Postgres's `float8` does:
/// the orderings are answered over `f64`, `-0.0` and `0.0` are one query
/// term, and every NaN is one and sorts above `+Infinity`.
#[tokio::test]
async fn floats_order_by_their_order_key() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let lt = |value: f64| OreProfile::SCORE.lt(value).encrypt(&keyset);
    let ope = |value: f64| OpeProfile::SCORE.lt(value).encrypt(&keyset);
    let zero: OreTerm<f64> = lt(0.0).await.unwrap();
    assert_eq!(lt(-0.0).await.unwrap(), zero, "-0.0 is 0.0");
    let nan: OreTerm<f64> = lt(f64::NAN).await.unwrap();
    assert_eq!(lt(-f64::NAN).await.unwrap(), nan, "one NaN");

    let order = [
        f64::NEG_INFINITY,
        -1.5,
        0.0,
        1e-300,
        1.5,
        f64::INFINITY,
        f64::NAN,
    ];
    let mut terms = Vec::new();
    for value in order {
        let term: OpeTerm<f64> = ope(value).await.unwrap();
        terms.push(term.as_bytes().to_vec());
    }
    assert!(terms.windows(2).all(|pair| pair[0] < pair[1]), "{order:?}");
    let low: OreTerm<f64> = lt(-1.5).await.unwrap();
    assert!(low < zero && zero < nan);

    let between = |lo: f64, hi: f64| OreProfile::SCORE.between(lo, hi).encrypt(&keyset);
    let from_nan = between(f64::NAN, f64::INFINITY).await.unwrap();
    assert!(from_nan.lo() > from_nan.hi(), "NaN sorts last");
    let one = between(0.0, -0.0).await.unwrap();
    assert_eq!(one.lo(), one.hi(), "one value");
    let range = between(-0.5, 2.5).await.unwrap();
    assert!(range.lo() < range.hi());
}
