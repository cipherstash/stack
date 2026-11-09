//! The contexts the EQL v4 types use, shown before any key is requested
//! (#1568). Scenario 8 of the Stack Encrypt API plan's context scenarios:
//! an EQL type, with its column as the context.

use eql_bindings::v4::text::{TextEq, TextEqQuery};
use eql_bindings::Identifier;
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::target::{EncryptTarget, Encryption, NoCallerContext, Zeroize};
use stack_encrypt::testing::{from_plaintext, required};
use stack_encrypt::{
    assert_context, Describe as _, EncryptInto, IntoContext as _, NonEmpty, StackCipher,
};

async fn cipher() -> StackCipher<FakeDataKeySource> {
    StackCipher::builder()
        .kms(FakeDataKeySource::new())
        .init()
        .await
        .unwrap()
}

/// Every stored field of an EQL type is sealed or indexed under the column
/// the caller supplies, which the type stores in `i`.
#[test]
fn a_stored_type_shows_the_column_as_a_typed_placeholder() {
    assert_eq!(
        TextEq::contexts().to_string(),
        "c\n  context: {context: NonEmpty<Identifier>}\nhm\n  context: {context: NonEmpty<Identifier>}\n"
    );
    assert_context!(
        TextEq::contexts(),
        c = [required::<NonEmpty<Identifier>>()],
        hm = [required::<NonEmpty<Identifier>>()],
    );
    // A query type stores no column, and its term is derived under the one
    // the caller supplies.
    assert_eq!(
        TextEqQuery::contexts().to_string(),
        "hm\n  context: {context: NonEmpty<Identifier>}\n"
    );
}

/// A call shows the column itself: the table, then the column.
#[tokio::test]
async fn a_call_shows_the_table_and_the_column() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let column = Identifier::for_column("users", "email").unwrap();
    let call = String::from("ada@example.com").encrypt_into_with_context::<TextEq, _>(&keyset, column);
    assert_eq!(call.context().to_string(), "context: users / email\n");
    assert_context!(call.context(), ["users", "email"]);
    let stored = call.await.unwrap();
    assert_eq!(stored.i.t, "users");
}

/// A borrowed identifier is the same context as the identifier: a caller
/// can hold one identifier and pass `&identifier` to the cipher-directed
/// API, or build a `NonEmpty<&Identifier>` for a term.
#[test]
fn a_borrowed_identifier_is_the_same_context() {
    let column = Identifier::for_column("users", "email").unwrap().into_inner();
    assert_eq!((&column).into_context(), column.clone().into_context());
    assert_eq!((&column).into_context(), column.to_context());
}

/// The migration shim of #1586 takes its column from the plaintext, and the
/// view says so.
struct V3Plaintext {
    i: Identifier,
    p: String,
}
impl Zeroize for V3Plaintext {
    // The column is not secret.
    fn zeroize(&mut self) {
        self.p.zeroize();
    }
}
struct Shim(#[allow(dead_code)] TextEq);
impl EncryptTarget<V3Plaintext> for Shim {
    type ContextInput = NoCallerContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, V3Plaintext, Self, K, NoCallerContext> {
        <TextEq as EncryptTarget<String>>::encryption()
            .project(|source: &V3Plaintext| &source.p)
            .context_from(|source: &V3Plaintext| &source.i)
            .map(Shim)
    }
}

#[test]
fn a_shim_shows_the_column_read_from_the_plaintext() {
    let contexts = <Shim as EncryptTarget<V3Plaintext>>::encryption::<()>().contexts();
    assert_eq!(
        contexts.to_string(),
        "c\n  context: {context: NonEmpty<Identifier>, from the plaintext}\nhm\n  context: {context: NonEmpty<Identifier>, from the plaintext}\n"
    );
    assert_context!(
        contexts,
        c = [from_plaintext::<NonEmpty<Identifier>>("context")],
        hm = [from_plaintext::<NonEmpty<Identifier>>("context")],
    );
}
