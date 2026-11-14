//! A field type that stores its context, as a field of a derived `struct =
//! ..` record (`FromFieldContext`).
//!
//! The record gives each field its scope and the field's name. A field type
//! that stores a table and a column takes that pair as the context it
//! stores, as an EQL type in `eql-bindings` does. Here `Column` stands in
//! for EQL's `Identifier`:
//!
//! - the field stores the pair, and writes the term it writes on its own
//!   under that column;
//! - on decrypt, the stored column must be the field's;
//! - a record that lists a caller scope or a binding gives the field a
//!   context it cannot store, and every call is refused before any key is
//!   requested.
use std::sync::atomic::Ordering;

use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{
    Bind, CallerContext, DecryptSource, EncryptTarget, FromFieldContext, Scope,
};
use stack_encrypt::{
    Ciphertext, ContextPiece, DecryptFrom, EncryptInto, Error, IntoContext, MaybeEmpty, NonEmpty,
    PlanError,
};
use zeroize::Zeroize;
mod common;

/// A table and a column, as EQL's `Identifier` stores them.
#[derive(Clone, Debug, PartialEq)]
struct Column {
    table: String,
    column: String,
}

impl Column {
    fn of(table: &str, column: &str) -> NonEmpty<Self> {
        NonEmpty::new(Self {
            table: table.into(),
            column: column.into(),
        })
        .unwrap()
    }
}

impl MaybeEmpty for Column {
    fn is_empty(&self) -> bool {
        self.table.is_empty() || self.column.is_empty()
    }
}

/// The same two parts a record gives a field: the scope, then the name.
impl<'a> IntoContext<'a> for Column {
    fn into_context(self) -> ContextPiece<'a> {
        ContextPiece::List(vec![
            ContextPiece::Text(self.table.into()),
            ContextPiece::Text(self.column.into()),
        ])
    }
}

impl FromFieldContext for Column {
    fn from_field_context(context: &CallerContext) -> Option<NonEmpty<Self>> {
        if context.has_bindings() {
            return None;
        }
        let ContextPiece::List(parts) = context.query() else {
            return None;
        };
        let [ContextPiece::Text(table), ContextPiece::Text(column)] = parts.as_slice() else {
            return None;
        };
        NonEmpty::new(Self {
            table: table.to_string(),
            column: column.to_string(),
        })
        .ok()
    }
}

/// A value that stores its column, as an EQL `TextEq` does.
#[derive(Clone, EncryptTarget, DecryptSource)]
#[stash(plaintext = String)]
struct Stored {
    #[stash(context_field)]
    column: Column,
    c: Ciphertext,
    hm: EqualityTerm,
}

#[derive(Clone, Debug, PartialEq, Zeroize)]
struct User {
    email: String,
}

fn ada() -> User {
    User {
        email: "ada@example.com".into(),
    }
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, scope = "users")]
struct EncryptedUser {
    email: Stored,
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, scope = "users", scope(tenant: u64))]
struct TenantUser {
    email: Stored,
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, scope = "users", bind(row: u128))]
struct BoundUser {
    email: Stored,
}

/// The refusal names the field by the record's scope and its name.
fn assert_not_storable<T>(result: Result<T, Error>) {
    match result {
        Err(Error::Plan(PlanError::ContextNotStorable { field })) => {
            assert_eq!(field, "users/email");
        }
        Err(other) => panic!("expected ContextNotStorable, got {other:?}"),
        Ok(_) => panic!("expected ContextNotStorable, got a value"),
    }
}

#[tokio::test]
async fn a_field_stores_the_record_scope_and_its_name() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let stored: EncryptedUser = ada().encrypt_into(&keyset).await.unwrap();
    assert_eq!(stored.email.column, *Column::of("users", "email").get());

    // The term the field writes on its own under the column.
    let alone: Stored = ada()
        .email
        .encrypt_into_with_context(&keyset, Column::of("users", "email"))
        .await
        .unwrap();
    assert_eq!(stored.email.hm, alone.hm);

    let opened = User::decrypt_from(stored, &keyset).await.unwrap();
    assert_eq!(opened, ada());

    // The value written on its own opens as the record's field.
    let record = EncryptedUser { email: alone };
    assert_eq!(User::decrypt_from(record, &keyset).await.unwrap(), ada());
}

#[tokio::test]
async fn a_field_that_stores_another_column_is_refused() {
    let (cipher, _, retrieves) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let elsewhere: Stored = ada()
        .email
        .encrypt_into_with_context(&keyset, Column::of("users", "name"))
        .await
        .unwrap();
    let record = EncryptedUser { email: elsewhere };
    let before = retrieves.load(Ordering::SeqCst);
    assert!(matches!(
        User::decrypt_from(record, &keyset).await,
        Err(Error::ContextMismatch { .. })
    ));
    assert_eq!(retrieves.load(Ordering::SeqCst), before, "no key requested");
}

#[tokio::test]
async fn a_caller_scope_or_binding_is_refused_before_any_key() {
    let (cipher, generates, retrieves) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();

    let scoped: Result<TenantUser, _> = ada()
        .encrypt_into_with_context(&keyset, Scope::new(42u64))
        .await;
    assert_not_storable(scoped);
    let bound: Result<BoundUser, _> = ada()
        .encrypt_into_with_context(&keyset, Bind::new(9u128))
        .await;
    assert_not_storable(bound);
    assert_eq!(generates.load(Ordering::SeqCst), 0, "no key requested");

    // A value stored under the field's own column does not open in such a
    // record either: the record's context is not the one it stores.
    let alone: Stored = ada()
        .email
        .encrypt_into_with_context(&keyset, Column::of("users", "email"))
        .await
        .unwrap();
    let before = retrieves.load(Ordering::SeqCst);
    let scoped = TenantUser {
        email: alone.clone(),
    };
    assert_not_storable(User::decrypt_from_with_context(scoped, &keyset, Scope::new(42u64)).await);
    let bound = BoundUser { email: alone };
    assert_not_storable(User::decrypt_from_with_context(bound, &keyset, Bind::new(9u128)).await);
    assert_eq!(retrieves.load(Ordering::SeqCst), before, "no key requested");
}
