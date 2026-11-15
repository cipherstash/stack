//! A field type that stores its context, as a field of a derived `struct =
//! ..` record (`ContextFromField`).
//!
//! The record gives each field a context of its own: the record's scope,
//! then the field's name. A field type that stores a table and a column
//! stores that pair, as an EQL type in `eql-bindings` does. Here `Column`
//! stands in for EQL's `Identifier`:
//!
//! - the field stores its own context, and writes the term it writes on its
//!   own under that column;
//! - on decrypt, the stored column must be the field's;
//! - a scope or a binding that the record lists comes after the own
//!   context. The field runs under it, as a field of any other type does,
//!   and does not store it. The reader supplies it again;
//! - a field of a record nested in another stores its own context too;
//! - a type that cannot store the field's own context is refused before any
//!   key is requested.
use std::sync::atomic::Ordering;

use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{
    Bind, CallerContext, ContextFromField, DecryptField, DecryptSource, EncryptTarget, Encryption,
    NoCallerContext, Scope,
};
use stack_encrypt::{
    nonempty, Ciphertext, ContextPiece, DecryptFrom, Descriptor, EncryptInto, Encrypted, Error,
    IntoContext, MaybeEmpty, NonEmpty, PlanError,
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

impl ContextFromField for Column {
    fn from_field(own: &ContextPiece<'_>) -> Option<NonEmpty<Self>> {
        let ContextPiece::List(parts) = own else {
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

/// A user's email on its own under the `users/email` column, with no record
/// around it.
async fn alone<K>(keyset: &stack_encrypt::KeysetCipher<'_, K>) -> Stored
where
    K: stack_encrypt::kms::DataKeySource + stack_encrypt::kms::IndexKeySource + Sync + 'static,
{
    ada()
        .email
        .encrypt_into_with_context(keyset, Column::of("users", "email"))
        .await
        .unwrap()
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, scope = "users")]
struct EncryptedUser {
    email: Stored,
}

#[tokio::test]
async fn a_field_stores_the_record_scope_and_its_name() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let stored: EncryptedUser = ada().encrypt_into(&keyset).await.unwrap();
    assert_eq!(stored.email.column, *Column::of("users", "email").get());

    // The term the field writes on its own under the column.
    let alone = alone(&keyset).await;
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

// --- A scope and a binding come after the own context, and are not stored ---

/// The caller supplies a tenant scope and a row binding.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, scope = "users", scope(tenant: u64), bind(row: u128))]
struct TenantUser {
    email: Stored,
}

/// The same record with a field type that stores nothing: the term and the
/// ciphertext, under the context the record gives the field.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, scope = "users", scope(tenant: u64), bind(row: u128))]
struct NativeTenantUser {
    email: Encrypted<EqualityTerm>,
}

#[tokio::test]
async fn a_scope_and_a_binding_are_used_and_not_stored() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let parts = || Scope::new(42u64).bind(9u128);
    let stored: TenantUser = ada()
        .encrypt_into_with_context(&keyset, parts())
        .await
        .unwrap();

    // Only the field's own context is stored.
    assert_eq!(stored.email.column, *Column::of("users", "email").get());

    // The term derives under the tenant too, as a field of any other type
    // does. So it is not the term of the column alone.
    let native: NativeTenantUser = ada()
        .encrypt_into_with_context(&keyset, parts())
        .await
        .unwrap();
    assert_eq!(stored.email.hm, native.email.terms);
    assert_ne!(stored.email.hm, alone(&keyset).await.hm);

    // The binding is in no query context: another row has the same term.
    let other_row: TenantUser = ada()
        .encrypt_into_with_context(&keyset, Scope::new(42u64).bind(10u128))
        .await
        .unwrap();
    assert_eq!(stored.email.hm, other_row.email.hm);
    // Another tenant has another term.
    let other_tenant: TenantUser = ada()
        .encrypt_into_with_context(&keyset, Scope::new(43u64).bind(9u128))
        .await
        .unwrap();
    assert_ne!(stored.email.hm, other_tenant.email.hm);

    // The reader supplies the scope and the binding again.
    let opened = User::decrypt_from_with_context(stored, &keyset, parts())
        .await
        .unwrap();
    assert_eq!(opened, ada());
}

#[tokio::test]
async fn a_field_opens_only_under_the_scope_and_binding_it_was_sealed_under() {
    let (cipher, _, retrieves) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let sealed = || async {
        let stored: TenantUser = ada()
            .encrypt_into_with_context(&keyset, Scope::new(42u64).bind(9u128))
            .await
            .unwrap();
        stored
    };

    let other_tenant =
        User::decrypt_from_with_context(sealed().await, &keyset, Scope::new(43u64).bind(9u128));
    assert!(other_tenant.await.is_err(), "another tenant");
    let other_row =
        User::decrypt_from_with_context(sealed().await, &keyset, Scope::new(42u64).bind(10u128));
    assert!(other_row.await.is_err(), "another row");

    // A value written on its own stores the same column. It was sealed
    // under the column alone, so it does not open as the record's field.
    let record = TenantUser {
        email: alone(&keyset).await,
    };
    let opened = User::decrypt_from_with_context(record, &keyset, Scope::new(42u64).bind(9u128));
    assert!(opened.await.is_err(), "sealed without the scope");

    // The stored column is still checked first, before any key.
    let elsewhere: Stored = ada()
        .email
        .encrypt_into_with_context(&keyset, Column::of("users", "name"))
        .await
        .unwrap();
    let record = TenantUser { email: elsewhere };
    let before = retrieves.load(Ordering::SeqCst);
    assert!(matches!(
        User::decrypt_from_with_context(record, &keyset, Scope::new(42u64).bind(9u128)).await,
        Err(Error::ContextMismatch { .. })
    ));
    assert_eq!(retrieves.load(Ordering::SeqCst), before, "no key requested");
}

#[derive(Clone, Debug, PartialEq, Zeroize)]
struct Account {
    id: u128,
    tenant: u64,
    email: String,
}

/// The scope and the binding are stored in the row, in fields of the
/// record. The field that stores its context still stores its own alone.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Account, scope = "accounts", scope(field = "tenant"), bind(field = "id"))]
struct EncryptedAccount {
    #[stash(passthrough)]
    id: u128,
    #[stash(passthrough)]
    tenant: u64,
    email: Stored,
}

#[tokio::test]
async fn a_scope_and_a_binding_stored_in_the_row_are_not_stored_in_the_field() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let account = Account {
        id: 9,
        tenant: 42,
        email: "ada@example.com".into(),
    };
    let stored: EncryptedAccount = account.clone().encrypt_into(&keyset).await.unwrap();
    assert_eq!(stored.email.column, *Column::of("accounts", "email").get());

    // The row supplies its scope and its binding, so the reader passes none.
    let moved = EncryptedAccount {
        id: 10,
        tenant: stored.tenant,
        email: stored.email.clone(),
    };
    assert_eq!(
        Account::decrypt_from(stored, &keyset).await.unwrap(),
        account
    );
    // The same field in another row does not open.
    assert!(Account::decrypt_from(moved, &keyset).await.is_err());
}

#[derive(Clone, Debug, PartialEq, Zeroize)]
struct Team {
    lead: User,
}

/// A record that holds another. The inner field's context is its own pair,
/// then the outer field's.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Team, scope = "teams")]
struct EncryptedTeam {
    lead: EncryptedUser,
}

#[tokio::test]
async fn a_field_of_a_nested_record_stores_its_own_context() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let team = Team { lead: ada() };
    let stored: EncryptedTeam = team.clone().encrypt_into(&keyset).await.unwrap();

    // The inner record's scope and the field's name. The outer record's
    // names come after them, and are not stored.
    assert_eq!(
        stored.lead.email.column,
        *Column::of("users", "email").get()
    );
    assert_ne!(stored.lead.email.hm, alone(&keyset).await.hm);

    assert_eq!(Team::decrypt_from(stored, &keyset).await.unwrap(), team);
}

// --- A context the type cannot store ----------------------------------------

/// `Stored`, under an own context of three parts. A `Column` stores two.
struct Misplaced(#[allow(dead_code)] Stored);
impl EncryptTarget<String> for Misplaced {
    type ContextInput = NoCallerContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, String, Self, K, Self::ContextInput> {
        <Stored as EncryptTarget<String>>::encryption()
            .under(nonempty!("users").with("email").with("work"))
            .map(Self)
            .accepting()
    }
}

/// The refusal names the context the type could not store.
fn assert_not_storable<T>(result: Result<T, Error>, named: &str) {
    match result {
        Err(Error::Plan(PlanError::ContextNotStorable { field })) => assert_eq!(field, named),
        Err(other) => panic!("expected ContextNotStorable, got {other:?}"),
        Ok(_) => panic!("expected ContextNotStorable, got a value"),
    }
}

#[tokio::test]
async fn an_own_context_the_type_cannot_store_is_refused_before_any_key() {
    let (cipher, generates, retrieves) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let own = Descriptor::of(nonempty!("users").with("email").with("work"));

    let sealed: Result<Misplaced, _> = ada().email.encrypt_into(&keyset).await;
    assert_not_storable(sealed, own.as_str());
    assert_eq!(generates.load(Ordering::SeqCst), 0, "no key requested");

    // The same on decrypt: no stored column can be the field's own.
    let stored = alone(&keyset).await;
    let before = retrieves.load(Ordering::SeqCst);
    let context =
        CallerContext::from(Scope::new(7u64)).extend(nonempty!("users").with("email").with("work"));
    let opening =
        <Stored as DecryptField<String, _>>::decryption_field(stored.clone(), context).unwrap();
    assert_not_storable(cipher.run_decryption(opening).await, own.as_str());

    // A context that no record built for a field has no own part. The
    // refusal names the context the type was given.
    let opening = <Stored as DecryptField<String, _>>::decryption_field(
        stored,
        CallerContext::from(Scope::new(7u64)),
    )
    .unwrap();
    assert_not_storable(cipher.run_decryption(opening).await, "7u64");
    assert_eq!(retrieves.load(Ordering::SeqCst), before, "no key requested");
}

/// A scope or a binding alone, with no field that stores its context, is
/// unchanged by all this: the record still requires it.
#[tokio::test]
async fn a_binding_alone_still_binds_the_field() {
    #[derive(EncryptTarget, DecryptSource)]
    #[stash(struct = User, scope = "users", bind(row: u128))]
    struct BoundUser {
        email: Stored,
    }
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let stored: BoundUser = ada()
        .encrypt_into_with_context(&keyset, Bind::new(9u128))
        .await
        .unwrap();
    assert_eq!(stored.email.column, *Column::of("users", "email").get());
    // A binding is in no query context, so the term is the column's.
    assert_eq!(stored.email.hm, alone(&keyset).await.hm);

    let moved = BoundUser {
        email: stored.email.clone(),
    };
    assert!(
        User::decrypt_from_with_context(moved, &keyset, Bind::new(10u128))
            .await
            .is_err(),
        "another row"
    );
    let opened = User::decrypt_from_with_context(stored, &keyset, Bind::new(9u128))
        .await
        .unwrap();
    assert_eq!(opened, ada());
}
