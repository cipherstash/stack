//! Scopes and bindings on a derived record (#1487): the context scenarios
//! 2 to 7 of the Stack Encrypt API plan.
//!
//! A scope is a part a query can supply too, such as a tenant. A binding
//! ties a ciphertext to one row, such as a row ID. Search terms derive
//! under the query context, the scopes. The key and the AAD derive under
//! the stored context, the scopes then the bindings. So a record bound to
//! its row is still found by a column query, and fails to open in another
//! row.
#![cfg(feature = "testing")]

mod common;

use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{Bind, DecryptSource, EncryptTarget, Scope};
use stack_encrypt::testing::{bind, scope, stored_bind, stored_scope, Expect};
use stack_encrypt::{
    assert_context, nonempty, DecryptFrom, EncryptInto, Encrypted, Error, StackCipher,
    StackCipherText,
};
use zeroize::Zeroize;

async fn cipher() -> StackCipher<FakeDataKeySource> {
    StackCipher::builder()
        .kms(FakeDataKeySource::new())
        .init()
        .await
        .unwrap()
}

/// The equality term a query for `email` derives under `context`: the
/// query context, with no binding.
async fn query_term<'a>(
    keyset: &stack_encrypt::KeysetCipher<'a, FakeDataKeySource>,
    email: &str,
    context: stack_encrypt::target::CallerContext,
) -> EqualityTerm {
    let probe: Encrypted<EqualityTerm> = String::from(email)
        .encrypt_into_with_context(keyset, context)
        .await
        .unwrap();
    probe.terms
}

fn column() -> stack_encrypt::NonEmpty<(&'static str, &'static str)> {
    nonempty!("users").with("email")
}

// Scenario 2: a scope the caller supplies and does not store.
#[derive(Clone, Zeroize)]
struct User {
    email: String,
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, scope = "users", scope(tenant: u64))]
struct TenantScoped {
    email: Encrypted<EqualityTerm>,
}

mod a_scope_the_caller_supplies {
    use super::*;

    #[test]
    fn shows_the_scope_in_both_contexts() {
        assert_eq!(
            TenantScoped::contexts().to_string(),
            "email\n  context: (users / email) / {tenant: u64}\n"
        );
        assert_context!(
            TenantScoped::contexts(),
            email = [["users", "email"], scope::<u64>("tenant")],
        );
    }

    #[tokio::test]
    async fn opens_under_the_same_tenant_and_is_found_by_a_tenant_query() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let user = User {
            email: "ada@example.com".into(),
        };
        let call = user
            .clone()
            .encrypt_into_with_context::<TenantScoped, _>(&keyset, Scope::new(42u64));
        assert_eq!(
            call.context().to_string(),
            "context: (users / email) / 42u64\n"
        );
        let stored = call.await.unwrap();

        // A tenant query derives the same term.
        let term = query_term(&keyset, "ada@example.com", column().with(42u64).into()).await;
        assert_eq!(stored.email.terms, term);
        let other = query_term(&keyset, "ada@example.com", column().with(43u64).into()).await;
        assert_ne!(stored.email.terms, other);

        let back = User::decrypt_from_with_context(stored, &keyset, Scope::new(42u64))
            .await
            .unwrap();
        assert_eq!(back.email, "ada@example.com");
    }

    #[tokio::test]
    async fn fails_to_open_under_another_tenant() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored: TenantScoped = User {
            email: "ada@example.com".into(),
        }
        .encrypt_into_with_context(&keyset, Scope::new(42u64))
        .await
        .unwrap();
        assert!(
            User::decrypt_from_with_context(stored, &keyset, Scope::new(43u64))
                .await
                .is_err()
        );
    }
}

// Scenario 3: a scope taken from the plaintext and stored in the row.
#[derive(Clone, Zeroize)]
struct TenantUser {
    tenant: u64,
    email: String,
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = TenantUser, scope = "users", scope(field = "tenant"))]
struct StoredTenant {
    #[stash(passthrough)]
    tenant: u64,
    email: Encrypted<EqualityTerm>,
}

mod a_scope_stored_in_the_row {
    use super::*;

    #[test]
    fn shows_where_the_scope_is_read_from() {
        assert_eq!(
            StoredTenant::contexts().to_string(),
            "email\n  context: (users / email) / {tenant: u64, from the plaintext}\n"
        );
        assert_context!(
            StoredTenant::contexts(),
            email = [["users", "email"], stored_scope::<u64>("tenant")],
        );
    }

    #[tokio::test]
    async fn reads_the_tenant_from_the_plaintext_and_from_the_row() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let user = TenantUser {
            tenant: 42,
            email: "ada@example.com".into(),
        };
        let call = user.encrypt_into::<StoredTenant, _>(&keyset);
        assert_eq!(
            call.context().to_string(),
            "context: (users / email) / 42u64\n"
        );
        let stored = call.await.unwrap();
        assert_eq!(stored.tenant, 42);
        let term = query_term(&keyset, "ada@example.com", column().with(42u64).into()).await;
        assert_eq!(stored.email.terms, term);

        // The row says which tenant: no context argument.
        let back = TenantUser::decrypt_from(stored, &keyset).await.unwrap();
        assert_eq!((back.tenant, back.email.as_str()), (42, "ada@example.com"));
    }

    #[tokio::test]
    async fn checks_a_tenant_the_reader_passes_before_any_key_is_requested() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored: StoredTenant = TenantUser {
            tenant: 42,
            email: "ada@example.com".into(),
        }
        .encrypt_into(&keyset)
        .await
        .unwrap();
        let same = TenantUser::decrypt_from_with_context(stored, &keyset, Scope::new(42u64))
            .await
            .unwrap();
        assert_eq!(same.tenant, 42);

        let (recording, sent) = common::recording_cipher().await;
        let stored: StoredTenant = TenantUser {
            tenant: 42,
            email: "ada@example.com".into(),
        }
        .encrypt_into(&recording.default_keyset())
        .await
        .unwrap();
        let before = sent.lock().unwrap().retrieved().len();
        let recording_keyset = recording.default_keyset();
        let open =
            TenantUser::decrypt_from_with_context(stored, &recording_keyset, Scope::new(7u64));
        assert!(open.context().has_failed());
        match open.await {
            Err(Error::ContextMismatch { stored }) => assert_eq!(stored.as_str(), "42u64"),
            Err(other) => panic!("expected a mismatch, got {other:?}"),
            Ok(_) => panic!("expected a mismatch, got a plaintext"),
        }
        assert_eq!(sent.lock().unwrap().retrieved().len(), before);
    }
}

// Scenario 4: a binding stored in the row.
#[derive(Clone, Zeroize)]
struct IdUser {
    id: u128,
    email: String,
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = IdUser, scope = "users", bind(field = "id"))]
struct RowBound {
    #[stash(passthrough)]
    id: u128,
    email: Encrypted<EqualityTerm>,
}

mod a_binding_stored_in_the_row {
    use super::*;

    #[test]
    fn shows_the_binding_in_the_stored_context_only() {
        assert_eq!(
            RowBound::contexts().to_string(),
            "email\n  query context:  users / email\n  stored context: (users / email) / {id: u128, from the plaintext}\n"
        );
        assert_context!(
            RowBound::contexts(),
            email = {
                query = ["users", "email"],
                stored = [["users", "email"], stored_bind::<u128>("id")],
            },
        );
    }

    #[tokio::test]
    async fn is_found_by_a_column_query_and_opens_only_in_its_row() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let user = IdUser {
            id: 9,
            email: "ada@example.com".into(),
        };
        let call = user.encrypt_into::<RowBound, _>(&keyset);
        assert_eq!(
            call.context().to_string(),
            "query context:  users / email\nstored context: (users / email) / 9u128\n"
        );
        let stored = call.await.unwrap();

        // The binding is not in the query context: a column query, with no
        // row ID, derives the stored term.
        let term = query_term(&keyset, "ada@example.com", column().into()).await;
        assert_eq!(stored.email.terms, term);

        let back = IdUser::decrypt_from(stored, &keyset).await.unwrap();
        assert_eq!(back.id, 9);

        // A ciphertext copied into another row fails to open there.
        let stored: RowBound = IdUser {
            id: 9,
            email: "ada@example.com".into(),
        }
        .encrypt_into(&keyset)
        .await
        .unwrap();
        let moved = RowBound {
            id: 10,
            email: stored.email,
        };
        assert!(IdUser::decrypt_from(moved, &keyset).await.is_err());
    }
}

// Scenario 5: a stored scope and a stored binding.
#[derive(Clone, Zeroize)]
struct TenantIdUser {
    tenant: u64,
    id: u128,
    email: String,
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = TenantIdUser, scope = "users", scope(field = "tenant"), bind(field = "id"))]
struct StoredBoth {
    #[stash(passthrough)]
    tenant: u64,
    #[stash(passthrough)]
    id: u128,
    email: Encrypted<EqualityTerm>,
}

mod a_stored_scope_and_a_stored_binding {
    use super::*;

    #[test]
    fn shows_both_parts() {
        assert_context!(
            StoredBoth::contexts(),
            email = {
                query = [["users", "email"], stored_scope::<u64>("tenant")],
                stored = [
                    [
                        Expect::from(["users", "email"]),
                        Expect::from(stored_scope::<u64>("tenant")),
                    ],
                    stored_bind::<u128>("id"),
                ],
            },
        );
    }

    #[tokio::test]
    async fn is_found_by_a_tenant_query_and_checks_both_parts_on_read() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored: StoredBoth = TenantIdUser {
            tenant: 42,
            id: 9,
            email: "ada@example.com".into(),
        }
        .encrypt_into(&keyset)
        .await
        .unwrap();
        let term = query_term(&keyset, "ada@example.com", column().with(42u64).into()).await;
        assert_eq!(stored.email.terms, term);

        let both =
            TenantIdUser::decrypt_from_with_context(stored, &keyset, Scope::new(42u64).bind(9u128))
                .await
                .unwrap();
        assert_eq!((both.tenant, both.id), (42, 9));

        let stored: StoredBoth = TenantIdUser {
            tenant: 42,
            id: 9,
            email: "ada@example.com".into(),
        }
        .encrypt_into(&keyset)
        .await
        .unwrap();
        let wrong_row =
            TenantIdUser::decrypt_from_with_context(stored, &keyset, Scope::new(42u64).bind(8u128))
                .await;
        assert!(matches!(wrong_row, Err(Error::ContextMismatch { .. })));
    }
}

// Scenario 6: a stored part and a caller-supplied part together.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = TenantUser, scope = "users", scope(field = "tenant"), bind(row: u128))]
struct StoredTenantCallerRow {
    #[stash(passthrough)]
    tenant: u64,
    email: Encrypted<EqualityTerm>,
}

mod a_stored_scope_and_a_caller_binding {
    use super::*;

    #[test]
    fn shows_the_stored_part_then_the_callers() {
        assert_context!(
            StoredTenantCallerRow::contexts(),
            email = {
                query = [["users", "email"], stored_scope::<u64>("tenant")],
                stored = [
                    [
                        Expect::from(["users", "email"]),
                        Expect::from(stored_scope::<u64>("tenant")),
                    ],
                    bind::<u128>("row"),
                ],
            },
        );
    }

    #[tokio::test]
    async fn takes_the_row_from_the_caller_and_the_tenant_from_the_row() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let user = TenantUser {
            tenant: 42,
            email: "ada@example.com".into(),
        };
        let stored: StoredTenantCallerRow = user
            .clone()
            .encrypt_into_with_context(&keyset, Bind::new(9u128))
            .await
            .unwrap();
        let term = query_term(&keyset, "ada@example.com", column().with(42u64).into()).await;
        assert_eq!(stored.email.terms, term);

        // The row ID must be passed. The tenant may be passed, to check it.
        let back = TenantUser::decrypt_from_with_context(stored, &keyset, Bind::new(9u128))
            .await
            .unwrap();
        assert_eq!(back.tenant, 42);

        let stored: StoredTenantCallerRow = user
            .clone()
            .encrypt_into_with_context(&keyset, Bind::new(9u128))
            .await
            .unwrap();
        let checked =
            TenantUser::decrypt_from_with_context(stored, &keyset, Scope::new(42u64).bind(9u128))
                .await
                .unwrap();
        assert_eq!(checked.email, "ada@example.com");

        let stored: StoredTenantCallerRow = user
            .encrypt_into_with_context(&keyset, Bind::new(9u128))
            .await
            .unwrap();
        assert!(
            TenantUser::decrypt_from_with_context(stored, &keyset, Bind::new(8u128))
                .await
                .is_err()
        );
    }
}

// Scenario 7: a scope the caller supplies on every call and never stores.
#[derive(Clone, Zeroize)]
struct Secret {
    value: String,
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Secret, scope = "secrets", scope(host: String))]
struct HostScoped {
    value: StackCipherText,
}

mod a_scope_that_is_never_stored {
    use super::*;

    #[test]
    fn shows_the_host_scope() {
        assert_context!(
            HostScoped::contexts(),
            value = [["secrets", "value"], scope::<String>("host")],
        );
    }

    #[tokio::test]
    async fn opens_only_on_the_host_that_sealed_it() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let host = String::from("host-a");
        let stored: HostScoped = Secret {
            value: "s3cret".into(),
        }
        .encrypt_into_with_context(&keyset, Scope::new(host.clone()))
        .await
        .unwrap();
        let back = Secret::decrypt_from_with_context(stored, &keyset, Scope::new(host))
            .await
            .unwrap();
        assert_eq!(back.value, "s3cret");

        let stored: HostScoped = Secret {
            value: "s3cret".into(),
        }
        .encrypt_into_with_context(&keyset, Scope::new(String::from("host-a")))
        .await
        .unwrap();
        assert!(Secret::decrypt_from_with_context(
            stored,
            &keyset,
            Scope::new(String::from("host-b"))
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn refuses_an_empty_scope_before_any_key_is_requested() {
        let (cipher, sent) = common::recording_cipher().await;
        let keyset = cipher.default_keyset();
        let result = Secret {
            value: "s3cret".into(),
        }
        .encrypt_into_with_context::<HostScoped, _>(&keyset, Scope::new(String::new()))
        .await;
        assert!(result.is_err());
        assert!(sent.lock().unwrap().generated().is_empty());
    }
}

/// A record with no part stores the same bytes as before: its contexts are
/// the field's own, with nothing after them, so the key, the AAD and the
/// terms are unchanged. The frozen conformance vectors hold the bytes; this
/// pins the view.
#[test]
fn a_record_with_no_binding_has_one_context_per_field() {
    #[derive(Zeroize)]
    struct Plain {
        email: String,
    }
    #[derive(EncryptTarget, DecryptSource)]
    #[stash(struct = Plain, scope = "users")]
    struct Unbound {
        email: Encrypted<EqualityTerm>,
    }
    assert!(!Unbound::contexts().fields()[0].context().has_binding());
    assert_context!(Unbound::contexts(), email = ["users", "email"]);
}

/// A JSON document bound to its row: the entries seal under the stored
/// context, and the selectors derive under the query context, so a query
/// under the scopes alone finds the document, and the document opens under
/// its binding and under nothing less.
mod a_bound_json_document {
    use super::*;
    use stack_encrypt::json::{JsonDocument, JsonPath};
    use stack_encrypt::target::{CallerContext, DecryptInto, EncryptFrom};

    fn profile() -> stack_encrypt::NonEmpty<(&'static str, &'static str)> {
        nonempty!("users").with("profile")
    }

    #[tokio::test]
    async fn is_found_by_a_query_under_the_scopes_and_opens_under_its_binding() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let value = serde_json::json!({"hello": "world"});
        let bound = CallerContext::from(Scope::new(42u64).bind(9u128)).extend(profile());
        let sealing = keyset.run(
            <JsonDocument as EncryptFrom<serde_json::Value>>::encryption::<FakeDataKeySource>(),
            &value,
            bound.clone(),
        );
        assert_eq!(
            sealing.context().to_string(),
            "query context:  (users / profile) / 42u64\n\
             stored context: ((users / profile) / 42u64) / 9u128\n"
        );
        let document = sealing.await.unwrap();

        // The selector a query derives under the scopes names an entry.
        let path = JsonPath::parse("$.hello").unwrap();
        let under_scopes = keyset
            .json_selector(&path, profile().with(42u64))
            .await
            .unwrap();
        let has = |selector: &stack_encrypt::json::JsonSelector| {
            document
                .entries()
                .iter()
                .any(|entry| entry.selector() == selector.as_bytes())
        };
        assert!(
            has(&under_scopes),
            "the bound document is found by a query under the scopes"
        );
        let under_binding = keyset
            .json_selector(&path, profile().with(42u64).with(9u128))
            .await
            .unwrap();
        assert!(
            !has(&under_binding),
            "no selector derives under the binding"
        );

        // The document opens under its binding, and not under the scopes.
        let opened: serde_json::Value = keyset
            .run_decryption(
                <JsonDocument as DecryptInto<serde_json::Value>>::decryption::<FakeDataKeySource>(
                    document.clone(),
                    bound.into(),
                ),
            )
            .await
            .unwrap();
        assert_eq!(opened, value);
        let scopes_alone = CallerContext::from(Scope::new(42u64)).extend(profile());
        let refused = keyset
            .run_decryption(
                <JsonDocument as DecryptInto<serde_json::Value>>::decryption::<FakeDataKeySource>(
                    document,
                    scopes_alone.into(),
                ),
            )
            .await;
        assert!(refused.is_err(), "the binding left out: {refused:?}");
    }

    /// With the root open, the client walks the token chain itself, so the
    /// chain must derive under the query context on both sides: a bound
    /// document sealed with `sealed_root: false` opens under its binding.
    #[tokio::test]
    async fn opens_with_its_root_open_too() {
        use stack_encrypt::json::JsonOptions;
        use stack_encrypt::target::{json_document, Borrowed};
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let value = serde_json::json!({"hello": "world", "n": [1, 2]});
        let bound = CallerContext::from(Scope::new(42u64).bind(9u128)).extend(profile());
        let options = JsonOptions {
            sealed_root: false,
            ..JsonOptions::new()
        };
        let document: JsonDocument = keyset
            .run(json_document::<_, Borrowed>(options), &value, bound.clone())
            .await
            .unwrap();
        let opened: serde_json::Value = keyset
            .run_decryption(
                <JsonDocument as DecryptInto<serde_json::Value>>::decryption::<FakeDataKeySource>(
                    document.clone(),
                    bound.into(),
                ),
            )
            .await
            .unwrap();
        assert_eq!(opened, value);
        let scopes_alone = CallerContext::from(Scope::new(42u64)).extend(profile());
        let refused = keyset
            .run_decryption(
                <JsonDocument as DecryptInto<serde_json::Value>>::decryption::<FakeDataKeySource>(
                    document,
                    scopes_alone.into(),
                ),
            )
            .await;
        assert!(refused.is_err(), "the binding left out: {refused:?}");
    }
}

/// A query carries no binding. A bare `Bind` does not compile
/// (`tests/ui/bind_in_query.rs`); a binding that reaches the chain inside
/// a `CallerContext` or a `DeclaredContext` is refused when the query is
/// awaited, before any key is requested, rather than dropped.
mod a_binding_in_a_query_chain {
    use super::*;
    use stack_encrypt::target::{CallerContext, DeclaredContext};
    use stack_encrypt::{op, Equality, Plan, PlanError};

    #[tokio::test]
    async fn is_refused_before_any_key_is_requested() {
        let cipher = cipher().await;
        let plan = Plan::context("users/email")
            .with::<String, _>(Equality)
            .build()
            .unwrap();
        let bound = || CallerContext::from(Scope::new(7u64).bind(9u128));
        let refused = cipher
            .query(op::Eq, "ada@example.com")
            .extend(bound())
            .on(&plan)
            .await;
        assert!(
            matches!(refused, Err(Error::Plan(PlanError::BindInQuery))),
            "{refused:?}"
        );
        let refused = cipher
            .query(op::Eq, "ada@example.com")
            .extend(DeclaredContext::default().with(Bind::new(9u128)))
            .on(&plan)
            .await;
        assert!(
            matches!(refused, Err(Error::Plan(PlanError::BindInQuery))),
            "{refused:?}"
        );
        assert_eq!(
            PlanError::BindInQuery.to_string(),
            "a query takes no binding: a binding is in the stored context only"
        );

        // The same context seals a write through the plan, and the scopes
        // alone derive the stored term: the row is found by its tenant.
        let keyset = cipher.default_keyset();
        let stored = cipher
            .encrypt(&String::from("ada@example.com"))
            .using(&plan)
            .extend(bound())
            .await
            .unwrap();
        let query = cipher
            .query(op::Eq, "ada@example.com")
            .extend(Scope::new(7u64))
            .on(&plan)
            .await
            .unwrap();
        assert_eq!(stored.terms, query);
        let _ = keyset;
    }
}
