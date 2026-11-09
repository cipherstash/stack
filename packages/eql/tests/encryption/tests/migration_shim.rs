//! A migration shim: an EQL v4 type encrypted from a value that contains its
//! own column, with no context argument.
//!
//! To move EQL v3 data to v4, each v3 value is decrypted, then encrypted again
//! as v4. The decrypted value arrives with the column it was stored in, `i`.
//! The shim takes the context from `i`, through `Encryption::context_from`,
//! and the value from `p`. To rename the column, edit `i` before the call.
//!
//! One generic impl covers every v4 type whose context is its column. The
//! shim must write the v4 type itself, byte for byte where the bytes are
//! deterministic. A query built the usual way finds the value, and the value
//! opens as the original plaintext.

mod common;

use std::cmp::Ordering;

use eql_bindings::v4::integer::{IntegerOrdOre, IntegerOrdOreQuery};
use eql_bindings::v4::text::{TextEq, TextEqQuery};
use eql_bindings::Identifier;
use stack_encrypt::target::{EncryptTarget, Encryption, NoCallerContext, RequiredContext, Zeroize};
use stack_encrypt::{DecryptFrom, EncryptInto, Error, NonEmpty};

/// A value decrypted from EQL v3, with the column it was stored in.
struct V3Plaintext<P> {
    i: Identifier,
    p: P,
}
impl<P: Zeroize> Zeroize for V3Plaintext<P> {
    // The column is not secret: it is stored in the clear in `i`.
    fn zeroize(&mut self) {
        self.p.zeroize();
    }
}

/// A v4 type, encrypted from a v3 plaintext, under the column in the plaintext.
struct Shim<T>(T);

impl<P, T> EncryptTarget<V3Plaintext<P>> for Shim<T>
where
    P: Zeroize,
    T: EncryptTarget<P, ContextInput = RequiredContext<NonEmpty<Identifier>>>,
{
    type ContextInput = NoCallerContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, V3Plaintext<P>, Self, K, NoCallerContext>
    where
        V3Plaintext<P>: 's,
    {
        T::encryption()
            .project(|source: &V3Plaintext<P>| &source.p)
            .context_from(|source: &V3Plaintext<P>| &source.i)
            .map(Shim)
    }
}

fn identifier(table: &str, column: &str) -> Identifier {
    Identifier {
        t: table.to_owned(),
        c: column.to_owned(),
    }
}

fn column(table: &str, column: &str) -> NonEmpty<Identifier> {
    Identifier::for_column(table, column).unwrap()
}

async fn email_query(
    keyset: &stack_encrypt::KeysetCipher<'_, common::Observed>,
    name: &str,
) -> TextEqQuery {
    "alan@example.com"
        .to_owned()
        .encrypt_into_with_context(keyset, column("customers", name))
        .await
        .unwrap()
}

async fn age_query(
    keyset: &stack_encrypt::KeysetCipher<'_, common::Observed>,
    age: i32,
) -> IntegerOrdOreQuery {
    age.encrypt_into_with_context(keyset, column("customers", "age"))
        .await
        .unwrap()
}

#[tokio::test]
async fn a_v3_value_encrypts_as_the_v4_type_with_no_context_argument() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();

    let source = V3Plaintext {
        i: identifier("customers", "email"),
        p: "alan@example.com".to_owned(),
    };
    let Shim(migrated): Shim<TextEq> = source.encrypt_into(&keyset).await.unwrap();

    assert_eq!(
        (migrated.i.t.as_str(), migrated.i.c.as_str()),
        ("customers", "email")
    );
    let query: TextEqQuery = "alan@example.com"
        .to_owned()
        .encrypt_into_with_context(&keyset, column("customers", "email"))
        .await
        .unwrap();
    assert_eq!(
        migrated.hm, query.hm,
        "a query built the usual way finds it"
    );

    let opened = String::decrypt_from_with_context(migrated, &keyset, column("customers", "email"))
        .await
        .unwrap();
    assert_eq!(opened, "alan@example.com");
}

#[tokio::test]
async fn the_same_shim_covers_an_ordered_type() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();

    let source = V3Plaintext {
        i: identifier("customers", "age"),
        p: 41_i32,
    };
    let Shim(migrated): Shim<IntegerOrdOre> = source.encrypt_into(&keyset).await.unwrap();

    // A block ORE term contains a nonce, so the test compares it by order.
    // The migrated value orders after the query for 40, equal to the query
    // for 41, and before the query for 42.
    let compare = |query: &IntegerOrdOreQuery| migrated.ob.partial_cmp(&query.ob);
    assert_eq!(
        compare(&age_query(&keyset, 40).await),
        Some(Ordering::Greater)
    );
    assert_eq!(
        compare(&age_query(&keyset, 41).await),
        Some(Ordering::Equal)
    );
    assert_eq!(compare(&age_query(&keyset, 42).await), Some(Ordering::Less));

    let opened = i32::decrypt_from_with_context(migrated, &keyset, column("customers", "age"))
        .await
        .unwrap();
    assert_eq!(opened, 41);
}

#[tokio::test]
async fn a_renamed_column_is_the_column_the_value_is_sealed_under() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();

    let mut source = V3Plaintext {
        i: identifier("customers", "email"),
        p: "alan@example.com".to_owned(),
    };
    source.i.c = "contact_email".to_owned();
    let Shim(migrated): Shim<TextEq> = source.encrypt_into(&keyset).await.unwrap();
    assert_eq!(migrated.i.c, "contact_email");

    // The query for the new column finds the value. The query for the old
    // column does not.
    assert_eq!(migrated.hm, email_query(&keyset, "contact_email").await.hm);
    assert_ne!(migrated.hm, email_query(&keyset, "email").await.hm);

    // The ciphertext is sealed under the new column, so it opens there.
    let opened = String::decrypt_from_with_context(
        migrated.clone(),
        &keyset,
        column("customers", "contact_email"),
    )
    .await
    .unwrap();
    assert_eq!(opened, "alan@example.com");

    // Opened as the old column, the value is refused before any key is
    // requested, because the stored column does not match.
    let result =
        String::decrypt_from_with_context(migrated.clone(), &keyset, column("customers", "email"))
            .await;
    assert!(
        matches!(result, Err(Error::ContextMismatch { .. })),
        "{:?}",
        result.err()
    );

    // Change the stored column back to the old one. The ciphertext still
    // fails to open, because it is bound to the new column, not to the label.
    let mut relabelled = migrated;
    relabelled.i.c = "email".to_owned();
    let result = String::decrypt_from(relabelled, &keyset).await;
    assert!(matches!(result, Err(Error::Aead)), "{:?}", result.err());
}

#[tokio::test]
async fn an_empty_column_is_refused_before_any_key_is_requested() {
    let (cipher, calls) = common::cipher().await;
    let keyset = cipher.default_keyset();

    let source = V3Plaintext {
        i: identifier("customers", ""),
        p: "alan@example.com".to_owned(),
    };
    let result = source.encrypt_into::<Shim<TextEq>, _>(&keyset).await;
    assert!(matches!(result, Err(Error::Other(_))));
    assert!(
        calls.lock().unwrap().generate.is_empty(),
        "no key was requested"
    );
}
