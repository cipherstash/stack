//! A migration shim: an EQL v4 type encrypted from a value that carries its
//! own column, with no context argument.
//!
//! Moving EQL v3 data to v4 decrypts each v3 value and encrypts it again as
//! v4. The decrypted value arrives with the column it was stored in, `i`, so
//! the shim takes the context from there (`Encryption::context_from`) and the
//! value from `p`. Renaming the column is an edit to `i` before the call.
//!
//! One generic impl covers every v4 type whose context is its column. What
//! it writes must be the v4 type itself, byte for byte where bytes are
//! deterministic: a query built the usual way finds it, and it opens as the
//! original plaintext.

mod common;

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
    // The column is not secret.
    fn zeroize(&mut self) {
        self.p.zeroize();
    }
}

/// A v4 type, encrypted from a v3 plaintext under the column it carries.
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
            .context_from(|source| {
                NonEmpty::new(source.i.clone()).map_err(|e| Error::Other(Box::new(e)))
            })
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

    // A block ORE term carries a nonce, so it is compared by order.
    let query: IntegerOrdOreQuery = 41_i32
        .encrypt_into_with_context(&keyset, column("customers", "age"))
        .await
        .unwrap();
    assert!(
        migrated.ob == query.ob,
        "the query orders equal to the migrated value"
    );

    let opened = i32::decrypt_from(migrated, &keyset).await.unwrap();
    assert_eq!(opened, 41);
}

#[tokio::test]
async fn a_renamed_column_is_the_column_the_value_is_stored_under() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();

    let mut source = V3Plaintext {
        i: identifier("customers", "email"),
        p: "alan@example.com".to_owned(),
    };
    source.i.c = "contact_email".to_owned();
    let Shim(migrated): Shim<TextEq> = source.encrypt_into(&keyset).await.unwrap();

    assert_eq!(migrated.i.c, "contact_email");
    let renamed: TextEqQuery = "alan@example.com"
        .to_owned()
        .encrypt_into_with_context(&keyset, column("customers", "contact_email"))
        .await
        .unwrap();
    let original: TextEqQuery = "alan@example.com"
        .to_owned()
        .encrypt_into_with_context(&keyset, column("customers", "email"))
        .await
        .unwrap();
    assert_eq!(migrated.hm, renamed.hm, "the new column's query finds it");
    assert_ne!(migrated.hm, original.hm, "the old column's query does not");

    assert!(
        String::decrypt_from_with_context(migrated, &keyset, column("customers", "email"))
            .await
            .is_err(),
        "it does not open as the old column"
    );
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
