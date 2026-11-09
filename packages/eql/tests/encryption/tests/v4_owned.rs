//! The EQL v4 types through Stack Encrypt's owned API: `EncryptTarget` and
//! `DecryptSource`, called as `value.encrypt_into_with_context(..)` and
//! `P::decrypt_from(..)`.
//!
//! The owned API must write what the structural API (`encrypt_as`,
//! `decrypt_as`) writes, because data written by either is stored in the
//! same columns and queried by the same terms. Every stored type and every
//! derived query type is checked:
//!
//! - every term in the payload is the same, because a term is derived without
//!   randomness. The ciphertext `c` differs, because it is sealed under a
//!   fresh nonce each time, so each path must open the other's instead;
//! - both null forms behave as before: a type over an `Option` seals a null,
//!   and an `Option` of a type stores nothing for `None` (a database NULL);
//! - a value is refused under another column before any key is requested.

mod common;

use std::str::FromStr;

use chrono::{DateTime, NaiveDate, Utc};
use eql_bindings::v4::plaintext::{
    Date as DateValue, Decimal as DecimalValue, Timestamp as TimestampValue,
};
use eql_bindings::v4::{
    bigint, boolean, date, double, integer, numeric, real, smallint, text, timestamp,
};
use eql_bindings::Identifier;
use serde::Serialize;
use stack_encrypt::sem::OreBlockTerm;
use stack_encrypt::{DecryptFrom, EncryptInto, NonEmpty};

fn column() -> NonEmpty<Identifier> {
    Identifier::for_column("users", "entry").unwrap()
}

fn other_column() -> NonEmpty<Identifier> {
    Identifier::for_column("users", "other").unwrap()
}

/// A stored payload without its ciphertext: the envelope and every term.
fn terms_of<T: Serialize>(stored: &T) -> serde_json::Value {
    let mut json = serde_json::to_value(stored).unwrap();
    let object = json.as_object_mut().unwrap();
    assert!(object.remove("c").is_some(), "a stored value carries `c`");
    json
}

/// The stored payloads of one value written twice: the same envelope and
/// the same terms.
///
/// A block ORE term (`ob`) is compared by the scheme, not by its bytes. Its
/// right half carries a random nonce, as the ciphertext does, so one value
/// gives different bytes each time, and two terms of one value order equal.
fn assert_same_terms<T: Serialize>(owned: &T, structural: &T, name: &str) {
    let mut owned = terms_of(owned);
    let mut structural = terms_of(structural);
    let ob = |json: &mut serde_json::Value| {
        json.as_object_mut()
            .unwrap()
            .remove("ob")
            .map(|ob| serde_json::from_value::<OreBlockTerm<String>>(ob).unwrap())
    };
    match (ob(&mut owned), ob(&mut structural)) {
        (Some(a), Some(b)) => assert!(a == b, "{name}: the block ORE terms order equal"),
        (None, None) => {}
        _ => panic!("{name}: only one path wrote a block ORE term"),
    }
    assert_eq!(
        owned, structural,
        "{name}: the owned API derives the terms the structural API does"
    );
}

fn date(text: &str) -> DateValue {
    DateValue::from(NaiveDate::from_str(text).unwrap())
}

fn timestamp(text: &str) -> TimestampValue {
    let instant: DateTime<Utc> = DateTime::parse_from_rfc3339(text).unwrap().to_utc();
    TimestampValue::try_from(instant).unwrap()
}

fn decimal(text: &str) -> DecimalValue {
    DecimalValue::from(rust_decimal::Decimal::from_str(text).unwrap())
}

/// A plaintext as a value that can be compared. The date, timestamp and
/// decimal plaintexts do not implement `PartialEq`, so they are compared as
/// the chrono and rust_decimal values they convert to.
trait Seen {
    type View: PartialEq + std::fmt::Debug;
    fn view(&self) -> Self::View;
}
macro_rules! seen_as_itself {
    ($($ty:ty),+) => {$(
        impl Seen for $ty {
            type View = $ty;
            fn view(&self) -> $ty {
                self.clone()
            }
        }
    )+};
}
seen_as_itself!(
    String,
    i16,
    i32,
    i64,
    f32,
    f64,
    bool,
    Option<String>,
    Option<i32>,
    Option<bool>
);
impl Seen for DateValue {
    type View = NaiveDate;
    fn view(&self) -> NaiveDate {
        NaiveDate::from(self)
    }
}
impl Seen for TimestampValue {
    type View = DateTime<Utc>;
    fn view(&self) -> DateTime<Utc> {
        DateTime::<Utc>::from(self)
    }
}
impl Seen for DecimalValue {
    type View = String;
    fn view(&self) -> String {
        rust_decimal::Decimal::from(self).to_string()
    }
}

/// Each stored type, written through both APIs from the same plaintext under
/// the same column: the same terms, and each ciphertext opens through the
/// other API.
macro_rules! stored_agrees {
    ($cipher:expr, $keyset:expr, $plaintext:ty, $value:expr, [$($ty:ty),+ $(,)?]) => {$({
        let value: $plaintext = $value;
        let structural: $ty = $keyset.encrypt_as(&value, column()).await.unwrap();
        let owned: $ty = value
            .clone()
            .encrypt_into_with_context(&$keyset, column())
            .await
            .unwrap();
        assert_same_terms(&owned, &structural, stringify!($ty));

        let opened = <$plaintext>::decrypt_from(structural, &$keyset).await.unwrap();
        assert_eq!(opened.view(), value.view(), "{}: the owned API opens structural output", stringify!($ty));
        let opened: $plaintext = $cipher
            .decrypt_as(owned.clone(), column().into())
            .await
            .unwrap();
        assert_eq!(opened.view(), value.view(), "{}: the structural API opens owned output", stringify!($ty));
        let opened = <$plaintext>::decrypt_from_with_context(owned, &$keyset, column())
            .await
            .unwrap();
        assert_eq!(opened.view(), value.view(), "{}: the stored column is the one expected", stringify!($ty));
    })+};
}

/// Each query type, built through both APIs: the same operand. A query
/// operand carries no ciphertext, so the whole payload must match.
macro_rules! query_agrees {
    ($keyset:expr, $plaintext:ty, $value:expr, [$($ty:ty),+ $(,)?]) => {$({
        let value: $plaintext = $value;
        let structural: $ty = $keyset.encrypt_as(&value, column()).await.unwrap();
        let owned: $ty = value
            .clone()
            .encrypt_into_with_context(&$keyset, column())
            .await
            .unwrap();
        assert_eq!(
            owned,
            structural,
            "{}: the owned API builds the operand the structural API does",
            stringify!($ty)
        );
    })+};
}

mod every_stored_type {
    use super::*;

    #[tokio::test]
    async fn text() {
        let (cipher, _) = common::cipher().await;
        let keyset = cipher.default_keyset();
        use text::*;
        stored_agrees!(
            cipher,
            keyset,
            String,
            "Ada Lovelace".to_owned(),
            [
                Text,
                TextEq,
                TextMatch,
                TextOrdOre,
                TextOrd,
                TextOrdOpe,
                TextSearchOre,
                TextSearch
            ]
        );
    }

    #[tokio::test]
    async fn integers() {
        let (cipher, _) = common::cipher().await;
        let keyset = cipher.default_keyset();
        {
            use integer::*;
            stored_agrees!(
                cipher,
                keyset,
                i32,
                -42,
                [Integer, IntegerEq, IntegerOrdOre, IntegerOrd, IntegerOrdOpe]
            );
        }
        {
            use smallint::*;
            stored_agrees!(
                cipher,
                keyset,
                i16,
                7,
                [
                    Smallint,
                    SmallintEq,
                    SmallintOrdOre,
                    SmallintOrd,
                    SmallintOrdOpe
                ]
            );
        }
        {
            use bigint::*;
            stored_agrees!(
                cipher,
                keyset,
                i64,
                1 << 40,
                [Bigint, BigintEq, BigintOrdOre, BigintOrd, BigintOrdOpe]
            );
        }
    }

    #[tokio::test]
    async fn floats_and_booleans() {
        let (cipher, _) = common::cipher().await;
        let keyset = cipher.default_keyset();
        {
            use double::*;
            stored_agrees!(
                cipher,
                keyset,
                f64,
                -2.5,
                [Double, DoubleEq, DoubleOrdOre, DoubleOrd, DoubleOrdOpe]
            );
        }
        {
            use real::*;
            stored_agrees!(
                cipher,
                keyset,
                f32,
                0.25,
                [Real, RealEq, RealOrdOre, RealOrd, RealOrdOpe]
            );
        }
        stored_agrees!(cipher, keyset, bool, true, [boolean::Boolean]);
    }

    #[tokio::test]
    async fn dates_timestamps_and_decimals() {
        let (cipher, _) = common::cipher().await;
        let keyset = cipher.default_keyset();
        {
            use date::*;
            stored_agrees!(
                cipher,
                keyset,
                DateValue,
                date("2024-02-29"),
                [Date, DateEq, DateOrdOre, DateOrd, DateOrdOpe]
            );
        }
        {
            use timestamp::*;
            stored_agrees!(
                cipher,
                keyset,
                TimestampValue,
                timestamp("2024-02-29T12:34:56.123456789Z"),
                [
                    Timestamp,
                    TimestampEq,
                    TimestampOrdOre,
                    TimestampOrd,
                    TimestampOrdOpe
                ]
            );
        }
        {
            use numeric::*;
            stored_agrees!(
                cipher,
                keyset,
                DecimalValue,
                decimal("-1234.5600"),
                [Numeric, NumericEq, NumericOrdOre, NumericOrd, NumericOrdOpe]
            );
        }
    }
}

mod every_query_type {
    use super::*;

    #[tokio::test]
    async fn text() {
        let (cipher, _) = common::cipher().await;
        let keyset = cipher.default_keyset();
        use text::*;
        query_agrees!(
            keyset,
            String,
            "Ada Lovelace".to_owned(),
            [
                TextEqQuery,
                TextMatchQuery,
                TextOrdOreQuery,
                TextOrdQuery,
                TextOrdOpeQuery,
                TextSearchOreEqualityQuery,
                TextSearchOreOrderQuery,
                TextSearchOreMatchQuery,
                TextSearchEqualityQuery,
                TextSearchOrderQuery,
                TextSearchMatchQuery,
            ]
        );
    }

    #[tokio::test]
    async fn numbers() {
        let (cipher, _) = common::cipher().await;
        let keyset = cipher.default_keyset();
        {
            use integer::*;
            query_agrees!(
                keyset,
                i32,
                -42,
                [
                    IntegerEqQuery,
                    IntegerOrdOreQuery,
                    IntegerOrdQuery,
                    IntegerOrdOpeQuery
                ]
            );
        }
        {
            use smallint::*;
            query_agrees!(
                keyset,
                i16,
                7,
                [
                    SmallintEqQuery,
                    SmallintOrdOreQuery,
                    SmallintOrdQuery,
                    SmallintOrdOpeQuery
                ]
            );
        }
        {
            use bigint::*;
            query_agrees!(
                keyset,
                i64,
                1 << 40,
                [
                    BigintEqQuery,
                    BigintOrdOreQuery,
                    BigintOrdQuery,
                    BigintOrdOpeQuery
                ]
            );
        }
        {
            use double::*;
            query_agrees!(
                keyset,
                f64,
                -2.5,
                [
                    DoubleEqQuery,
                    DoubleOrdOreQuery,
                    DoubleOrdQuery,
                    DoubleOrdOpeQuery
                ]
            );
        }
        {
            use real::*;
            query_agrees!(
                keyset,
                f32,
                0.25,
                [RealEqQuery, RealOrdOreQuery, RealOrdQuery, RealOrdOpeQuery]
            );
        }
    }

    #[tokio::test]
    async fn dates_timestamps_and_decimals() {
        let (cipher, _) = common::cipher().await;
        let keyset = cipher.default_keyset();
        {
            use date::*;
            query_agrees!(
                keyset,
                DateValue,
                date("2024-02-29"),
                [DateEqQuery, DateOrdOreQuery, DateOrdQuery, DateOrdOpeQuery]
            );
        }
        {
            use timestamp::*;
            query_agrees!(
                keyset,
                TimestampValue,
                timestamp("2024-02-29T12:34:56.123456789Z"),
                [
                    TimestampEqQuery,
                    TimestampOrdOreQuery,
                    TimestampOrdQuery,
                    TimestampOrdOpeQuery
                ]
            );
        }
        {
            use numeric::*;
            query_agrees!(
                keyset,
                DecimalValue,
                decimal("-1234.5600"),
                [
                    NumericEqQuery,
                    NumericOrdOreQuery,
                    NumericOrdQuery,
                    NumericOrdOpeQuery
                ]
            );
        }
    }
}

mod a_null {
    use super::*;

    // A type over an `Option` seals a null: a stored value, under a key,
    // with the terms a null has.
    #[tokio::test]
    async fn sealed_by_a_type_over_an_option_matches_the_structural_api() {
        let (cipher, _) = common::cipher().await;
        let keyset = cipher.default_keyset();
        stored_agrees!(
            cipher,
            keyset,
            Option<String>,
            None,
            [text::Text, text::TextEq]
        );
        stored_agrees!(
            cipher,
            keyset,
            Option<i32>,
            None,
            [integer::Integer, integer::IntegerEq]
        );
        stored_agrees!(cipher, keyset, Option<bool>, None, [boolean::Boolean]);
        query_agrees!(keyset, Option<String>, None, [text::TextEqQuery]);
        query_agrees!(keyset, Option<i32>, None, [integer::IntegerEqQuery]);
    }

    // An `Option` of a type stores nothing for `None`: the column is NULL.
    #[tokio::test]
    async fn as_an_option_of_a_type_is_a_database_null() {
        let (cipher, calls) = common::cipher().await;
        let keyset = cipher.default_keyset();

        let absent: Option<text::TextEq> = None::<String>
            .encrypt_into_with_context(&keyset, column())
            .await
            .unwrap();
        assert!(absent.is_none());
        assert!(
            calls.lock().unwrap().generate.is_empty(),
            "a NULL needs no key"
        );
        assert_eq!(
            Option::<String>::decrypt_from(absent, &keyset)
                .await
                .unwrap(),
            None
        );
        assert!(
            calls.lock().unwrap().retrieve.is_empty(),
            "a NULL needs no key"
        );

        // A present value is the type alone, with the terms of the value.
        let present: Option<text::TextEq> = Some("ada@example.com".to_owned())
            .encrypt_into_with_context(&keyset, column())
            .await
            .unwrap();
        let plain: text::TextEq = "ada@example.com"
            .to_owned()
            .encrypt_into_with_context(&keyset, column())
            .await
            .unwrap();
        assert_same_terms(present.as_ref().unwrap(), &plain, "Option<TextEq>");
        assert_eq!(
            Option::<String>::decrypt_from(present, &keyset)
                .await
                .unwrap(),
            Some("ada@example.com".to_owned())
        );
    }
}

#[tokio::test]
async fn a_value_is_refused_under_another_column_before_any_key_is_requested() {
    let (cipher, calls) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let stored: text::TextEq = "ada@example.com"
        .to_owned()
        .encrypt_into_with_context(&keyset, column())
        .await
        .unwrap();

    let result = String::decrypt_from_with_context(stored, &keyset, other_column()).await;
    assert!(result.is_err(), "a value from another column is refused");
    assert!(
        calls.lock().unwrap().retrieve.is_empty(),
        "the column is checked before any key is requested"
    );
}
