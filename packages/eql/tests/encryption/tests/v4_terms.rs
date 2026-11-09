//! Known answers for the terms that every EQL v4 type writes.
//!
//! A term is derived without randomness. The same plaintext, column, and index
//! key give the same bytes every time. `FakeDataKeySource` has a fixed index
//! key, so `fixtures/v4_terms.json` records the envelope and every term of
//! every type.
//!
//! A change to any of these bytes is a change to the stored format. After such
//! a change, a new query no longer finds the rows written before it.
//!
//! The fixture contains the output of the structural API (`encrypt_as`). This
//! test writes through the owned API (`encrypt_into_with_context`). So the test
//! also checks that the owned API writes what the structural API wrote.
//!
//! The test leaves out two fields. Each contains a random nonce, so its bytes
//! differ every time:
//!
//! - the ciphertext `c`. `v4_owned.rs` checks it by opening it.
//! - the block ORE (order-revealing encryption) term `ob`. `v4_owned.rs` and
//!   the Postgres suites compare it by order.
//!
//! Regenerate the fixture only for an intended change to the stored format.
//! Set `EQL_UPDATE_V4_TERMS=1`, exactly `1`, and add a changeset on
//! `@cipherstash/eql` that says what breaks. Do not edit the fixture by hand.

mod common;

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::str::FromStr;

use chrono::{DateTime, NaiveDate, Utc};
use eql_bindings::v4::plaintext::{
    Date as DateValue, Decimal as DecimalValue, Timestamp as TimestampValue,
};
use eql_bindings::v4::{
    bigint, boolean, date, double, integer, numeric, real, smallint, text, timestamp,
};
use eql_bindings::Identifier;
use serde_json::Value;
use stack_encrypt::{EncryptInto, NonEmpty};

fn column() -> NonEmpty<Identifier> {
    Identifier::for_column("users", "entry").unwrap()
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

/// The payload as JSON, without the two fields that contain a nonce.
fn pinned_part<T: serde::Serialize>(value: &T) -> Value {
    let mut json = serde_json::to_value(value).unwrap();
    let object = json.as_object_mut().unwrap();
    object.remove("c");
    object.remove("ob");
    json
}

/// One value of the plaintext type, encrypted into `$ty` under `column()`.
macro_rules! encrypt {
    ($keyset:expr, $value:expr, $ty:ty) => {{
        let out: $ty = $value
            .clone()
            .encrypt_into_with_context(&$keyset, column())
            .await
            .unwrap();
        out
    }};
}

/// Records each type's payload under its name, or under `<name>/null` for a
/// sealed null.
macro_rules! record {
    ($out:ident, $keyset:expr, $suffix:literal, $value:expr, [$($ty:ident),+ $(,)?]) => {$({
        let out = encrypt!($keyset, $value, $ty);
        $out.insert(format!("{}{}", stringify!($ty), $suffix), pinned_part(&out));
    })+};
    // A query projection, recorded as the query type it converts into.
    ($out:ident, $keyset:expr, $value:expr, [$($projection:ident => $twin:ident),+ $(,)?]) => {$({
        let out = encrypt!($keyset, $value, $projection);
        let twin: $twin = out.into();
        $out.insert(stringify!($projection).to_owned(), pinned_part(&twin));
    })+};
}

async fn every_payload() -> BTreeMap<String, Value> {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let mut out = BTreeMap::new();
    {
        use text::*;
        let value = "Ada Lovelace".to_owned();
        record!(
            out,
            keyset,
            "",
            value,
            [
                Text,
                TextEq,
                TextMatch,
                TextOrdOre,
                TextOrd,
                TextOrdOpe,
                TextSearchOre,
                TextSearch,
                TextEqQuery,
                TextMatchQuery,
                TextOrdOreQuery,
                TextOrdQuery,
                TextOrdOpeQuery,
            ]
        );
        record!(out, keyset, value, [
            TextSearchOreEqualityQuery => TextSearchOreQuery,
            TextSearchOreOrderQuery => TextSearchOreQuery,
            TextSearchOreMatchQuery => TextSearchOreQuery,
            TextSearchEqualityQuery => TextSearchQuery,
            TextSearchOrderQuery => TextSearchQuery,
            TextSearchMatchQuery => TextSearchQuery,
        ]);
        record!(
            out,
            keyset,
            "/null",
            None::<String>,
            [Text, TextEq, TextEqQuery]
        );
    }
    {
        use integer::*;
        record!(
            out,
            keyset,
            "",
            -42_i32,
            [
                Integer,
                IntegerEq,
                IntegerOrdOre,
                IntegerOrd,
                IntegerOrdOpe,
                IntegerEqQuery,
                IntegerOrdOreQuery,
                IntegerOrdQuery,
                IntegerOrdOpeQuery,
            ]
        );
        record!(
            out,
            keyset,
            "/null",
            None::<i32>,
            [Integer, IntegerEq, IntegerEqQuery]
        );
    }
    {
        use smallint::*;
        record!(
            out,
            keyset,
            "",
            7_i16,
            [
                Smallint,
                SmallintEq,
                SmallintOrdOre,
                SmallintOrd,
                SmallintOrdOpe,
                SmallintEqQuery,
                SmallintOrdOreQuery,
                SmallintOrdQuery,
                SmallintOrdOpeQuery,
            ]
        );
        record!(
            out,
            keyset,
            "/null",
            None::<i16>,
            [Smallint, SmallintEq, SmallintEqQuery]
        );
    }
    {
        use bigint::*;
        record!(
            out,
            keyset,
            "",
            1_i64 << 40,
            [
                Bigint,
                BigintEq,
                BigintOrdOre,
                BigintOrd,
                BigintOrdOpe,
                BigintEqQuery,
                BigintOrdOreQuery,
                BigintOrdQuery,
                BigintOrdOpeQuery,
            ]
        );
        record!(
            out,
            keyset,
            "/null",
            None::<i64>,
            [Bigint, BigintEq, BigintEqQuery]
        );
    }
    {
        use double::*;
        record!(
            out,
            keyset,
            "",
            -2.5_f64,
            [
                Double,
                DoubleEq,
                DoubleOrdOre,
                DoubleOrd,
                DoubleOrdOpe,
                DoubleEqQuery,
                DoubleOrdOreQuery,
                DoubleOrdQuery,
                DoubleOrdOpeQuery,
            ]
        );
        record!(
            out,
            keyset,
            "/null",
            None::<f64>,
            [Double, DoubleEq, DoubleEqQuery]
        );
    }
    {
        use real::*;
        record!(
            out,
            keyset,
            "",
            0.25_f32,
            [
                Real,
                RealEq,
                RealOrdOre,
                RealOrd,
                RealOrdOpe,
                RealEqQuery,
                RealOrdOreQuery,
                RealOrdQuery,
                RealOrdOpeQuery,
            ]
        );
        record!(
            out,
            keyset,
            "/null",
            None::<f32>,
            [Real, RealEq, RealEqQuery]
        );
    }
    {
        use boolean::*;
        record!(out, keyset, "", true, [Boolean]);
        record!(out, keyset, "/null", None::<bool>, [Boolean]);
    }
    {
        use date::*;
        record!(
            out,
            keyset,
            "",
            date("2024-02-29"),
            [
                Date,
                DateEq,
                DateOrdOre,
                DateOrd,
                DateOrdOpe,
                DateEqQuery,
                DateOrdOreQuery,
                DateOrdQuery,
                DateOrdOpeQuery,
            ]
        );
        record!(
            out,
            keyset,
            "/null",
            None::<DateValue>,
            [Date, DateEq, DateEqQuery]
        );
    }
    {
        use timestamp::*;
        record!(
            out,
            keyset,
            "",
            timestamp("2024-02-29T12:34:56.123456789Z"),
            [
                Timestamp,
                TimestampEq,
                TimestampOrdOre,
                TimestampOrd,
                TimestampOrdOpe,
                TimestampEqQuery,
                TimestampOrdOreQuery,
                TimestampOrdQuery,
                TimestampOrdOpeQuery,
            ]
        );
        record!(
            out,
            keyset,
            "/null",
            None::<TimestampValue>,
            [Timestamp, TimestampEq, TimestampEqQuery,]
        );
    }
    {
        use numeric::*;
        record!(
            out,
            keyset,
            "",
            decimal("-1234.5600"),
            [
                Numeric,
                NumericEq,
                NumericOrdOre,
                NumericOrd,
                NumericOrdOpe,
                NumericEqQuery,
                NumericOrdOreQuery,
                NumericOrdQuery,
                NumericOrdOpeQuery,
            ]
        );
        record!(
            out,
            keyset,
            "/null",
            None::<DecimalValue>,
            [Numeric, NumericEq, NumericEqQuery]
        );
    }
    out
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/v4_terms.json")
}

/// Only `EQL_UPDATE_V4_TERMS=1` rewrites the fixture. A rewrite hides a real
/// change to the stored format, so any other value, `0` included, does not.
fn update_requested(value: Option<&OsStr>) -> bool {
    value == Some(OsStr::new("1"))
}

#[test]
fn only_exactly_one_requests_an_update() {
    assert!(update_requested(Some(OsStr::new("1"))));
    for value in ["0", "true", "yes", "", " 1"] {
        assert!(!update_requested(Some(OsStr::new(value))), "{value:?}");
    }
    assert!(!update_requested(None));
}

#[tokio::test]
async fn every_type_writes_its_pinned_terms() {
    let actual = every_payload().await;
    if update_requested(std::env::var_os("EQL_UPDATE_V4_TERMS").as_deref()) {
        let mut text = serde_json::to_string_pretty(&actual).unwrap();
        text.push('\n');
        std::fs::write(fixture_path(), text).unwrap();
        return;
    }
    let pinned: BTreeMap<String, Value> =
        serde_json::from_str(&std::fs::read_to_string(fixture_path()).unwrap()).unwrap();

    let missing: Vec<_> = pinned.keys().filter(|k| !actual.contains_key(*k)).collect();
    let unpinned: Vec<_> = actual.keys().filter(|k| !pinned.contains_key(*k)).collect();
    assert!(
        missing.is_empty() && unpinned.is_empty(),
        "the fixture and the types disagree: not written {missing:?}, not pinned {unpinned:?}"
    );
    let changed: Vec<_> = pinned
        .iter()
        .filter(|(name, terms)| actual[*name] != **terms)
        .map(|(name, _)| name)
        .collect();
    assert!(
        changed.is_empty(),
        "these types no longer write their pinned terms, which changes the stored format: \
         {changed:?}"
    );
}
