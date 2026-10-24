//! The EQL v4 date, timestamp and numeric types Stack Encrypt produces:
//! each family's storage-only type (`Date`, `Timestamp`, `Numeric`) and its
//! equality type (`DateEq`, `TimestampEq`, `NumericEq`), from the
//! plaintexts eql-bindings re-exports (`v4::plaintext`). Their ordered
//! types are covered with the other families' in `v4_order.rs` (OPE) and
//! `v4_ore_block.rs` (block ORE).
//!
//! Each type must round-trip through both entry points, seal the leaf a
//! chrono or rust_decimal value of the same instant, day or number seals
//! (what any other producer writes for that kind), open a leaf such a value
//! sealed, and refuse a value of another kind. The Go SDK's rows
//! (`fixtures/v4_ledger_rows.json`) open here and are queried in
//! PostgreSQL with the queries this file derives
//! (`fixtures/v4_ledger_queries.json`).

mod common;

use std::str::FromStr;

use chrono::{DateTime, NaiveDate, Utc};
use eql_bindings::encryption::targets::{self as targets, TargetError};
use eql_bindings::encryption::NativeCiphertextVisitor as NativeLeaf;
use eql_bindings::v3::terms::Ciphertext;
use eql_bindings::v4::plaintext::{Date, Decimal, Timestamp};
use eql_bindings::v4::{date, numeric, timestamp};
use eql_bindings::Identifier;
use serde::de::DeserializeOwned;
use stack_encrypt::dynamic::{ValueFrame, ValueKind};
use stack_encrypt::target::transcode::Reader;
use stack_encrypt::{Encrypt, Label, NonEmpty};

fn frame<T: Encrypt>(value: T) -> ValueFrame {
    ValueFrame::of(value).unwrap()
}

fn same(a: &ValueFrame, b: &ValueFrame) -> bool {
    a.risky_ref() == b.risky_ref()
}

fn column() -> NonEmpty<Identifier> {
    Identifier::for_column("profiles", "entry").unwrap()
}

fn label() -> Label {
    Label::new(["profiles", "entry"]).unwrap()
}

fn refused<T>(result: Result<T, TargetError>) -> TargetError {
    match result {
        Err(error) => error,
        Ok(_) => panic!("the dispatch accepted what it should have refused"),
    }
}

fn day(text: &str) -> NaiveDate {
    NaiveDate::from_str(text).unwrap()
}

fn instant(text: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(text).unwrap().to_utc()
}

fn number(text: &str) -> rust_decimal::Decimal {
    rust_decimal::Decimal::from_str(text).unwrap()
}

/// What a stored `c` opens to as a frame, without any EQL type: the leaf
/// as another producer would read it.
async fn as_frame(
    cipher: &stack_encrypt::StackCipher<common::Observed>,
    c: Ciphertext,
) -> ValueFrame {
    let native = c.read(NativeLeaf).unwrap();
    cipher.decrypt(native, column()).await.unwrap()
}

async fn by_name<T: DeserializeOwned>(
    keyset: &stack_encrypt::KeysetCipher<'_, common::Observed>,
    name: &str,
    value: ValueFrame,
) -> T {
    let bytes = targets::encrypt(name, keyset, &label(), value)
        .unwrap()
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// The `hm` of `name` over `value`, through the by-name query dispatch.
async fn hm(
    keyset: &stack_encrypt::KeysetCipher<'_, common::Observed>,
    name: &str,
    value: ValueFrame,
) -> String {
    let bytes = targets::query(name, &common::index_of(name), keyset, &label(), value)
        .unwrap()
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    json["hm"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn dates_round_trip_and_seal_the_leaf_a_naive_date_seals() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    for text in ["2024-02-29", "1969-12-31", "0001-01-01", "1970-01-01"] {
        let theirs = day(text);
        let value = Date::from(theirs);
        let stored: date::Date = keyset.encrypt_as(&value, column()).await.unwrap();
        let opened: Date = cipher
            .decrypt_as(stored.clone(), column().into())
            .await
            .unwrap();
        assert_eq!(NaiveDate::from(&opened), theirs, "{text}");
        assert!(
            same(&as_frame(&cipher, stored.c.clone()).await, &frame(theirs)),
            "{text}: the leaf a NaiveDate seals"
        );

        let searchable: date::DateEq = keyset.encrypt_as(&value, column()).await.unwrap();
        let named: date::DateEq = by_name(&keyset, "DateEq", frame(theirs)).await;
        assert_eq!(searchable.hm, named.hm, "{text}: one term on both paths");
        let opened = targets::decrypt(
            "DateEq",
            &cipher,
            &label(),
            &serde_json::to_vec(&named).unwrap(),
        )
        .unwrap()
        .await
        .unwrap();
        assert!(same(&opened, &frame(theirs)), "{text}: by name");
    }
    for edge in [NaiveDate::MIN, NaiveDate::MAX] {
        let stored: date::DateEq = keyset
            .encrypt_as(&Date::from(edge), column())
            .await
            .unwrap();
        let opened: Date = cipher.decrypt_as(stored, column().into()).await.unwrap();
        assert_eq!(NaiveDate::from(&opened), edge);
    }
}

#[tokio::test]
async fn timestamps_round_trip_to_the_nanosecond_and_seal_the_leaf_a_date_time_seals() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    for text in [
        "2024-02-29T12:34:56.123456789Z",
        "1969-12-31T23:59:59.999999999Z",
        "1970-01-01T00:00:00Z",
    ] {
        let theirs = instant(text);
        let value = Timestamp::try_from(theirs).unwrap();
        let stored: timestamp::Timestamp = keyset.encrypt_as(&value, column()).await.unwrap();
        let opened: Timestamp = cipher
            .decrypt_as(stored.clone(), column().into())
            .await
            .unwrap();
        assert_eq!(DateTime::<Utc>::from(&opened), theirs, "{text}");
        assert!(
            same(&as_frame(&cipher, stored.c.clone()).await, &frame(theirs)),
            "{text}: the leaf a DateTime<Utc> seals"
        );

        let searchable: timestamp::TimestampEq = keyset.encrypt_as(&value, column()).await.unwrap();
        let named: timestamp::TimestampEq = by_name(&keyset, "TimestampEq", frame(theirs)).await;
        assert_eq!(searchable.hm, named.hm, "{text}: one term on both paths");
        let opened: Timestamp = cipher
            .decrypt_as(searchable, column().into())
            .await
            .unwrap();
        assert_eq!(
            DateTime::<Utc>::from(&opened),
            theirs,
            "{text}: nanoseconds kept"
        );
    }
    for edge in [
        chrono::NaiveDateTime::MIN.and_utc(),
        chrono::NaiveDateTime::MAX.and_utc(),
    ] {
        let stored: timestamp::TimestampEq = keyset
            .encrypt_as(&Timestamp::try_from(edge).unwrap(), column())
            .await
            .unwrap();
        let opened: Timestamp = cipher.decrypt_as(stored, column().into()).await.unwrap();
        assert_eq!(DateTime::<Utc>::from(&opened), edge);
    }
}

#[tokio::test]
async fn decimals_round_trip_with_their_scale_and_seal_the_leaf_rust_decimal_seals() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    for text in [
        "1.50",
        "-1234.5678",
        "0.00",
        "79228162514264337593543950335",
        "-0.0000000000000000000000000001",
    ] {
        let theirs = number(text);
        let value = Decimal::from(theirs);
        let stored: numeric::Numeric = keyset.encrypt_as(&value, column()).await.unwrap();
        let opened: Decimal = cipher
            .decrypt_as(stored.clone(), column().into())
            .await
            .unwrap();
        assert_eq!(
            rust_decimal::Decimal::from(&opened).to_string(),
            text,
            "the scale is kept"
        );
        assert!(
            same(&as_frame(&cipher, stored.c.clone()).await, &frame(theirs)),
            "{text}: the leaf a rust_decimal Decimal seals"
        );

        let searchable: numeric::NumericEq = keyset.encrypt_as(&value, column()).await.unwrap();
        let named: numeric::NumericEq = by_name(&keyset, "NumericEq", frame(theirs)).await;
        assert_eq!(searchable.hm, named.hm, "{text}: one term on both paths");
        let opened = targets::decrypt(
            "NumericEq",
            &cipher,
            &label(),
            &serde_json::to_vec(&named).unwrap(),
        )
        .unwrap()
        .await
        .unwrap();
        assert!(same(&opened, &frame(theirs)), "{text}: by name");
    }
}

/// ADR-0002's baseline and vitaminc's equality encodings: a decimal's scale
/// is normalised, a timestamp is truncated to the microsecond, and distinct
/// values have distinct terms.
#[tokio::test]
async fn equality_terms_follow_the_baseline() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let n = |text: &str| frame(number(text));
    assert_eq!(
        hm(&keyset, "NumericEq", n("1.5")).await,
        hm(&keyset, "NumericEq", n("1.50")).await,
        "1.5 = 1.50"
    );
    assert_eq!(
        hm(&keyset, "NumericEq", n("0")).await,
        hm(&keyset, "NumericEq", n("-0.000")).await,
        "every zero is one value"
    );
    assert_ne!(
        hm(&keyset, "NumericEq", n("1.5")).await,
        hm(&keyset, "NumericEq", n("1.51")).await
    );
    assert_ne!(
        hm(&keyset, "NumericEq", n("1.5")).await,
        hm(&keyset, "NumericEq", n("-1.5")).await
    );

    let t = |text: &str| frame(instant(text));
    assert_eq!(
        hm(&keyset, "TimestampEq", t("2024-02-29T12:00:00.123456001Z")).await,
        hm(&keyset, "TimestampEq", t("2024-02-29T12:00:00.123456999Z")).await,
        "one microsecond, one term"
    );
    // Truncated, never rounded: the nanoseconds below the microsecond are
    // dropped, as the order term drops them. Before 1970 that is floor on
    // the count since the epoch.
    assert_eq!(
        hm(&keyset, "TimestampEq", t("2024-02-29T12:00:00.1234567Z")).await,
        hm(&keyset, "TimestampEq", t("2024-02-29T12:00:00.123456Z")).await,
        "truncated, not rounded"
    );
    assert_eq!(
        hm(&keyset, "TimestampEq", t("1969-12-31T23:59:59.9999995Z")).await,
        hm(&keyset, "TimestampEq", t("1969-12-31T23:59:59.999999Z")).await,
        "floor before the epoch"
    );
    assert_ne!(
        hm(&keyset, "TimestampEq", t("2024-02-29T12:00:00.123456Z")).await,
        hm(&keyset, "TimestampEq", t("2024-02-29T12:00:00.123457Z")).await
    );

    let d = |text: &str| frame(day(text));
    assert_ne!(
        hm(&keyset, "DateEq", d("2024-02-29")).await,
        hm(&keyset, "DateEq", d("2024-03-01")).await
    );
    // A date, an instant and a number are separate domains: the same
    // integer underneath is no match.
    assert_ne!(
        hm(
            &keyset,
            "DateEq",
            frame(Date::from_days_since_epoch(0).unwrap())
        )
        .await,
        hm(&keyset, "TimestampEq", frame(Timestamp::new(0, 0).unwrap())).await
    );
    assert_ne!(
        hm(
            &keyset,
            "DateEq",
            frame(Date::from_days_since_epoch(0).unwrap())
        )
        .await,
        hm(&keyset, "NumericEq", frame(Decimal::new(0, 0).unwrap())).await
    );
}

#[tokio::test]
async fn a_value_of_another_kind_is_refused_not_converted() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    for (name, value, expected) in [
        (
            "Date",
            frame(instant("2024-02-29T00:00:00Z")),
            ValueKind::Date,
        ),
        ("DateEq", frame::<i32>(19_782), ValueKind::Date),
        ("Timestamp", frame(day("2024-02-29")), ValueKind::Timestamp),
        ("TimestampEq", frame::<i64>(0), ValueKind::Timestamp),
        ("Numeric", frame::<f64>(1.5), ValueKind::Decimal),
        ("NumericEq", frame("1.50"), ValueKind::Decimal),
    ] {
        let error = refused(targets::encrypt(name, &keyset, &label(), value));
        assert!(
            matches!(error, TargetError::Plaintext { target, expected: e, .. } if target == name && e == expected),
            "{name}: {error}"
        );
    }

    // A stored date moved into a timestamp is not read as one.
    let stored: date::Date = keyset
        .encrypt_as(&Date::from(day("2024-02-29")), column())
        .await
        .unwrap();
    let moved = timestamp::Timestamp {
        v: stored.v,
        i: stored.i,
        c: stored.c,
    };
    let opened: Result<Timestamp, _> = cipher.decrypt_as(moved, column().into()).await;
    assert!(opened.is_err(), "a date is not a timestamp");
}

/// `fixtures/v4_ledger_queries.json`: the `DateEq`, `TimestampEq` and
/// `NumericEq` query operands the dispatch derives under
/// `FakeDataKeySource`'s index key, which the Go SDK's deterministic guest
/// shares. Its test derives the same queries through generated code and
/// requires the same bytes. Regenerate with `EQL_UPDATE_FIXTURES=1`.
#[tokio::test]
async fn the_ledger_query_fixture_is_what_the_dispatch_derives() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let query = |name: &'static str, column: &'static str, value: ValueFrame| {
        let keyset = &keyset;
        async move {
            let label = Label::new(["profiles", column]).unwrap();
            let bytes = targets::query(name, &common::index_of(name), keyset, &label, value)
                .unwrap()
                .await
                .unwrap();
            String::from_utf8(bytes).unwrap()
        }
    };
    let fixture = serde_json::json!({
        "_comment": "The DateEq, TimestampEq and NumericEq query operands eql-bindings derives for each plaintext under FakeDataKeySource's index key (keyset nil), read by the Go SDK's hermetic test; regenerate with EQL_UPDATE_FIXTURES=1, do not edit.",
        "table": "profiles",
        "due": {
            "plaintext": "2024-02-29",
            "query": query("DateEq", "due", frame(day("2024-02-29"))).await,
        },
        "posted": {
            "plaintext": "2024-02-29T12:34:56.123456Z",
            "query": query("TimestampEq", "posted", frame(instant("2024-02-29T12:34:56.123456Z"))).await,
        },
        "amount": {
            "plaintext": "1.50",
            "query": query("NumericEq", "amount", frame(number("1.50"))).await,
        },
    });
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/v4_ledger_queries.json");
    let rendered = serde_json::to_string_pretty(&fixture).unwrap() + "\n";
    if std::env::var_os("EQL_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &rendered).unwrap();
    }
    let committed = std::fs::read_to_string(&path)
        .expect("fixtures/v4_ledger_queries.json is committed; EQL_UPDATE_FIXTURES=1 writes it");
    assert_eq!(
        committed, rendered,
        "the committed fixture is what the dispatch derives today"
    );
}

fn database() -> postgres::Client {
    postgres::Client::connect(
        &std::env::var("EQL_TEST_DATABASE_URL").expect("EQL_TEST_DATABASE_URL"),
        postgres::NoTls,
    )
    .unwrap()
}

fn json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap()
}

/// Needs an EQL v4 installation. Rust-sealed values of each type pass their
/// domain check and read back, `=` on each equality column finds the rows
/// its query names (1.5 and 1.50 are one number; one microsecond is one
/// instant), and the storage-only columns refuse `=`.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_stores_and_finds_date_timestamp_and_numeric_rows() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = runtime.block_on(common::cipher());
    let keyset = cipher.default_keyset();
    let mut db = database();
    db.batch_execute(
        "CREATE TEMP TABLE v4_ledger (
            id int PRIMARY KEY,
            opened public.eql_v4_date,
            due public.eql_v4_date_eq,
            created public.eql_v4_timestamp,
            posted public.eql_v4_timestamp_eq,
            total public.eql_v4_numeric,
            amount public.eql_v4_numeric_eq
        );",
    )
    .unwrap();
    let rows = [
        (1, "2024-02-29", "2024-02-29T12:00:00.123456001Z", "1.5"),
        (
            2,
            "0001-01-01",
            "1969-12-31T23:59:59.999999999Z",
            "-79228162514264337593543950335",
        ),
        (3, "2024-02-29", "2024-02-29T12:00:00.123456999Z", "1.50"),
        (4, "2024-03-01", "2024-02-29T12:00:00.123457Z", "1.51"),
    ];
    for (id, d, t, n) in rows {
        let (opened, due, created, posted, total, amount) = runtime.block_on(async {
            let d = Date::from(day(d));
            let t = Timestamp::try_from(instant(t)).unwrap();
            let n = Decimal::from(number(n));
            (
                json(
                    &keyset
                        .encrypt_as::<_, date::Date>(&d, column())
                        .await
                        .unwrap(),
                ),
                json(
                    &keyset
                        .encrypt_as::<_, date::DateEq>(&d, column())
                        .await
                        .unwrap(),
                ),
                json(
                    &keyset
                        .encrypt_as::<_, timestamp::Timestamp>(&t, column())
                        .await
                        .unwrap(),
                ),
                json(
                    &keyset
                        .encrypt_as::<_, timestamp::TimestampEq>(&t, column())
                        .await
                        .unwrap(),
                ),
                json(
                    &keyset
                        .encrypt_as::<_, numeric::Numeric>(&n, column())
                        .await
                        .unwrap(),
                ),
                json(
                    &keyset
                        .encrypt_as::<_, numeric::NumericEq>(&n, column())
                        .await
                        .unwrap(),
                ),
            )
        });
        db.execute(
            "INSERT INTO v4_ledger VALUES ($1,
                $2::text::jsonb::public.eql_v4_date,
                $3::text::jsonb::public.eql_v4_date_eq,
                $4::text::jsonb::public.eql_v4_timestamp,
                $5::text::jsonb::public.eql_v4_timestamp_eq,
                $6::text::jsonb::public.eql_v4_numeric,
                $7::text::jsonb::public.eql_v4_numeric_eq)",
            &[&id, &opened, &due, &created, &posted, &total, &amount],
        )
        .unwrap();
    }
    let mut ids = |column_name: &str, query_domain: &str, query: String| -> Vec<i32> {
        db.query(
            &format!(
                "SELECT id FROM v4_ledger WHERE {column_name} = $1::text::jsonb::eql_v4.{query_domain} ORDER BY id"
            ),
            &[&query],
        )
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect()
    };
    let date_query = |text: &str| {
        let value = Date::from(day(text));
        runtime.block_on(async {
            json(
                &keyset
                    .encrypt_as::<_, date::DateEqQuery>(&value, column())
                    .await
                    .unwrap(),
            )
        })
    };
    let timestamp_query = |text: &str| {
        let value = Timestamp::try_from(instant(text)).unwrap();
        runtime.block_on(async {
            json(
                &keyset
                    .encrypt_as::<_, timestamp::TimestampEqQuery>(&value, column())
                    .await
                    .unwrap(),
            )
        })
    };
    let numeric_query = |text: &str| {
        let value = Decimal::from(number(text));
        runtime.block_on(async {
            json(
                &keyset
                    .encrypt_as::<_, numeric::NumericEqQuery>(&value, column())
                    .await
                    .unwrap(),
            )
        })
    };
    assert_eq!(
        ids("due", "query_date_eq", date_query("2024-02-29")),
        [1, 3]
    );
    assert_eq!(ids("due", "query_date_eq", date_query("0001-01-01")), [2]);
    assert_eq!(
        ids("due", "query_date_eq", date_query("2025-01-01")),
        Vec::<i32>::new()
    );
    assert_eq!(
        ids(
            "posted",
            "query_timestamp_eq",
            timestamp_query("2024-02-29T12:00:00.123456Z")
        ),
        [1, 3],
        "one microsecond is one instant"
    );
    assert_eq!(
        ids(
            "posted",
            "query_timestamp_eq",
            timestamp_query("2024-02-29T12:00:00.123457Z")
        ),
        [4]
    );
    assert_eq!(
        ids("amount", "query_numeric_eq", numeric_query("1.500")),
        [1, 3],
        "1.5 = 1.50 = 1.500"
    );
    assert_eq!(
        ids(
            "amount",
            "query_numeric_eq",
            numeric_query("-79228162514264337593543950335")
        ),
        [2]
    );

    // A stored value reads back and opens with its scale and nanoseconds.
    let row = db
        .query_one(
            "SELECT opened::text, created::text, total::text FROM v4_ledger WHERE id = 3",
            &[],
        )
        .unwrap();
    let (opened, created, total): (String, String, String) = (row.get(0), row.get(1), row.get(2));
    runtime.block_on(async {
        let opened: Date = cipher
            .decrypt_as(
                serde_json::from_str::<date::Date>(&opened).unwrap(),
                column().into(),
            )
            .await
            .unwrap();
        assert_eq!(NaiveDate::from(&opened), day("2024-02-29"));
        let created: Timestamp = cipher
            .decrypt_as(
                serde_json::from_str::<timestamp::Timestamp>(&created).unwrap(),
                column().into(),
            )
            .await
            .unwrap();
        assert_eq!(created.nanoseconds(), 123_456_999);
        let total: Decimal = cipher
            .decrypt_as(
                serde_json::from_str::<numeric::Numeric>(&total).unwrap(),
                column().into(),
            )
            .await
            .unwrap();
        assert_eq!(rust_decimal::Decimal::from(&total).to_string(), "1.50");
    });

    // The storage-only columns have no equality operator.
    for (column_name, domain) in [
        ("opened", "eql_v4_date"),
        ("created", "eql_v4_timestamp"),
        ("total", "eql_v4_numeric"),
    ] {
        let err = db
            .query(
                &format!("SELECT id FROM v4_ledger WHERE {column_name} = {column_name}"),
                &[],
            )
            .unwrap_err();
        let message = err.as_db_error().map(|e| e.message()).unwrap_or_default();
        assert!(
            message.contains(&format!("is not supported for public.{domain}")),
            "{column_name}: {message}"
        );
    }
}

/// `fixtures/v4_ledger_rows.json`: `Ledger` rows the Go SDK's generated code
/// sealed over the deterministic EQL guest
/// (`TestV4LedgerRowsMatchTheCommittedFixture` writes it).
mod go_ledger {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(serde::Deserialize)]
    pub struct Fixture {
        pub seed: String,
        pub table: String,
        pub rows: Vec<Row>,
    }
    #[derive(serde::Deserialize)]
    pub struct Row {
        pub id: i32,
        pub plaintext: Plain,
        pub stored: BTreeMap<String, serde_json::Value>,
    }
    /// Dates in ISO 8601, instants in RFC 3339 with nanoseconds, decimals
    /// as fixed-point text with their scale.
    #[derive(serde::Deserialize)]
    pub struct Plain {
        pub opened: String,
        pub due: String,
        pub created: String,
        pub posted: String,
        pub total: String,
        pub amount: String,
    }

    pub fn fixture() -> Fixture {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/v4_ledger_rows.json");
        let raw = std::fs::read_to_string(path).expect(
            "fixtures/v4_ledger_rows.json is written by the Go SDK's \
             TestV4LedgerRowsMatchTheCommittedFixture",
        );
        serde_json::from_str(&raw).unwrap()
    }

    pub async fn cipher(seed: &str) -> stack_encrypt::StackCipher<stack_kms::DeterministicSource> {
        let seed: [u8; 32] = seed.as_bytes().try_into().expect("a 32-byte seed");
        stack_encrypt::StackCipher::builder()
            .kms(stack_kms::DeterministicSource::new(seed))
            .init()
            .await
            .unwrap()
    }

    fn parsed<T: DeserializeOwned>(row: &Row, column: &str) -> T {
        serde_json::from_value(row.stored[column].clone())
            .unwrap_or_else(|e| panic!("row {} {column}: {e}", row.id))
    }

    /// Open every field of `row` as its v4 type, into eql-bindings'
    /// plaintexts, and check it against what Go sealed.
    pub async fn open_row(
        cipher: &stack_encrypt::StackCipher<stack_kms::DeterministicSource>,
        row: &Row,
    ) {
        let column = |name: &str| Identifier::for_column("profiles", name).unwrap();
        let p = &row.plaintext;
        let id = row.id;
        let opened: Date = cipher
            .decrypt_as(parsed::<date::Date>(row, "opened"), column("opened").into())
            .await
            .unwrap();
        assert_eq!(NaiveDate::from(&opened), day(&p.opened), "row {id} opened");
        let due: Date = cipher
            .decrypt_as(parsed::<date::DateEq>(row, "due"), column("due").into())
            .await
            .unwrap();
        assert_eq!(NaiveDate::from(&due), day(&p.due), "row {id} due");
        let created: Timestamp = cipher
            .decrypt_as(
                parsed::<timestamp::Timestamp>(row, "created"),
                column("created").into(),
            )
            .await
            .unwrap();
        assert_eq!(
            DateTime::<Utc>::from(&created),
            instant(&p.created),
            "row {id} created"
        );
        let posted: Timestamp = cipher
            .decrypt_as(
                parsed::<timestamp::TimestampEq>(row, "posted"),
                column("posted").into(),
            )
            .await
            .unwrap();
        assert_eq!(
            DateTime::<Utc>::from(&posted),
            instant(&p.posted),
            "row {id} posted"
        );
        let total: Decimal = cipher
            .decrypt_as(
                parsed::<numeric::Numeric>(row, "total"),
                column("total").into(),
            )
            .await
            .unwrap();
        assert_eq!(
            rust_decimal::Decimal::from(&total).to_string(),
            p.total,
            "row {id} total keeps its scale"
        );
        let amount: Decimal = cipher
            .decrypt_as(
                parsed::<numeric::NumericEq>(row, "amount"),
                column("amount").into(),
            )
            .await
            .unwrap();
        assert_eq!(
            rust_decimal::Decimal::from(&amount).to_string(),
            p.amount,
            "row {id} amount keeps its scale"
        );
    }
}

/// What the Go SDK sealed as the date, timestamp and numeric types parses as
/// each type and opens in Rust to the same day, instant and number.
#[tokio::test]
async fn ledger_rows_the_go_sdk_sealed_open_in_rust() {
    let fixture = go_ledger::fixture();
    assert_eq!(fixture.table, "profiles");
    assert!(fixture.rows.len() > 1);
    let cipher = go_ledger::cipher(&fixture.seed).await;
    for row in &fixture.rows {
        go_ledger::open_row(&cipher, row).await;
    }
}

/// The Go-sealed ledger rows in PostgreSQL: each value passes its domain
/// check, and `=` with this file's queries (which the Go SDK's test derives
/// byte for byte) finds the rows holding that day, microsecond and number.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_stores_and_queries_ledger_rows_the_go_sdk_sealed() {
    let fixture = go_ledger::fixture();
    let mut db = database();
    db.batch_execute(
        "CREATE TEMP TABLE go_ledgers (
            id int PRIMARY KEY,
            opened public.eql_v4_date,
            due public.eql_v4_date_eq,
            created public.eql_v4_timestamp,
            posted public.eql_v4_timestamp_eq,
            total public.eql_v4_numeric,
            amount public.eql_v4_numeric_eq
        );",
    )
    .unwrap();
    for row in &fixture.rows {
        let v = |column: &str| row.stored[column].to_string();
        db.execute(
            "INSERT INTO go_ledgers VALUES ($1,
                $2::text::jsonb::public.eql_v4_date,
                $3::text::jsonb::public.eql_v4_date_eq,
                $4::text::jsonb::public.eql_v4_timestamp,
                $5::text::jsonb::public.eql_v4_timestamp_eq,
                $6::text::jsonb::public.eql_v4_numeric,
                $7::text::jsonb::public.eql_v4_numeric_eq)",
            &[
                &row.id,
                &v("opened"),
                &v("due"),
                &v("created"),
                &v("posted"),
                &v("total"),
                &v("amount"),
            ],
        )
        .unwrap();
    }
    let queries: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("fixtures/v4_ledger_queries.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let plaintext = |key: &str| queries[key]["plaintext"].as_str().unwrap().to_owned();
    let due = day(&plaintext("due"));
    let posted = instant(&plaintext("posted")).timestamp_micros();
    let amount = number(&plaintext("amount")).normalize();
    for (column_name, query_domain, expected) in [
        (
            "due",
            "query_date_eq",
            fixture
                .rows
                .iter()
                .filter(|r| day(&r.plaintext.due) == due)
                .map(|r| r.id)
                .collect::<Vec<_>>(),
        ),
        (
            "posted",
            "query_timestamp_eq",
            fixture
                .rows
                .iter()
                .filter(|r| instant(&r.plaintext.posted).timestamp_micros() == posted)
                .map(|r| r.id)
                .collect(),
        ),
        (
            "amount",
            "query_numeric_eq",
            fixture
                .rows
                .iter()
                .filter(|r| number(&r.plaintext.amount).normalize() == amount)
                .map(|r| r.id)
                .collect(),
        ),
    ] {
        assert!(
            !expected.is_empty() && expected.len() < fixture.rows.len(),
            "{column_name}: the fixture splits the rows"
        );
        let key = column_name;
        let ids: Vec<i32> = db
            .query(
                &format!(
                    "SELECT id FROM go_ledgers WHERE {column_name} = $1::text::jsonb::eql_v4.{query_domain} ORDER BY id"
                ),
                &[&queries[key]["query"].as_str().unwrap()],
            )
            .unwrap()
            .iter()
            .map(|r| r.get(0))
            .collect();
        assert_eq!(ids, expected, "= over Go-sealed {column_name}");
    }
}

/// The length of the sealed leaf a stored `c` holds.
fn leaf_len(c: &Ciphertext) -> usize {
    match c.clone().read(NativeLeaf).unwrap() {
        stack_encrypt::CipherText::Single(leaf) => leaf.to_bytes().len(),
        _ => panic!("a stored c is one leaf"),
    }
}

/// A storage-only type stores an absent value (#1298): `None` seals as a
/// typed null as long as a value, so the column does not show which rows
/// are absent, and opens as `None`, on the typed path and by name. A value
/// sealed from `Some` is the leaf the plaintext alone seals, so each opens
/// the other's.
#[tokio::test]
async fn a_storage_only_type_stores_a_none_as_long_as_a_value() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let value = Date::from(day("2024-02-29"));

    let present: date::Date = keyset.encrypt_as(&value, column()).await.unwrap();
    let absent: date::Date = keyset.encrypt_as(&None::<Date>, column()).await.unwrap();
    assert_eq!(
        leaf_len(&absent.c),
        leaf_len(&present.c),
        "as long as a value"
    );
    let opened: Option<Date> = cipher
        .decrypt_as(absent.clone(), column().into())
        .await
        .unwrap();
    assert!(opened.is_none());
    let refused: Result<Date, _> = cipher.decrypt_as(absent.clone(), column().into()).await;
    assert!(refused.is_err(), "a None does not open as a value");

    let some: date::Date = keyset
        .encrypt_as(&Some(value.clone()), column())
        .await
        .unwrap();
    let opened: Date = cipher.decrypt_as(some, column().into()).await.unwrap();
    assert_eq!(
        NaiveDate::from(&opened),
        day("2024-02-29"),
        "Some seals the plaintext's own leaf"
    );
    let opened: Option<Date> = cipher.decrypt_as(present, column().into()).await.unwrap();
    assert_eq!(
        opened.as_ref().map(NaiveDate::from),
        Some(day("2024-02-29")),
        "and an Option opens a value"
    );

    let null = ValueFrame::from_bytes(&[0x00]).unwrap();
    let named: date::Date = by_name(&keyset, "Date", null.clone()).await;
    assert_eq!(leaf_len(&named.c), leaf_len(&absent.c), "by name too");
    let opened = targets::decrypt(
        "Date",
        &cipher,
        &label(),
        &serde_json::to_vec(&named).unwrap(),
    )
    .unwrap()
    .await
    .unwrap();
    assert!(same(&opened, &null), "opens as a null by name");

    // A type whose term is equality's stores a null with a null's term,
    // the one a query of a null derives (#1298); a type with an order term
    // has no null to store, since its term column would show it.
    let eq: date::DateEq = by_name(&keyset, "DateEq", null.clone()).await;
    let present_eq: date::DateEq = by_name(&keyset, "DateEq", frame(day("2024-02-29"))).await;
    assert_eq!(
        leaf_len(&eq.c),
        leaf_len(&present_eq.c),
        "as long as a value"
    );
    assert_ne!(eq.hm, present_eq.hm, "a null's term is no value's");
    assert_eq!(
        hm(&keyset, "DateEq", null.clone()).await,
        eq.hm.0,
        "a query of a null finds it"
    );
    let opened = targets::decrypt(
        "DateEq",
        &cipher,
        &label(),
        &serde_json::to_vec(&eq).unwrap(),
    )
    .unwrap()
    .await
    .unwrap();
    assert!(same(&opened, &null), "opens as a null");
    assert!(matches!(
        refused_null(&keyset, "IntegerOrd"),
        TargetError::Plaintext { .. }
    ));
}

fn refused_null(
    keyset: &stack_encrypt::KeysetCipher<'_, common::Observed>,
    name: &str,
) -> TargetError {
    let null = ValueFrame::from_bytes(&[0x00]).unwrap();
    refused(targets::encrypt(name, keyset, &label(), null))
}

/// Needs an EQL v4 installation. A storage-only column stores an absent
/// value sealed as a typed null (#1298): the domain's check takes it, as
/// it takes a value, and it reads back and opens as `None`.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_stores_a_sealed_null_in_a_storage_only_column() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = runtime.block_on(common::cipher());
    let keyset = cipher.default_keyset();
    let mut db = database();
    db.batch_execute(
        "CREATE TEMP TABLE v4_optional (
            id int PRIMARY KEY,
            entry public.eql_v4_date,
            due public.eql_v4_date_eq
        );",
    )
    .unwrap();
    let rows: Vec<(i32, Option<Date>)> = vec![
        (1, None),
        (2, Some(Date::from(day("2024-02-29")))),
        (3, None),
    ];
    for (id, value) in &rows {
        let (entry, due): (date::Date, date::DateEq) = runtime.block_on(async {
            (
                keyset.encrypt_as(value, column()).await.unwrap(),
                keyset.encrypt_as(value, column()).await.unwrap(),
            )
        });
        db.execute(
            "INSERT INTO v4_optional VALUES ($1,
                $2::text::jsonb::public.eql_v4_date,
                $3::text::jsonb::public.eql_v4_date_eq)",
            &[id, &json(&entry), &json(&due)],
        )
        .unwrap();
    }
    let stored: String = db
        .query_one(
            "SELECT entry::jsonb::text FROM v4_optional WHERE id = 1",
            &[],
        )
        .unwrap()
        .get(0);
    let stored: date::Date = serde_json::from_str(&stored).unwrap();
    let opened: Option<Date> = runtime
        .block_on(async { cipher.decrypt_as(stored, column().into()).await })
        .unwrap();
    assert!(opened.is_none(), "the stored null opens as None");

    // `=` with the query of a null finds the absent rows, and only them.
    let null_query: date::DateEqQuery = runtime
        .block_on(async { keyset.encrypt_as(&None::<Date>, column()).await })
        .unwrap();
    let found: Vec<i32> = db
        .query(
            "SELECT id FROM v4_optional WHERE due = $1::text::jsonb::eql_v4.query_date_eq ORDER BY id",
            &[&json(&null_query)],
        )
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(found, [1, 3]);
}
