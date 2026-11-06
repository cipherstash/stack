//! The block ORE EQL v4 types Stack Encrypt produces: `IntegerOrdOre`,
//! `SmallintOrdOre`, `BigintOrdOre`, `RealOrdOre`, `DoubleOrdOre`,
//! `DateOrdOre`, `TimestampOrdOre`, `NumericOrdOre`, `TextOrdOre` and
//! `TextSearchOre`, and EQL v4's comparator for their `ob` term.
//!
//! The term is ore-rs's 6-bit block ORE: the fixed-width scheme (wire
//! header `02 02`) for the integers, floats and dates, the chained scheme
//! (`02 03`) for timestamps, decimals and text, text padded to a
//! power-of-two length bucket of at least 16 bytes. Every term carries a random nonce, so the stored bytes differ on
//! each write and only the comparator orders them.
//!
//! Against an EQL v4 database these tests compare pairs of real ore-rs
//! ciphertexts with `eql_v4_internal.compare_ore_block_v2_term`, both ways
//! round, and require the answer to be the plaintext order and ore-rs's own
//! comparator's: equal values, a first difference in every block, shared
//! prefixes, and text in different padding buckets. They check the hash bit
//! against ore.rs's vectors, that malformed and mismatched terms raise, that
//! EQL admits the block counts ore-rs does up to 1366 blocks (the longest
//! term Stack Encrypt writes) and none past it, that the domains answer
//! `<`, `=` and `ORDER BY` through a btree index, and that a domain's CHECK
//! takes an order term only as one hex string with its scheme's prefix.
//!
//! An `ob` term is one hex string on the wire, the whole ore-rs ciphertext,
//! and the bindings hold it as Stack Encrypt's `OreBlockTerm`, which refuses
//! anything else when the payload is read.

mod common;

use std::cmp::Ordering;

use eql_bindings::encryption::targets;
use stack_encrypt::dynamic::ValueFrame;
use stack_encrypt::sem::{Orderable, OreBlockTerm};
use stack_encrypt::value::{Date, Decimal, Timestamp};
use stack_encrypt::{Encrypt, Label};

type Keyset<'a> = stack_encrypt::KeysetCipher<'a, common::Observed>;

fn frame<T: Encrypt>(value: T) -> ValueFrame {
    ValueFrame::of(value).unwrap()
}

fn label() -> Label {
    Label::new(["rankings", "level"]).unwrap()
}

fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The stored JSON the named type writes for `value`.
async fn stored(keyset: &Keyset<'_>, name: &str, value: ValueFrame) -> serde_json::Value {
    let bytes = targets::encrypt(name, keyset, &label(), value)
        .unwrap()
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// The block ORE term the named type stores for `value`, as bytes: one hex
/// string, the whole ore-rs ciphertext.
async fn ob(keyset: &Keyset<'_>, name: &str, value: ValueFrame) -> Vec<u8> {
    let json = stored(keyset, name, value).await;
    unhex(json["ob"].as_str().expect("ob is one hex string"))
}

/// The terms of `values`, two writes each: the second write of a value is
/// a different ciphertext of the same plaintext.
async fn terms<T: Encrypt + Copy>(keyset: &Keyset<'_>, name: &str, values: &[T]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for value in values {
        out.push(ob(keyset, name, frame(*value)).await);
        out.push(ob(keyset, name, frame(*value)).await);
    }
    out
}

async fn text_terms(keyset: &Keyset<'_>, name: &str, values: &[&str]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for value in values {
        out.push(ob(keyset, name, frame(*value)).await);
        out.push(ob(keyset, name, frame(*value)).await);
    }
    out
}

/// ore-rs's own comparator over two terms.
fn rust_cmp<T: Orderable>(a: &[u8], b: &[u8]) -> Ordering {
    let a = OreBlockTerm::<T>::try_from(a).unwrap();
    let b = OreBlockTerm::<T>::try_from(b).unwrap();
    a.compare(&b).expect("terms of one index compare")
}

#[tokio::test]
async fn each_type_stores_one_block_ore_term_of_its_scheme() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    for (name, value, header, keys) in [
        (
            "IntegerOrdOre",
            frame(7i32),
            [2u8, 2],
            &["c", "i", "ob", "v"][..],
        ),
        (
            "SmallintOrdOre",
            frame(7i16),
            [2, 2],
            &["c", "i", "ob", "v"],
        ),
        ("BigintOrdOre", frame(7i64), [2, 2], &["c", "i", "ob", "v"]),
        ("RealOrdOre", frame(7.0f32), [2, 2], &["c", "i", "ob", "v"]),
        (
            "DoubleOrdOre",
            frame(7.0f64),
            [2, 2],
            &["c", "i", "ob", "v"],
        ),
        (
            "DateOrdOre",
            frame(Date::from_days_since_epoch(7).unwrap()),
            [2, 2],
            &["c", "i", "ob", "v"],
        ),
        (
            "TimestampOrdOre",
            frame(Timestamp::new(7, 8).unwrap()),
            [2, 3],
            &["c", "i", "ob", "v"],
        ),
        (
            "NumericOrdOre",
            frame(Decimal::new(750, 2).unwrap()),
            [2, 3],
            &["c", "i", "ob", "v"],
        ),
        (
            "TextOrdOre",
            frame("alice"),
            [2, 3],
            &["c", "hm", "i", "ob", "v"],
        ),
        (
            "TextSearchOre",
            frame("alice"),
            [2, 3],
            &["bf", "c", "hm", "i", "ob", "v"],
        ),
    ] {
        let json = stored(&keyset, name, value).await;
        let mut found: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        found.sort_unstable();
        assert_eq!(found, keys, "{name}");
        let term = unhex(json["ob"].as_str().unwrap());
        assert_eq!(term[..2], header, "{name}: the scheme's wire header");
    }
}

/// A v4 type reads an order term only as one hex string of its scheme:
/// the value Stack Encrypt writes reads back and writes out unchanged, and
/// an EQL v3 array, a term of the other scheme, a truncated term and text
/// that is not hex are refused when the payload is read. No error repeats
/// the term.
#[tokio::test]
async fn a_v4_type_reads_an_order_term_only_as_its_hex_string() {
    use eql_bindings::v4::integer::{IntegerOrd, IntegerOrdOre};
    use serde_json::{json, Value};
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let ore = stored(&keyset, "IntegerOrdOre", frame(7i32)).await;
    let ope = stored(&keyset, "IntegerOrd", frame(7i32)).await;
    let read: IntegerOrdOre = serde_json::from_value(ore.clone()).unwrap();
    assert_eq!(serde_json::to_value(&read).unwrap(), ore);
    let read: IntegerOrd = serde_json::from_value(ope.clone()).unwrap();
    assert_eq!(serde_json::to_value(&read).unwrap(), ope);

    let ob = ore["ob"].as_str().unwrap().to_owned();
    let op = ope["op"].as_str().unwrap().to_owned();
    let with = |base: &Value, key: &str, term: Value| {
        let mut value = base.clone();
        value[key] = term;
        value
    };
    for (what, value) in [
        ("an EQL v3 array", with(&ore, "ob", json!([ob]))),
        ("an OPE term", with(&ore, "ob", json!(op))),
        (
            "a truncated term",
            with(&ore, "ob", json!(&ob[..ob.len() - 2])),
        ),
        (
            "text that is not hex",
            with(&ore, "ob", json!(format!("zz{}", &ob[2..]))),
        ),
    ] {
        let error = serde_json::from_value::<IntegerOrdOre>(value)
            .expect_err(what)
            .to_string();
        assert!(!error.contains(&ob[8..]), "{what}: {error}");
    }
    let carry = format!("02{}", &op[2..]);
    for (what, value) in [
        ("an EQL v3 array", with(&ope, "op", json!([op]))),
        ("a block ORE term", with(&ope, "op", json!(ob))),
        ("a carry of 2", with(&ope, "op", json!(carry))),
    ] {
        let error = serde_json::from_value::<IntegerOrd>(value)
            .expect_err(what)
            .to_string();
        assert!(!error.contains(&op[8..]), "{what}: {error}");
    }
}

/// Pairs whose order keys first differ in each block in turn: `x` with one
/// bit of block `k` clear, and `x` with it set. An `i32`'s key is 32 bits,
/// six 6-bit blocks (the last holds two bits); an `i64`'s is eleven.
fn first_difference_in_every_block_i32() -> Vec<i32> {
    let mut values = Vec::new();
    for block in 0..6u32 {
        let bit = (6 * block + 5).min(31);
        let mask = 1u32 << (31 - bit);
        let key = 0x5a5a_5a5a_u32 & !mask;
        // The order key of an i32 is its bits with the sign bit flipped.
        values.push((key ^ 0x8000_0000) as i32);
        values.push(((key | mask) ^ 0x8000_0000) as i32);
    }
    values
}

fn first_difference_in_every_block_i64() -> Vec<i64> {
    let mut values = Vec::new();
    for block in 0..11u32 {
        let bit = (6 * block + 5).min(63);
        let mask = 1u64 << (63 - bit);
        let key = 0x5a5a_5a5a_5a5a_5a5a_u64 & !mask;
        values.push((key ^ 0x8000_0000_0000_0000) as i64);
        values.push(((key | mask) ^ 0x8000_0000_0000_0000) as i64);
    }
    values
}

/// Text sharing prefixes, across padding buckets (a string pads to 16, 32
/// or 64 bytes, its one marker byte counted), and differing first at each
/// position of a 40-character string, so in every block of it.
fn texts() -> Vec<String> {
    let mut values: Vec<String> = [
        "",
        "a",
        "ab",
        "abc",
        "abd",
        "abc ",
        "b",
        "zz",
        // 15 characters (a 16-byte bucket) and 16 (a 32-byte bucket).
        "aaaaaaaaaaaaaaa",
        "aaaaaaaaaaaaaaaa",
        "aaaaaaaaaaaaaaab",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let base = "mnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz".to_string();
    for at in 0..base.len() {
        let mut changed = base.clone().into_bytes();
        changed[at] = b'a' + (changed[at] - b'a' + 1) % 26;
        values.push(String::from_utf8(changed).unwrap());
    }
    values.push(base);
    values
}

fn connect() -> postgres::Client {
    postgres::Client::connect(
        &std::env::var("EQL_TEST_DATABASE_URL").expect("EQL_TEST_DATABASE_URL"),
        postgres::NoTls,
    )
    .unwrap()
}

/// EQL v4's comparator over two terms.
fn sql_cmp(db: &mut postgres::Client, a: &[u8], b: &[u8]) -> Result<i32, postgres::Error> {
    db.query_one(
        "SELECT eql_v4_internal.compare_ore_block_v2_term(\
           ROW($1::bytea)::eql_v4_internal.ore_block_v2_term, \
           ROW($2::bytea)::eql_v4_internal.ore_block_v2_term)",
        &[&a, &b],
    )
    .map(|row| row.get(0))
}

fn as_ordering(n: i32) -> Ordering {
    n.cmp(&0)
}

/// Every pair of `terms`, both ways round: EQL's answer, ore-rs's and the
/// plaintext order all agree. `terms[i]` encrypts `plain[i / 2]`.
fn assert_agree<T: Orderable, P: PartialOrd + std::fmt::Debug>(
    db: &mut postgres::Client,
    what: &str,
    plain: &[P],
    terms: &[Vec<u8>],
) {
    for (i, a) in terms.iter().enumerate() {
        for (j, b) in terms.iter().enumerate() {
            let (pa, pb) = (&plain[i / 2], &plain[j / 2]);
            let expected = pa.partial_cmp(pb).unwrap();
            let sql = as_ordering(sql_cmp(db, a, b).unwrap_or_else(|e| panic!("{what}: {e}")));
            assert_eq!(sql, expected, "{what}: {pa:?} against {pb:?} in SQL");
            assert_eq!(
                rust_cmp::<T>(a, b),
                expected,
                "{what}: {pa:?} against {pb:?} in ore-rs"
            );
        }
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Needs an EQL v4 installation.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_compares_fixed_width_terms_as_ore_rs_and_the_plaintexts_do() {
    let runtime = runtime();
    let (cipher, _) = runtime.block_on(common::cipher());
    let keyset = cipher.default_keyset();
    let mut db = connect();

    let mut ints = vec![i32::MIN, -1_000_000, -1, 0, 1, 63, 64, 1_000_000, i32::MAX];
    ints.extend(first_difference_in_every_block_i32());
    ints.sort_unstable();
    ints.dedup();
    let int_terms = runtime.block_on(terms(&keyset, "IntegerOrdOre", &ints));
    assert_agree::<i32, _>(&mut db, "IntegerOrdOre", &ints, &int_terms);

    let smalls = vec![i16::MIN, -300, -1, 0, 1, 63, 64, 300, i16::MAX];
    let small_terms = runtime.block_on(terms(&keyset, "SmallintOrdOre", &smalls));
    assert_agree::<i16, _>(&mut db, "SmallintOrdOre", &smalls, &small_terms);

    let mut bigs = vec![i64::MIN, -1, 0, 1, 1 << 40, i64::MAX];
    bigs.extend(first_difference_in_every_block_i64());
    bigs.sort_unstable();
    bigs.dedup();
    let big_terms = runtime.block_on(terms(&keyset, "BigintOrdOre", &bigs));
    assert_agree::<i64, _>(&mut db, "BigintOrdOre", &bigs, &big_terms);

    // Floats order as float8: -0.0 ties 0.0, and NaN (left out of the
    // plaintext comparison, which has no order for it) sorts last, below.
    let doubles = [
        f64::NEG_INFINITY,
        -1e300,
        -1.5,
        -0.0,
        0.0,
        1e-300,
        1.0,
        2.0,
        1e300,
        f64::INFINITY,
    ];
    let double_terms = runtime.block_on(terms(&keyset, "DoubleOrdOre", &doubles));
    assert_agree::<f64, _>(&mut db, "DoubleOrdOre", &doubles, &double_terms);
    let nan = runtime.block_on(ob(&keyset, "DoubleOrdOre", frame(f64::NAN)));
    for term in &double_terms {
        assert_eq!(sql_cmp(&mut db, &nan, term).unwrap(), 1, "NaN sorts last");
        assert_eq!(sql_cmp(&mut db, term, &nan).unwrap(), -1, "NaN sorts last");
    }
    assert_eq!(sql_cmp(&mut db, &nan, &nan).unwrap(), 0, "NaN ties NaN");

    let reals = [
        f32::NEG_INFINITY,
        -2.5,
        -0.0,
        0.0,
        0.5,
        f32::MAX,
        f32::INFINITY,
    ];
    let real_terms = runtime.block_on(terms(&keyset, "RealOrdOre", &reals));
    assert_agree::<f32, _>(&mut db, "RealOrdOre", &reals, &real_terms);
}

/// Each value's terms, two writes each, as `terms` makes them for a `Copy`
/// plaintext: the plaintexts here are wiped on drop, so are not `Copy`.
async fn terms_of<T: Encrypt + Clone>(
    keyset: &Keyset<'_>,
    name: &str,
    values: impl IntoIterator<Item = T>,
) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for value in values {
        out.push(ob(keyset, name, frame(value.clone())).await);
        out.push(ob(keyset, name, frame(value)).await);
    }
    out
}

/// Needs an EQL v4 installation. A date orders by day, a timestamp by the
/// microsecond (floored), and a decimal by value whatever its scale; the
/// plaintext each is compared as here says so.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_compares_date_timestamp_and_decimal_terms_as_ore_rs_and_the_plaintexts_do() {
    let runtime = runtime();
    let (cipher, _) = runtime.block_on(common::cipher());
    let keyset = cipher.default_keyset();
    let mut db = connect();

    let days = [-719_162, -1, 0, 1, 63, 64, 19_782];
    let date_terms = runtime.block_on(terms_of(
        &keyset,
        "DateOrdOre",
        days.map(|d| Date::from_days_since_epoch(d).unwrap()),
    ));
    assert_agree::<Date, _>(&mut db, "DateOrdOre", &days, &date_terms);

    // (seconds, nanoseconds), compared as whole microseconds, floored.
    let instants = [
        (-1, 999_999_000),
        (-1, 999_999_999),
        (0, 0),
        (0, 999),
        (0, 1_000),
        (1_700_000_000, 0),
    ];
    let micros = instants.map(|(s, n): (i64, u32)| {
        (i128::from(s) * 1_000_000_000 + i128::from(n)).div_euclid(1_000)
    });
    let instant_terms = runtime.block_on(terms_of(
        &keyset,
        "TimestampOrdOre",
        instants.map(|(s, n)| Timestamp::new(s, n).unwrap()),
    ));
    assert_agree::<Timestamp, _>(&mut db, "TimestampOrdOre", &micros, &instant_terms);

    // (mantissa, scale), compared as ten-thousandths.
    let numbers = [
        (-1_000, 0),
        (-15, 1),
        (0, 0),
        (0, 3),
        (15, 1),
        (150, 2),
        (2, 0),
    ];
    let scaled = numbers.map(|(m, s): (i128, u32)| m * 10i128.pow(4 - s));
    let number_terms = runtime.block_on(terms_of(
        &keyset,
        "NumericOrdOre",
        numbers.map(|(m, s)| Decimal::new(m, s as u8).unwrap()),
    ));
    assert_agree::<Decimal, _>(&mut db, "NumericOrdOre", &scaled, &number_terms);
}

/// Needs an EQL v4 installation.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_compares_chained_text_terms_as_ore_rs_and_the_plaintexts_do() {
    let runtime = runtime();
    let (cipher, _) = runtime.block_on(common::cipher());
    let keyset = cipher.default_keyset();
    let mut db = connect();
    // Lower-case ASCII folds to itself, so the fold order is byte order.
    let mut values = texts();
    values.sort();
    values.dedup();
    let refs: Vec<&str> = values.iter().map(String::as_str).collect();
    let text_terms = runtime.block_on(text_terms(&keyset, "TextOrdOre", &refs));
    let counts: std::collections::BTreeSet<u16> = text_terms
        .iter()
        .map(|t| u16::from_be_bytes([t[2], t[3]]))
        .collect();
    assert!(
        counts.len() >= 3,
        "the values span padding buckets: {counts:?}"
    );
    assert_agree::<String, _>(&mut db, "TextOrdOre", &values, &text_terms);

    // Text that differs only in case and accents folds to one value.
    let a = runtime.block_on(ob(&keyset, "TextOrdOre", frame("Café")));
    let b = runtime.block_on(ob(&keyset, "TextOrdOre", frame("cafe")));
    assert_eq!(sql_cmp(&mut db, &a, &b).unwrap(), 0);
}

/// ore.rs's vectors for the σ-MMO hash bit
/// (`docs/reviews/2026-06-16-mmo-plpgsql-validation.sql` in ore.rs).
const HASH_VECTORS: [(&str, &str, i32); 12] = [
    (
        "00070e151c232a31383f464d545b6269",
        "010e1b2835424f5c697683909daab7c4",
        1,
    ),
    (
        "1f262d343b424950575e656c737a8188",
        "121f2c394653606d7a8794a1aebbc8d5",
        0,
    ),
    (
        "3e454c535a61686f767d848b9299a0a7",
        "23303d4a5764717e8b98a5b2bfccd9e6",
        0,
    ),
    (
        "5d646b727980878e959ca3aab1b8bfc6",
        "34414e5b6875828f9ca9b6c3d0ddeaf7",
        0,
    ),
    (
        "7c838a91989fa6adb4bbc2c9d0d7dee5",
        "45525f6c798693a0adbac7d4e1eefb08",
        0,
    ),
    (
        "9ba2a9b0b7bec5ccd3dae1e8eff6fd04",
        "5663707d8a97a4b1becbd8e5f2ff0c19",
        1,
    ),
    (
        "bac1c8cfd6dde4ebf2f900070e151c23",
        "6774818e9ba8b5c2cfdce9f603101d2a",
        0,
    ),
    (
        "d9e0e7eef5fc030a11181f262d343b42",
        "7885929facb9c6d3e0edfa0714212e3b",
        0,
    ),
    (
        "f8ff060d141b222930373e454c535a61",
        "8996a3b0bdcad7e4f1fe0b1825323f4c",
        0,
    ),
    (
        "171e252c333a41484f565d646b727980",
        "9aa7b4c1cedbe8f5020f1c293643505d",
        0,
    ),
    (
        "363d444b525960676e757c838a91989f",
        "abb8c5d2dfecf90613202d3a4754616e",
        1,
    ),
    (
        "555c636a71787f868d949ba2a9b0b7be",
        "bcc9d6e3f0fd0a1724313e4b5865727f",
        0,
    ),
];

/// Needs an EQL v4 installation.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_hash_bit_matches_ore_rs_vectors() {
    let mut db = connect();
    for (f, nonce, expected) in HASH_VECTORS {
        let bit: i32 = db
            .query_one(
                "SELECT eql_v4_internal.ore_block_v2_hash_bit($1::bytea, $2::bytea)",
                &[&unhex(f), &unhex(nonce)],
            )
            .unwrap()
            .get(0);
        assert_eq!(bit, expected, "{f} under {nonce}");
    }
}

fn raises(db: &mut postgres::Client, a: &[u8], b: &[u8], what: &str) -> String {
    match sql_cmp(db, a, b) {
        Ok(n) => panic!("{what}: compared to {n}, not refused"),
        Err(e) => e
            .as_db_error()
            .map(|e| e.message().to_owned())
            .unwrap_or_else(|| e.to_string()),
    }
}

/// Needs an EQL v4 installation.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_refuses_malformed_and_mismatched_terms() {
    let runtime = runtime();
    let (cipher, _) = runtime.block_on(common::cipher());
    let keyset = cipher.default_keyset();
    let mut db = connect();
    let int = runtime.block_on(ob(&keyset, "IntegerOrdOre", frame(7i32)));
    let big = runtime.block_on(ob(&keyset, "BigintOrdOre", frame(7i64)));
    let text = runtime.block_on(ob(&keyset, "TextOrdOre", frame("alice")));

    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        ("truncated", int[..int.len() - 1].to_vec()),
        ("one byte long", int.iter().copied().chain([0]).collect()),
        ("empty", Vec::new()),
        ("header alone", int[..4].to_vec()),
    ];
    let mut version = int.clone();
    version[0] = 1;
    cases.push(("wire version 1", version));
    let mut scheme = int.clone();
    scheme[1] = 4;
    cases.push(("an unknown scheme", scheme));
    let mut symbol = int.clone();
    symbol[4] = 64;
    cases.push(("a symbol of 64", symbol));
    let mut count = int.clone();
    count[3] += 1;
    cases.push(("a block count its length does not have", count));
    let mut policy = text.clone();
    policy[4] = 3;
    cases.push(("an unknown padding kind", policy));
    let mut bucket = text.clone();
    bucket[5..7].copy_from_slice(&64u16.to_be_bytes());
    cases.push(("a block count its padding cannot produce", bucket));
    for (what, bad) in &cases {
        let message = raises(&mut db, bad, &int, what);
        assert!(
            message.contains("Malformed ORE block term"),
            "{what}: {message}"
        );
        let message = raises(&mut db, &text, bad, what);
        assert!(
            message.contains("Malformed ORE block term"),
            "{what}: {message}"
        );
        assert!(
            !message.contains(&hex(bad)) || bad.is_empty(),
            "{what}: the message names the length, never the bytes"
        );
    }

    let message = raises(&mut db, &int, &text, "fixed against chained");
    assert!(message.contains("different schemes"), "{message}");
    let message = raises(&mut db, &int, &big, "6 blocks against 11");
    assert!(message.contains("different lengths"), "{message}");
    // The same text term under the no-padding policy, which admits any
    // block count: well formed, but padded differently.
    let mut unpadded = text.clone();
    unpadded[4..7].copy_from_slice(&[0, 0, 0]);
    let message = raises(&mut db, &text, &unpadded, "two padding policies");
    assert!(message.contains("different policies"), "{message}");

    // A value holds one term, the hex string `ob` carries: the extractor
    // reads it, and refuses an EQL v3 array as a value with no `ob`.
    let extracted: Vec<u8> = db
        .query_one(
            "SELECT (eql_v4_internal.ore_block_v2(jsonb_build_object('ob', $1::text))).term.bytes",
            &[&hex(&int)],
        )
        .unwrap()
        .get(0);
    assert_eq!(extracted, int);
    let error = db
        .query_one(
            "SELECT eql_v4_internal.ore_block_v2(jsonb_build_object('ob', jsonb_build_array($1::text)))",
            &[&hex(&int)],
        )
        .unwrap_err();
    let message = error.as_db_error().unwrap().message().to_owned();
    assert!(message.contains("Expected an ore index (ob)"), "{message}");
}

/// The longest chained term EQL v4 admits: 1366 blocks, a 1,024-byte string
/// (the longest Stack Encrypt writes, marker byte included).
const MAX_CHAINED_BLOCKS: usize = 1366;

/// A term of `count` all-zero blocks with the header given, well formed in
/// every respect but the header.
fn zero_term(header: &[u8], count: usize) -> Vec<u8> {
    let mut term = header.to_vec();
    term.resize(header.len() + 25 * count + 16, 0);
    term
}

fn chained_header(kind: u8, policy: u16, count: usize) -> Vec<u8> {
    let count = u16::try_from(count).unwrap().to_be_bytes();
    let policy = policy.to_be_bytes();
    vec![2, 3, count[0], count[1], kind, policy[0], policy[1]]
}

/// Needs an EQL v4 installation. For every padding kind, a spread of
/// policies around each power-of-two bucket and every block count up to
/// past the bound, EQL v4 admits a term exactly when ore-rs does and the
/// term has between one block and [`MAX_CHAINED_BLOCKS`]; for the
/// fixed-width scheme, exactly when ore-rs does. ore-rs parses a chained
/// term of no blocks, which Stack Encrypt never writes (text and bytes go
/// in behind a marker byte), and EQL v4 refuses it. The terms are built in the database, from
/// the header fields alone, so the check does not ship each one.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_admits_the_block_counts_ore_rs_does_up_to_the_bound() {
    let mut db = connect();
    db.batch_execute(
        "CREATE FUNCTION pg_temp.admits(t bytea) RETURNS boolean LANGUAGE plpgsql AS $$
         BEGIN
           PERFORM eql_v4_internal.ore_block_v2_scheme(t);
           RETURN true;
         EXCEPTION WHEN raise_exception THEN
           RETURN false;
         END $$",
    )
    .unwrap();

    let mut policies: Vec<u16> = vec![0, 1, 2, 3, 5, 7, 49151, 49152, 65535];
    for k in 2..=15 {
        let bucket = 1u32 << k;
        for p in [bucket - 1, bucket, bucket + 1, bucket * 3 / 4] {
            policies.push(u16::try_from(p).unwrap());
        }
    }
    policies.sort_unstable();
    policies.dedup();
    let mut counts: Vec<usize> = (0..=MAX_CHAINED_BLOCKS + 40).collect();
    counts.extend([2048, 2731, 2732, 21846, 43691, 65535]);

    let mut cases: Vec<(u8, u16, usize)> = Vec::new();
    for kind in 0..=3u8 {
        let kind_policies: &[u16] = match kind {
            1 | 2 => &policies,
            _ => &[0, 1, 16],
        };
        for &policy in kind_policies {
            for &count in &counts {
                cases.push((kind, policy, count));
            }
        }
    }

    let kinds: Vec<i32> = cases.iter().map(|c| i32::from(c.0)).collect();
    let pols: Vec<i32> = cases.iter().map(|c| i32::from(c.1)).collect();
    let cnts: Vec<i32> = cases.iter().map(|c| c.2 as i32).collect();
    let admitted: Vec<bool> = db
        .query(
            "SELECT pg_temp.admits(
                 '\\x0203'::bytea || substr(int4send(c), 3, 2) || substr(int4send(k), 4, 1)
                 || substr(int4send(p), 3, 2) || decode(repeat('00', 25 * c + 16), 'hex'))
             FROM unnest($1::int[], $2::int[], $3::int[]) WITH ORDINALITY AS x(k, p, c, n)
             ORDER BY n",
            &[&kinds, &pols, &cnts],
        )
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(admitted.len(), cases.len());

    let mut both = 0;
    for (&(kind, policy, count), &sql) in cases.iter().zip(&admitted) {
        let term = zero_term(&chained_header(kind, policy, count), count);
        let ore_rs = OreBlockTerm::<String>::try_from(term.as_slice()).is_ok();
        let expected = ore_rs && (1..=MAX_CHAINED_BLOCKS).contains(&count);
        assert_eq!(
            sql, expected,
            "chained kind {kind}, policy {policy}, {count} blocks: ore-rs says {ore_rs}"
        );
        both += usize::from(sql);
    }
    // The grid reaches both answers, and past the bound ore-rs alone admits.
    assert!(both > 0 && both < cases.len());
    assert!(cases
        .iter()
        .zip(&admitted)
        .any(|(&(_, _, count), &sql)| count > MAX_CHAINED_BLOCKS
            && !sql
            && OreBlockTerm::<String>::from_bytes(zero_term(&chained_header(0, 0, count), count))
                .is_ok()));

    for count in 0..=20usize {
        let header = [2, 2, 0, u8::try_from(count).unwrap()];
        let term = zero_term(&header, count);
        let sql: bool = db
            .query_one("SELECT pg_temp.admits($1)", &[&term])
            .unwrap()
            .get(0);
        let ore_rs = OreBlockTerm::<u64>::try_from(term.as_slice()).is_ok();
        assert_eq!(sql, ore_rs, "fixed-width, {count} blocks");
    }
}

/// Needs an EQL v4 installation. The longest text Stack Encrypt orders,
/// 1023 bytes, is a term of exactly [`MAX_CHAINED_BLOCKS`] blocks and
/// compares; the same shape one block longer, which ore-rs alone would
/// accept, is refused before any block is compared.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_compares_the_longest_term_and_refuses_one_past_it() {
    let runtime = runtime();
    let (cipher, _) = runtime.block_on(common::cipher());
    let keyset = cipher.default_keyset();
    let mut db = connect();
    let longest = "z".repeat(1023);
    let shorter = format!("{}y", "z".repeat(1022));
    let a = runtime.block_on(ob(&keyset, "TextOrdOre", frame(longest.as_str())));
    let b = runtime.block_on(ob(&keyset, "TextOrdOre", frame(shorter.as_str())));
    assert_eq!(
        usize::from(u16::from_be_bytes([a[2], a[3]])),
        MAX_CHAINED_BLOCKS
    );
    assert_eq!(
        as_ordering(sql_cmp(&mut db, &a, &b).unwrap()),
        Ordering::Greater
    );
    assert_eq!(
        as_ordering(sql_cmp(&mut db, &b, &a).unwrap()),
        Ordering::Less
    );
    assert_eq!(
        as_ordering(sql_cmp(&mut db, &a, &a).unwrap()),
        Ordering::Equal
    );

    let count = MAX_CHAINED_BLOCKS + 1;
    let over = zero_term(&chained_header(0, 0, count), count);
    assert!(
        OreBlockTerm::<String>::try_from(over.as_slice()).is_ok(),
        "ore-rs admits it"
    );
    let unpadded = zero_term(
        &chained_header(0, 0, MAX_CHAINED_BLOCKS),
        MAX_CHAINED_BLOCKS,
    );
    for (x, y) in [(&over, &unpadded), (&unpadded, &over)] {
        let message = raises(&mut db, x, y, "one block past the bound");
        assert!(message.contains("Malformed ORE block term"), "{message}");
    }
}

/// Needs an EQL v4 installation. Rows written through the by-name dispatch
/// and queried through a btree index on the order term: `<`, `>=`, `=` and
/// `ORDER BY` find exactly the rows the plaintexts say.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_answers_the_orderings_through_a_btree_index() {
    let runtime = runtime();
    let (cipher, _) = runtime.block_on(common::cipher());
    let keyset = cipher.default_keyset();
    let mut db = connect();
    db.batch_execute(
        "CREATE TEMP TABLE v4_ore_block (id int PRIMARY KEY, \
           level public.eql_v4_integer_ord_ore, title public.eql_v4_text_ord_ore);",
    )
    .unwrap();
    let rows: [(i32, i32, &str); 6] = [
        (1, -5, "alice"),
        (2, 0, "bob"),
        (3, 0, "bob"),
        (4, 7, "carol"),
        (5, 64, "carola"),
        (6, i32::MAX, "zoe"),
    ];
    for (id, level, title) in rows {
        let (level, title) = runtime.block_on(async {
            (
                stored(&keyset, "IntegerOrdOre", frame(level))
                    .await
                    .to_string(),
                stored(&keyset, "TextOrdOre", frame(title))
                    .await
                    .to_string(),
            )
        });
        db.execute(
            "INSERT INTO v4_ore_block VALUES ($1, $2::text::jsonb::public.eql_v4_integer_ord_ore, \
               $3::text::jsonb::public.eql_v4_text_ord_ore)",
            &[&id, &level, &title],
        )
        .unwrap();
    }
    db.batch_execute(
        "CREATE INDEX ON v4_ore_block USING btree (eql_v4.ord_term_ore(level)); \
         CREATE INDEX ON v4_ore_block USING btree (eql_v4.ord_term_ore(title)); \
         ANALYZE v4_ore_block; SET enable_seqscan = off;",
    )
    .unwrap();
    let probe = |name: &str, value: ValueFrame| -> String {
        runtime.block_on(async {
            let bytes = targets::query(name, &common::index_of(name), &keyset, &label(), value)
                .unwrap()
                .await
                .unwrap();
            String::from_utf8(bytes).unwrap()
        })
    };
    let level = probe("IntegerOrdOre", frame(0i32));
    let title = probe("TextOrdOre", frame("bob"));
    for (column, domain, probe) in [
        ("level", "query_integer_ord_ore", &level),
        ("title", "query_text_ord_ore", &title),
    ] {
        let ids = |db: &mut postgres::Client, op: &str| -> Vec<i32> {
            let sql = format!(
                "SELECT id FROM v4_ore_block WHERE {column} {op} $1::text::jsonb::eql_v4.{domain} ORDER BY id"
            );
            db.query(&sql, &[probe])
                .unwrap_or_else(|e| panic!("{sql}: {e}"))
                .iter()
                .map(|r| r.get(0))
                .collect()
        };
        assert_eq!(ids(&mut db, "<"), [1], "{column} <");
        assert_eq!(ids(&mut db, ">="), [2, 3, 4, 5, 6], "{column} >=");
        assert_eq!(ids(&mut db, "="), [2, 3], "{column} =");
        let plan: Vec<String> = db
            .query(
                &format!(
                    "EXPLAIN SELECT id FROM v4_ore_block WHERE {column} < $1::text::jsonb::eql_v4.{domain}"
                ),
                &[probe],
            )
            .unwrap()
            .iter()
            .map(|r| r.get(0))
            .collect();
        assert!(
            plan.iter().any(|line| line.contains("Index")),
            "{column}: the btree index answers `<`: {plan:#?}"
        );
        let ordered: Vec<i32> = db
            .query(
                &format!("SELECT id FROM v4_ore_block ORDER BY eql_v4.ord_term_ore({column}), id"),
                &[],
            )
            .unwrap()
            .iter()
            .map(|r| r.get(0))
            .collect();
        assert_eq!(ordered, [1, 2, 3, 4, 5, 6], "{column}: ORDER BY");
    }
}

/// SQLSTATE `check_violation`.
const CHECK_VIOLATION: &str = "23514";

/// Needs an EQL v4 installation. A domain takes an order term only as one
/// hex string with its scheme's prefix, so the CHECK refuses an EQL v3
/// array, a term of another scheme or engine, an OPE carry other than 0 or
/// 1, and a value that is not a string, at the cast and before any
/// comparison. What Stack Encrypt writes passes, stored, queried and as a
/// range bound.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_domains_take_an_order_term_only_as_its_hex_string() {
    use serde_json::{json, Value};
    let runtime = runtime();
    let (cipher, _) = runtime.block_on(common::cipher());
    let keyset = cipher.default_keyset();
    let mut db = connect();
    let ore = runtime.block_on(stored(&keyset, "IntegerOrdOre", frame(7i32)));
    let ope = runtime.block_on(stored(&keyset, "IntegerOrd", frame(7i32)));
    let ob = ore["ob"].as_str().unwrap().to_owned();
    let op = ope["op"].as_str().unwrap().to_owned();
    let query = |key: &str, term: Value| json!({"v": 4, "i": ore["i"], key: term});
    let range = |lo: Value, hi: Value| json!({"v": 4, "i": ore["i"], "lo": lo, "hi": hi});
    let with = |base: &Value, key: &str, term: Value| {
        let mut value = base.clone();
        value[key] = term;
        value
    };
    let cast = |db: &mut postgres::Client, domain: &str, value: &Value| {
        db.query_one(
            &format!("SELECT $1::text::jsonb::{domain} IS NOT NULL"),
            &[&value.to_string()],
        )
        .map(drop)
    };

    let stored_ore = "public.eql_v4_integer_ord_ore";
    let stored_ope = "public.eql_v4_integer_ord";
    let query_ore = "eql_v4.query_integer_ord_ore";
    let query_ope = "eql_v4.query_integer_ord";
    let range_ore = "eql_v4.query_integer_range_ore";
    let range_ope = "eql_v4.query_integer_range_ope";
    for (domain, value) in [
        (stored_ore, ore.clone()),
        (stored_ope, ope.clone()),
        (query_ore, query("ob", json!(ob))),
        (query_ope, query("op", json!(op))),
        (range_ore, range(json!(ob), json!(ob))),
        (range_ope, range(json!(op), json!(op))),
    ] {
        cast(&mut db, domain, &value).unwrap_or_else(|e| panic!("{domain}: {e}"));
    }

    let engine = format!("0204{}", &ob[4..]);
    let version = format!("01{}", &ob[2..]);
    let carry = format!("02{}", &op[2..]);
    for (what, domain, value) in [
        ("an EQL v3 array", stored_ore, with(&ore, "ob", json!([ob]))),
        (
            "an unknown engine",
            stored_ore,
            with(&ore, "ob", json!(engine)),
        ),
        (
            "wire version 1",
            stored_ore,
            with(&ore, "ob", json!(version)),
        ),
        ("an OPE term", stored_ore, with(&ore, "ob", json!(op))),
        ("a number", stored_ore, with(&ore, "ob", json!(7))),
        ("an OPE array", stored_ope, with(&ope, "op", json!([op]))),
        ("a carry of 2", stored_ope, with(&ope, "op", json!(carry))),
        ("a block ORE term", stored_ope, with(&ope, "op", json!(ob))),
        ("a query's v3 array", query_ore, query("ob", json!([ob]))),
        ("a query's carry of 2", query_ope, query("op", json!(carry))),
        ("a v3 array bound", range_ore, range(json!([ob]), json!(ob))),
        ("an OPE bound", range_ore, range(json!(ob), json!(op))),
        (
            "a carry of 2 bound",
            range_ope,
            range(json!(op), json!(carry)),
        ),
    ] {
        let error = cast(&mut db, domain, &value).expect_err(what);
        let state = error.code().map_or("", |code| code.code());
        assert_eq!(state, CHECK_VIOLATION, "{what}: {error}");
    }
}
