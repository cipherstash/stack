//! e2e suite: property tests over freshly generated values encrypted
//! end-to-end through ZeroKMS each run. Gated behind `proptest-e2e` (declared in
//! property/mod.rs) — needs CS_* creds, which `mise run test:sqlx` enables for
//! CI/local full SQLx runs.
//! Each proptest case generates one batch of random integers — seeded with
//! type-specific extremes, zero, and deliberate duplicates so the equality-true
//! branch fires across distinct ciphertexts of the same plaintext — encrypts it
//! in one batched ZeroKMS call, then runs the all-pairs oracle.

use anyhow::Result;
use eql_tests::fixtures::cipherstash::encrypt_store;
use eql_tests::fixtures::eql_plaintext::EqlPlaintext;
use eql_tests::fixtures::index_kind::IndexKind;
use eql_tests::property::{
    assert_eq_oracle, assert_ord_oracle, connect_pool, ensure_eql_installed, Row,
};
use eql_tests::scalar_domains::ScalarType;
use eql_tests::scalar_domains::Variant;
use proptest::prelude::*;
use proptest::test_runner::{Config, TestCaseError, TestRunner};
use sqlx::PgPool;

/// Encrypt a batch of plaintext values into `(plaintext, payload_json)` rows
/// via the existing fixture oracle. One ZeroKMS round trip for the whole batch.
/// The EQL cast is the type's own `EqlPlaintext::CAST` — never passed in, so it
/// cannot drift from `T`. `encrypt_store` returns v3-envelope payloads
/// (converted via eql_bindings::from_v2), so the oracle's domain casts
/// satisfy the `v = '3'` CHECKs.
async fn encrypt_rows<T>(pool_table: &str, values: &[T]) -> Result<Vec<Row<T>>>
where
    T: ScalarType + EqlPlaintext + Clone,
{
    let payloads = encrypt_store(
        pool_table,
        "payload",
        values,
        // The oracle runs each row through BOTH ordered variants, which are now
        // backed by different SEMs: `_ord` requires `op` (CLLW-OPE) and
        // `_ord_ore` requires `ob` (block-ORE). Omitting either makes the
        // corresponding domain's CHECK reject the payload at the cast.
        &[IndexKind::Unique, IndexKind::Ore, IndexKind::Ope],
    )
    .await?;
    // Fail fast on a count mismatch: a silent `zip` truncation would weaken the
    // oracle (fewer pairs than intended) and hide an encrypt_store contract
    // regression. (encrypt_store already checks this, but keep it local/explicit.)
    anyhow::ensure!(
        payloads.len() == values.len(),
        "encrypt_store returned {} payloads for {} plaintext values",
        payloads.len(),
        values.len()
    );
    Ok(values
        .iter()
        .cloned()
        .zip(payloads)
        .map(|(plaintext, payload)| Row {
            plaintext,
            payload_json: payload.to_string(),
        })
        .collect())
}

/// Drive proptest: each case is a batch of integers. Generation is in-process;
/// encryption + oracle is async on a current-thread runtime.
fn run_e2e_property<T>(table: &str, cases: u32, ordered: bool, seeds: &[T]) -> Result<()>
where
    T: ScalarType + EqlPlaintext + Clone + 'static,
{
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let pool: PgPool = rt.block_on(connect_pool())?;
    // The base DB this pool connects to is not migrated by `#[sqlx::test]`; in a
    // CI shard it has no `eql_v3` surface, so apply the migrations (idempotent +
    // process-safe via the migrator's advisory lock) before any cast/query.
    rt.block_on(ensure_eql_installed(&pool, &super::migrator()))?;

    // Shrinking is disabled for the e2e suite: every failed shrink attempt would
    // trigger another ZeroKMS batch, and ciphertext cannot be meaningfully
    // shrunk anyway. The catalog suite keeps normal shrinking.
    let mut runner = TestRunner::new(Config {
        cases,
        max_shrink_iters: 0,
        // Ciphertext can't be replayed across runs (fresh ZeroKMS each time), so
        // there's nothing to persist; also silences proptest's "no source file"
        // warning.
        failure_persistence: None,
        ..Config::default()
    });
    // 2..=10 random values, then we append deterministic seeds and duplicates
    // of the first two random values. Seeds guarantee min/max/zero coverage;
    // duplicates guarantee the eq-true branch across independently encrypted
    // ciphertexts.
    // Per-type bounded strategy (see ScalarType::arbitrary_value): integers draw
    // the full range, non-integer scalars draw from their cast-valid fixture set.
    let strategy = prop::collection::vec(T::arbitrary_value(), 2..11);
    runner
        .run(&strategy, |mut values| {
            let dup0 = values[0].clone();
            let dup1 = values[1].clone();
            values.extend_from_slice(seeds);
            values.push(dup0);
            values.push(dup1);
            let rows = rt
                .block_on(encrypt_rows::<T>(table, &values))
                // `{e:#}` keeps anyhow's full cause chain (the underlying error),
                // which a plain `{e}` would drop.
                .map_err(|e| TestCaseError::fail(format!("encrypt: {e:#}")))?;
            rt.block_on(async {
                assert_eq_oracle::<T>(&pool, &rows).await?;
                if ordered {
                    assert_ord_oracle::<T>(&pool, Variant::Ord, &rows).await?;
                    assert_ord_oracle::<T>(&pool, Variant::OrdOre, &rows).await?;
                }
                Ok::<_, anyhow::Error>(())
            })
            .map_err(|e| TestCaseError::fail(format!("oracle: {e:#}")))?;
            Ok(())
        })
        .map_err(|e| anyhow::anyhow!("e2e property failed: {e}"))
}

/// Each e2e case is a ZeroKMS round trip, so the case count stays low (8 keeps
/// CI bounded). One macro line per ordered scalar; the EQL cast is derived from
/// the type, the seeds are the per-type extremes + origin.
macro_rules! e2e_oracle_suite {
    ($modname:ident, $ty:ty, $table:literal, seeds = [$($seed:expr),* $(,)?]) => {
        mod $modname {
            use super::*;
            #[test]
            fn e2e_oracle() -> Result<()> {
                run_e2e_property::<$ty>($table, 8, true, &[$($seed),*])
            }
        }
    };
}

e2e_oracle_suite!(
    integer,
    i32,
    "proptest_e2e_integer",
    seeds = [i32::MIN, 0, i32::MAX]
);
e2e_oracle_suite!(
    smallint,
    i16,
    "proptest_e2e_smallint",
    seeds = [i16::MIN, 0, i16::MAX]
);
e2e_oracle_suite!(
    bigint,
    i64,
    "proptest_e2e_bigint",
    seeds = [i64::MIN, 0, i64::MAX]
);
e2e_oracle_suite!(
    date,
    chrono::NaiveDate,
    "proptest_e2e_date",
    seeds = [
        chrono::NaiveDate::from_ymd_opt(1900, 1, 1).unwrap(),
        chrono::NaiveDate::default(),
        chrono::NaiveDate::from_ymd_opt(2099, 12, 31).unwrap(),
    ]
);
e2e_oracle_suite!(
    timestamp,
    chrono::DateTime<chrono::Utc>,
    "proptest_e2e_timestamp",
    seeds = [
        chrono::DateTime::parse_from_rfc3339("1900-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        chrono::DateTime::<chrono::Utc>::default(),
        chrono::DateTime::parse_from_rfc3339("2099-12-31T23:59:59Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
    ]
);
e2e_oracle_suite!(
    numeric,
    rust_decimal::Decimal,
    "proptest_e2e_numeric",
    seeds = [
        <rust_decimal::Decimal as std::str::FromStr>::from_str("-1000000000000").unwrap(),
        rust_decimal::Decimal::ZERO,
        <rust_decimal::Decimal as std::str::FromStr>::from_str("1000000000000").unwrap(),
    ]
);
e2e_oracle_suite!(
    text,
    String,
    "proptest_e2e_text",
    seeds = ["aard".to_string(), "frank".to_string(), "zzzz".to_string()]
);
e2e_oracle_suite!(
    real,
    eql_tests::scalar_domains::F4,
    "proptest_e2e_real",
    seeds = [
        eql_tests::scalar_domains::F4(f32::NEG_INFINITY),
        eql_tests::scalar_domains::F4(0.0),
        eql_tests::scalar_domains::F4(f32::INFINITY),
    ]
);
e2e_oracle_suite!(
    double,
    eql_tests::scalar_domains::F8,
    "proptest_e2e_double",
    seeds = [
        eql_tests::scalar_domains::F8(f64::NEG_INFINITY),
        eql_tests::scalar_domains::F8(0.0),
        eql_tests::scalar_domains::F8(f64::INFINITY),
    ]
);

/// Both float widths encrypt through the SINGLE f64 crypto path
/// (`F4::to_plaintext` widens `self.0 as f64`; `F8::to_plaintext` is the
/// identity), so an f32 value and its exact f64 widening are the SAME real
/// number and are equality- and order-interchangeable across widths. The two
/// index terms behave differently and so are checked differently:
///
/// - `hm` (HMAC equality) is a **deterministic** keyed hash of the value, so the
///   two widths produce a **byte-identical** `hm` — assert that directly.
/// - `ob` (ORE ordering) is **probabilistic**: each encryption draws a fresh
///   per-ciphertext nonce (the random Right half of the BlockORE term), so two
///   encodings of one value are byte-UNEQUAL *by construction* — even same-width,
///   same-value. Ordering is decided by the ORE compare function, never by raw
///   bytes, so the ONLY correct cross-width ORE check is the SQL
///   `eql_v3_internal.ore_block_256` `=` operator over the extracted `ord_term_ore`s.
///
/// Creds/e2e-gated like the rest of this file.
#[test]
fn real_and_double_share_index_terms_for_the_same_value() -> Result<()> {
    use eql_tests::scalar_domains::{F4, F8};

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    // f32-exact value: `x as f64` is the same real number, so both widths encode
    // the identical f64 — any *value* difference would be a width artifact.
    let x: f32 = 2.25;

    let f4_payloads = rt.block_on(encrypt_store(
        "xwidth_f4",
        "payload",
        &[F4(x)],
        &[IndexKind::Unique, IndexKind::Ore],
    ))?;
    let f8_payloads = rt.block_on(encrypt_store(
        "xwidth_f8",
        "payload",
        &[F8(x as f64)],
        &[IndexKind::Unique, IndexKind::Ore],
    ))?;

    // `hm` (deterministic HMAC) is byte-identical across widths — compare directly.
    let hm = |p: &serde_json::Value| -> Result<String> {
        p.get("hm")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("payload missing string `hm`: {p}"))
    };
    assert_eq!(
        hm(&f4_payloads[0])?,
        hm(&f8_payloads[0])?,
        "real and double of the same value must share the hm equality term"
    );

    // `ob` (probabilistic ORE) is NOT byte-comparable — the only correct check is
    // the SQL ORE operator over the extracted `ord_term_ore`s. Cast each payload to
    // its width's `_ord_ore` domain, extract the `eql_v3_internal.ore_block_256` term, and
    // compare with `=` (eql_v3_internal.ore_block_256_eq => compare_ore_block_256_terms = 0).
    let pool: PgPool = rt.block_on(connect_pool())?;
    rt.block_on(ensure_eql_installed(&pool, &super::migrator()))?;

    let ord_term_ore = |p: &serde_json::Value, domain: &str| -> String {
        let lit = p.to_string().replace('\'', "''");
        format!("eql_v3.ord_term_ore('{lit}'::jsonb::{domain})")
    };
    let sql = format!(
        "SELECT {} = {}",
        ord_term_ore(&f4_payloads[0], "public.eql_v3_real_ord_ore"),
        ord_term_ore(&f8_payloads[0], "public.eql_v3_double_ord_ore"),
    );
    let ore_equal: Option<bool> = rt
        .block_on(sqlx::query_scalar(&sql).fetch_one(&pool))
        .map_err(|e| anyhow::anyhow!("cross-width ORE compare query ({sql}): {e}"))?;
    anyhow::ensure!(
        ore_equal == Some(true),
        "real and double of the same value must compare equal under the SQL ORE \
         operator (eql_v3_internal.ore_block_256 `=`); got {ore_equal:?}"
    );
    Ok(())
}
