//! fixture suite: property tests over the real, generated fixture rows.
//!
//! The fixture table `fixtures.eql_v3_<T>` carries `(plaintext, payload)` rows
//! encrypted by cipherstash-client during `test:sqlx:prep`. proptest selects a
//! sub-multiset of those rows (with repeats, so the equality diagonal includes
//! identical-ciphertext self-pairs) and the shared oracle engine checks every
//! pair. No new encryption — runs whenever the fixtures are present.
//!
//! Each test uses `#[sqlx::test]`, so it gets its OWN migrated scratch database
//! (the `eql_v3` surface is already installed by the embedded migrations) and
//! loads the fixture rows into that isolated DB. This is what every other test
//! in the suite does; it avoids the shared-base-DB races that bite under
//! nextest's process-per-test parallelism (concurrent `CREATE SCHEMA`, and a
//! later test re-`DROP`/`CREATE`-ing a fixture table out from under an earlier
//! test's in-flight reads). The only wrinkle is that proptest's case loop is
//! synchronous; `drive_proptest` bridges it to the async injected pool.
//!
//! Generic over `ScalarType`; instantiated per type at the bottom.

use anyhow::{Context, Result};
use eql_tests::property::{
    assert_eq_fn_oracle, assert_eq_oracle, assert_extractor_oracle, assert_ord_fn_oracle,
    assert_ord_oracle, Row,
};
use eql_tests::scalar_domains::{ScalarType, Variant};
use proptest::prelude::*;
use proptest::test_runner::{Config, TestCaseError, TestRunner};
use sqlx::PgPool;
use std::sync::Arc;

/// The fixture SQL for `T`, `include_str!`-embedded into this test binary
/// at compile time (one arm per catalog token). Embedding rather than reading
/// from disk at runtime is what lets the prebuilt nextest archive carry the
/// fixtures into CI shards, which do a fresh checkout where the gitignored
/// `tests/sqlx/fixtures/eql_v3_<T>.sql` files are absent. The path resolves
/// against the `eql_tests` crate root (`tests/sqlx`). Mirrors the loud catch-all
/// of the `generate_for_token` fixture dispatch.
///
/// `pub(crate)` so the sibling `match_smoke` module shares the one source of
/// truth for which fixture SQL is embedded.
pub(crate) fn embedded_fixture_sql<T: ScalarType>() -> &'static str {
    match T::PG_TYPE {
        "integer" => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/eql_v3_integer.sql"
        )),
        "smallint" => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/eql_v3_smallint.sql"
        )),
        "bigint" => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/eql_v3_bigint.sql"
        )),
        "date" => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/eql_v3_date.sql"
        )),
        "text" => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/eql_v3_text.sql"
        )),
        "timestamp" => {
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/fixtures/eql_v3_timestamp.sql"
            ))
        }
        "numeric" => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/eql_v3_numeric.sql"
        )),
        "real" => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/eql_v3_real.sql"
        )),
        "double" => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/eql_v3_double.sql"
        )),
        other => panic!(
            "no embedded fixture for catalog token '{other}'; \
             add an include_str! arm in fixture_oracle.rs"
        ),
    }
}

/// The `_doubles` fixture SQL for `T`, `include_str!`-embedded at compile time
/// (one arm per comparison-capable token). Same embed rationale as
/// `embedded_fixture_sql` — the prebuilt nextest archive carries the gitignored
/// fixtures into CI shards. The table is `fixtures.eql_v3_<T>_doubles`; the file
/// is `fixtures/eql_v3_<T>_doubles.sql`. `bool` is storage-only and has no
/// doubles fixture; the cross-ciphertext test never instantiates it, so its
/// absence (caught by the loud catch-all) is correct.
pub(crate) fn embedded_doubles_sql<T: ScalarType>() -> &'static str {
    match T::PG_TYPE {
        "smallint" => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/eql_v3_smallint_doubles.sql"
        )),
        "integer" => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/eql_v3_integer_doubles.sql"
        )),
        "bigint" => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/eql_v3_bigint_doubles.sql"
        )),
        "date" => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/eql_v3_date_doubles.sql"
        )),
        "timestamp" => {
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/fixtures/eql_v3_timestamp_doubles.sql"
            ))
        }
        "numeric" => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/eql_v3_numeric_doubles.sql"
        )),
        "text" => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/eql_v3_text_doubles.sql"
        )),
        other => panic!(
            "no embedded doubles fixture for catalog token '{other}'; \
             add an include_str! arm in embedded_doubles_sql"
        ),
    }
}

/// Load `T`'s generated fixtures into `pool`'s isolated scratch DB via the
/// `include_str!`-embedded SQL. The fixture SQL is self-contained (`CREATE SCHEMA
/// IF NOT EXISTS fixtures` / `CREATE` / `INSERT`); since each `#[sqlx::test]` DB
/// is private to its test there is no concurrency on it. `pub(crate)` so
/// `match_smoke` (which then fetches specific rows via `fetch_fixture_payload`)
/// shares the one embedded source.
pub(crate) async fn load_fixtures<T: ScalarType>(pool: &PgPool) -> Result<()> {
    sqlx::raw_sql(embedded_fixture_sql::<T>())
        .execute(pool)
        .await
        .with_context(|| format!("loading fixtures for {}", T::PG_TYPE))?;
    Ok(())
}

/// Load the generated fixtures for `T` into this test's isolated scratch
/// DB and read every `(plaintext, payload::text)` row, in id order.
pub(crate) async fn load_rows<T: ScalarType>(pool: &PgPool) -> Result<Arc<Vec<Row<T>>>> {
    load_fixtures::<T>(pool).await?;
    let sql = format!(
        "SELECT plaintext, payload::text FROM {} ORDER BY id",
        T::fixture_table_name()
    );
    let raw: Vec<(T, String)> = sqlx::query_as(&sql).fetch_all(pool).await?;
    let rows: Vec<Row<T>> = raw
        .into_iter()
        .map(|(plaintext, payload_json)| Row {
            plaintext,
            payload_json,
        })
        .collect();
    anyhow::ensure!(
        !rows.is_empty(),
        "fixture {} is empty",
        T::fixture_table_name()
    );
    Ok(Arc::new(rows))
}

/// Load `T`'s `_doubles` fixture into this test's isolated scratch DB and read
/// every `(plaintext, payload::text)` row in id order. The table is
/// `fixtures.eql_v3_<T>_doubles` (NOT the matrix's `fixtures.eql_v3_<T>`), so it
/// carries the equal-plaintext / distinct-ciphertext rows the cross-ciphertext
/// test needs.
pub(crate) async fn load_doubles_rows<T: ScalarType>(pool: &PgPool) -> Result<Arc<Vec<Row<T>>>> {
    sqlx::raw_sql(embedded_doubles_sql::<T>())
        .execute(pool)
        .await
        .with_context(|| format!("loading doubles fixtures for {}", T::PG_TYPE))?;
    let table = format!("fixtures.eql_v3_{}_doubles", T::PG_TYPE);
    let sql = format!("SELECT plaintext, payload::text FROM {table} ORDER BY id");
    let raw: Vec<(T, String)> = sqlx::query_as(&sql).fetch_all(pool).await?;
    let rows: Vec<Row<T>> = raw
        .into_iter()
        .map(|(plaintext, payload_json)| Row {
            plaintext,
            payload_json,
        })
        .collect();
    anyhow::ensure!(!rows.is_empty(), "doubles fixture {table} is empty");
    Ok(Arc::new(rows))
}

/// Build a sample by selecting indices (with repeats) into the loaded fixtures.
/// `idxs` are already bounded to `0..all.len()` by the proptest strategy.
fn pick<T: Clone>(all: &[Row<T>], idxs: &[usize]) -> Vec<Row<T>> {
    idxs.iter().map(|&i| all[i].clone()).collect()
}

/// Bridge proptest's synchronous case loop to async oracle work running on the
/// `#[sqlx::test]` runtime and its injected `pool`.
///
/// `TestRunner::run` is synchronous and cannot `.await`; spinning up a nested
/// runtime inside the test's runtime is unsound, and the pool is bound to the
/// test's runtime so it cannot be driven from another. So the runner lives on a
/// dedicated OS thread that ships each generated case to the async side over a
/// channel and blocks for the verdict; the async side (this future, on the test
/// runtime) runs `body` against the pool and replies. The pool never crosses
/// runtimes, and it works under any runtime flavour. Shrinking is preserved:
/// proptest re-invokes the closure with shrunk inputs, which flow through the
/// same channel.
async fn drive_proptest<V, S, F, Fut>(config: Config, strategy: S, body: F) -> Result<()>
where
    V: std::fmt::Debug + Send + 'static,
    S: Strategy<Value = V> + Send + 'static,
    F: Fn(V) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    use tokio::sync::{mpsc, oneshot};
    type Verdict = std::result::Result<(), String>;
    let (case_tx, mut case_rx) = mpsc::unbounded_channel::<(V, oneshot::Sender<Verdict>)>();

    // proptest drives cases on its own thread; `blocking_recv` is safe there
    // because it is not a runtime worker.
    let runner = std::thread::spawn(move || -> std::result::Result<(), String> {
        let mut runner = TestRunner::new(config);
        runner
            .run(&strategy, |value| {
                let (res_tx, res_rx) = oneshot::channel();
                case_tx
                    .send((value, res_tx))
                    .map_err(|_| TestCaseError::fail("oracle bridge: async side hung up"))?;
                match res_rx.blocking_recv() {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(msg)) => Err(TestCaseError::fail(msg)),
                    Err(_) => Err(TestCaseError::fail("oracle bridge: verdict dropped")),
                }
            })
            .map_err(|e| format!("{e}"))
    });

    // Service each case on the test runtime, where the pool lives. `{e:#}`
    // preserves anyhow's full cause chain (the real Postgres error).
    while let Some((value, res_tx)) = case_rx.recv().await {
        let verdict = body(value).await.map_err(|e| format!("{e:#}"));
        let _ = res_tx.send(verdict);
    }

    match runner.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(msg)) => Err(anyhow::anyhow!("fixture property failed: {msg}")),
        Err(_) => Err(anyhow::anyhow!("proptest runner thread panicked")),
    }
}

/// Strategy + config shared by the eq and ord runs: `cases` multisets of
/// `2..=12` indices into the fixtures (repeats wanted so the equality diagonal
/// includes identical-ciphertext self-pairs). No regression file — these sample
/// generated fixtures, nothing to persist/replay.
fn config_and_strategy(cases: u32, n: usize) -> (Config, impl Strategy<Value = Vec<usize>>) {
    let config = Config {
        cases,
        failure_persistence: None,
        ..Config::default()
    };
    (config, prop::collection::vec(0..n, 2..13))
}

/// Equality-oracle property over `T`'s fixture rows.
async fn run_eq_oracle<T: ScalarType>(pool: PgPool, cases: u32) -> Result<()> {
    let rows = load_rows::<T>(&pool).await?;
    let (config, strategy) = config_and_strategy(cases, rows.len());
    drive_proptest(config, strategy, move |idxs| {
        let pool = pool.clone();
        let rows = rows.clone();
        async move { assert_eq_oracle::<T>(&pool, &pick(&rows, &idxs)).await }
    })
    .await
}

/// Ordering-oracle property over `T`'s fixture rows (both ordered twins).
async fn run_ord_oracle<T: ScalarType>(pool: PgPool, cases: u32) -> Result<()> {
    let rows = load_rows::<T>(&pool).await?;
    let (config, strategy) = config_and_strategy(cases, rows.len());
    drive_proptest(config, strategy, move |idxs| {
        let pool = pool.clone();
        let rows = rows.clone();
        async move {
            let sample = pick(&rows, &idxs);
            assert_ord_oracle::<T>(&pool, Variant::Ord, &sample).await?;
            assert_ord_oracle::<T>(&pool, Variant::OrdOre, &sample).await
        }
    })
    .await
}

/// All fixtured scalars run the same number of proptest cases — the fixture
/// suite does no new encryption, so there is no reason for integer to be
/// privileged. Raise here (one place) if a regression ever needs more cases.
const FIXTURE_ORACLE_CASES: u32 = 32;

macro_rules! fixture_oracle_suite {
    ($modname:ident, $ty:ty, ordered) => {
        mod $modname {
            use super::*;
            #[sqlx::test]
            async fn eq_oracle(pool: PgPool) -> Result<()> {
                run_eq_oracle::<$ty>(pool, FIXTURE_ORACLE_CASES).await
            }
            #[sqlx::test]
            async fn ord_oracle(pool: PgPool) -> Result<()> {
                run_ord_oracle::<$ty>(pool, FIXTURE_ORACLE_CASES).await
            }
        }
    };
    ($modname:ident, $ty:ty, eq_only) => {
        mod $modname {
            use super::*;
            #[sqlx::test]
            async fn eq_oracle(pool: PgPool) -> Result<()> {
                run_eq_oracle::<$ty>(pool, FIXTURE_ORACLE_CASES).await
            }
        }
    };
}

fixture_oracle_suite!(integer, i32, ordered);
fixture_oracle_suite!(smallint, i16, ordered);
fixture_oracle_suite!(bigint, i64, ordered);
fixture_oracle_suite!(date, chrono::NaiveDate, ordered);
fixture_oracle_suite!(timestamp, chrono::DateTime<chrono::Utc>, ordered);
fixture_oracle_suite!(numeric, rust_decimal::Decimal, ordered);
fixture_oracle_suite!(text, String, ordered);
fixture_oracle_suite!(real, eql_tests::scalar_domains::F4, ordered);
fixture_oracle_suite!(double, eql_tests::scalar_domains::F8, ordered);

// --- function-double oracles -------------------------------------
//
// The same fixture rows, but calling the generated `eql_v3.*` comparison
// functions by name across all three overloads and asserting term-extractor
// identity (eq_term==hm / ord_term==op / ord_term_ore==ob). Free of fresh encryption — read-only
// SQL over the already-encrypted fixtures. integer is the reference family with
// explicit tests; the other types go through `fixture_fn_oracle_suite!`.

/// Function-double property driver: like `run_eq_oracle` / `run_ord_oracle`, but
/// the per-case `body` runs the caller's named-function / extractor oracles
/// against the per-case sample. Shares `load_rows` + `config_and_strategy` +
/// `drive_proptest`, so each fn-oracle test gets the same isolated `#[sqlx::test]`
/// DB and the same synchronous-proptest → async bridge as the operator oracles.
async fn run_fn_property<T, F, Fut>(pool: PgPool, cases: u32, body: F) -> Result<()>
where
    T: ScalarType,
    F: Fn(PgPool, Vec<Row<T>>) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let rows = load_rows::<T>(&pool).await?;
    let (config, strategy) = config_and_strategy(cases, rows.len());
    drive_proptest(config, strategy, move |idxs| {
        let pool = pool.clone();
        let sample = pick(&rows, &idxs);
        body(pool, sample)
    })
    .await
}

#[sqlx::test]
async fn prop_integer_eq_fn_oracle_over_fixture(pool: PgPool) -> Result<()> {
    run_fn_property::<i32, _, _>(pool, 32, |pool, sample| async move {
        assert_eq_fn_oracle::<i32>(&pool, Variant::Eq, &sample).await?;
        assert_extractor_oracle::<i32>(&pool, Variant::Eq, &sample).await
    })
    .await
}

#[sqlx::test]
async fn prop_integer_ord_fn_oracle_over_fixture(pool: PgPool) -> Result<()> {
    run_fn_property::<i32, _, _>(pool, 32, |pool, sample| async move {
        assert_ord_fn_oracle::<i32>(&pool, Variant::Ord, &sample).await?;
        assert_extractor_oracle::<i32>(&pool, Variant::Ord, &sample).await?;
        assert_ord_fn_oracle::<i32>(&pool, Variant::OrdOre, &sample).await?;
        assert_extractor_oracle::<i32>(&pool, Variant::OrdOre, &sample).await
    })
    .await
}

/// Function-double counterpart of `fixture_oracle_suite!`: per-family
/// named-function + extractor-identity oracles over the same fixture rows.
/// Parallel (distinct `<modname>` from the operator suite) so each family can be
/// added without disturbing the operator arms. `ordered` runs eq on `_eq` plus
/// the four ord functions on both ordered twins; `eq_only` runs eq alone. Each
/// arm is a `#[sqlx::test]` (its own migrated scratch DB), matching the operator
/// suite.
macro_rules! fixture_fn_oracle_suite {
    ($modname:ident, $ty:ty, ordered) => {
        mod $modname {
            use super::*;
            #[sqlx::test]
            async fn eq_fn_oracle(pool: PgPool) -> Result<()> {
                run_fn_property::<$ty, _, _>(pool, 32, |pool, c| async move {
                    assert_eq_fn_oracle::<$ty>(&pool, Variant::Eq, &c).await?;
                    assert_extractor_oracle::<$ty>(&pool, Variant::Eq, &c).await
                })
                .await
            }
            #[sqlx::test]
            async fn ord_fn_oracle(pool: PgPool) -> Result<()> {
                run_fn_property::<$ty, _, _>(pool, 32, |pool, c| async move {
                    assert_ord_fn_oracle::<$ty>(&pool, Variant::Ord, &c).await?;
                    assert_extractor_oracle::<$ty>(&pool, Variant::Ord, &c).await?;
                    assert_ord_fn_oracle::<$ty>(&pool, Variant::OrdOre, &c).await?;
                    assert_extractor_oracle::<$ty>(&pool, Variant::OrdOre, &c).await
                })
                .await
            }
        }
    };
    ($modname:ident, $ty:ty, eq_only) => {
        mod $modname {
            use super::*;
            #[sqlx::test]
            async fn eq_fn_oracle(pool: PgPool) -> Result<()> {
                run_fn_property::<$ty, _, _>(pool, 32, |pool, c| async move {
                    assert_eq_fn_oracle::<$ty>(&pool, Variant::Eq, &c).await?;
                    assert_extractor_oracle::<$ty>(&pool, Variant::Eq, &c).await
                })
                .await
            }
        }
    };
}

fixture_fn_oracle_suite!(smallint_fn, i16, ordered);
fixture_fn_oracle_suite!(bigint_fn, i64, ordered);
// date, timestamp, and numeric are all ordered scalars on the `eql_v3` base,
// so each gets eq/neq functions + eq_term identity plus the four ord functions
// on both ordered twins. The generated fixtures already encrypt the whole
// catalog, so this is full function-level coverage at zero marginal ZeroKMS cost.
fixture_fn_oracle_suite!(date_fn, chrono::NaiveDate, ordered);
fixture_fn_oracle_suite!(timestamp_fn, chrono::DateTime<chrono::Utc>, ordered);
fixture_fn_oracle_suite!(numeric_fn, rust_decimal::Decimal, ordered);

// text is bespoke rather than `fixture_fn_oracle_suite!`: its ordered domains
// carry `hm` plus an ordering term (`Ope` for `text_ord`, `Ore` for
// `text_ord_ore`), so they support the FULL six comparisons (eq/neq route
// through `hm`, the four ord ops through the ordering term) — the generic
// `ordered` arm only runs the four ord ops on the ordered twins. text also
// declares `_search` ([Hm, Ope, Bloom]), which `Variant::Search` reaches but
// the generic macro never instantiates. The generated text fixture is encrypted
// with [Unique, Ore, Match, Ope], so its payload carries hm+ob+bf+op and casts
// cleanly to every text domain. The fixture rows excludes the empty string (issue #262),
// so no generator filtering is needed here.
mod text_fn {
    use super::*;

    /// `text_eq` — eq/neq functions + eq_term identity.
    #[sqlx::test]
    async fn eq_fn_oracle(pool: PgPool) -> Result<()> {
        run_fn_property::<String, _, _>(pool, 32, |pool, c| async move {
            assert_eq_fn_oracle::<String>(&pool, Variant::Eq, &c).await?;
            assert_extractor_oracle::<String>(&pool, Variant::Eq, &c).await
        })
        .await
    }

    /// `text_ord` / `text_ord_ore` — full six comparisons (eq/neq + the four ord
    /// ops) plus eq_term(`hm`) identity on both, and each twin's ordering-term
    /// identity (ord_term(`op`) for `text_ord`, ord_term_ore(`ob`) for `text_ord_ore`).
    #[sqlx::test]
    async fn ord_fn_oracle(pool: PgPool) -> Result<()> {
        run_fn_property::<String, _, _>(pool, 32, |pool, c| async move {
            for variant in [Variant::Ord, Variant::OrdOre] {
                assert_eq_fn_oracle::<String>(&pool, variant, &c).await?;
                assert_ord_fn_oracle::<String>(&pool, variant, &c).await?;
                assert_extractor_oracle::<String>(&pool, variant, &c).await?;
            }
            Ok(())
        })
        .await
    }

    /// `text_search` ([Hm, Ope, Bloom]) — the eq/ord function facets plus
    /// eq_term + ord_term identity (the bloom `@>`/`<@` facet is covered by the
    /// example-based `match_smoke`, not a random oracle).
    #[sqlx::test]
    async fn search_fn_oracle(pool: PgPool) -> Result<()> {
        run_fn_property::<String, _, _>(pool, 32, |pool, c| async move {
            assert_eq_fn_oracle::<String>(&pool, Variant::Search, &c).await?;
            assert_ord_fn_oracle::<String>(&pool, Variant::Search, &c).await?;
            assert_extractor_oracle::<String>(&pool, Variant::Search, &c).await
        })
        .await
    }

    /// `text_search_ore` ([Hm, Ore, Bloom]) — the ORE twin of `text_search`. Same
    /// eq/ord function facets plus eq_term + ord_term_ore identity, but ordering
    /// rides the block-ORE term (`ord_term_ore`/`ob`) instead of the OPE term
    /// (`ord_term`/`op`). The bloom `@>`/`<@` facet is covered by `match_smoke`.
    #[sqlx::test]
    async fn search_ore_fn_oracle(pool: PgPool) -> Result<()> {
        run_fn_property::<String, _, _>(pool, 32, |pool, c| async move {
            assert_eq_fn_oracle::<String>(&pool, Variant::SearchOre, &c).await?;
            assert_ord_fn_oracle::<String>(&pool, Variant::SearchOre, &c).await?;
            assert_extractor_oracle::<String>(&pool, Variant::SearchOre, &c).await
        })
        .await
    }
}
