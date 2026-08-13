//! e2e suite: property tests for the **empty-bloom needle guard** in
//! `eql_v3.matches` (follow-up to PR #421).
//!
//! The guard (the `empty_bloom_guard` flag in
//! `crates/eql-codegen/templates/functions/wrapper.sql.j2`) fixes the
//! empty-needle bug: an empty needle bloom (`{}`, produced by a sub-trigram
//! search string with no n-gram tokens) is `@>`-contained by every value, so a
//! bare containment matched EVERY row. The guarded wrapper appends
//! `AND (cardinality(match_term(needle)) > 0 OR cardinality(match_term(value)) = 0)`,
//! giving the empty-needle case `LIKE`-shaped semantics: an empty needle
//! matches only a value whose own bloom is also empty.
//!
//! The example-based tests in `tests/encrypted_domain/text/text_match.rs`
//! (`empty_*`) pin the guard for two hand-picked fixtures (`"pq"` /
//! `"aardvark"`). This suite generalises them over **generated plaintexts,
//! freshly encrypted each run**, checking for every ordered pair `(value,
//! needle)` in each batch:
//!
//! 1. a needle with a non-empty bloom never matches a value with an empty
//!    bloom, and vice-versa (an empty needle never matches a non-empty value);
//! 2. an empty needle matches a value **iff** that value's bloom is also empty
//!    (the `'' LIKE ''` cell) — together 1+2 pin the guard's whole
//!    empty/non-empty truth table;
//! 3. the `@@` operator agrees with the by-name `eql_v3.matches` function (and
//!    its `(domain, jsonb)` convenience overload) on every pair — the guard
//!    lives in the one generated wrapper both routes share, so this pins
//!    operator/function equivalence *under the guard*;
//! 4. the premise: every sub-trigram plaintext (< `TRIGRAM_FLOOR` chars)
//!    extracts an **empty** bloom and every all-letter plaintext at/above the
//!    floor extracts a **non-empty** one — the generated-input generalisation
//!    of the example test `empty_bloom_needle_is_actually_empty`.
//!
//! On top of the guard's own truth table, pairs where bloom matching is
//! deterministic are asserted too (a bloom admits false positives but never
//! false negatives): equal plaintexts always match (across *independently
//! encrypted* ciphertexts — the bloom terms are keyed but deterministic), and a
//! substring needle always matches its superstring value (its n-grams are a
//! subset). Everything else (two non-empty blooms, not a substring pair) only
//! asserts property 3 — a containment hit there may be a legitimate bloom
//! false positive, so no plaintext oracle exists for it.
//!
//! Sub-trigram inputs cannot ride the generated fixtures — `eql-domains::
//! TEXT_FIXTURES` has no sub-trigram value (see the `v3_text_empty_bloom`
//! fixture doc) and `proptest` can only generate plaintexts, not ciphertext —
//! so this is an **e2e** suite member: each case batch-encrypts its generated
//! strings through ZeroKMS. Gated behind `proptest-e2e` and named in the
//! `test:sqlx:e2e` task (every gated suite must be listed there explicitly).
//! Shrinking/persistence are disabled like the rest of the e2e suite: a shrink
//! attempt is another ZeroKMS batch, and fresh ciphertext can't be replayed.
//!
//! The fixture-suite exclusion of the empty string (issue #262) is an
//! `_ord_ore` CHECK concern (`ob: []`); this suite encrypts with the `match`
//! index only (no `ob` term), so `""` is generated here on purpose — it is the
//! canonical `LIKE ''` needle.

use anyhow::{Context, Result};
use eql_tests::fixtures::cipherstash::encrypt_store;
use eql_tests::fixtures::index_kind::IndexKind;
use eql_tests::property::{connect_pool, ensure_eql_installed};
use proptest::prelude::*;
use proptest::test_runner::{Config, TestCaseError, TestRunner};
use sqlx::{PgPool, Row as _};

/// `public.eql_v3_text_match` — the bloom-filter (`bf`) domain whose `@@` /
/// `eql_v3.matches` carries the empty-needle guard.
const DOMAIN: &str = "public.eql_v3_text_match";

/// The tokenizer's n-gram width: a plaintext with fewer than this many
/// characters yields no tokens, i.e. an **empty** bloom. Property 4 pins this
/// premise over generated inputs; if a client change moves the floor, this
/// suite fails loudly here rather than the guard properties passing vacuously.
const TRIGRAM_FLOOR: usize = 3;

/// One freshly encrypted row: the plaintext, its payload JSON literal, and the
/// **measured** bloom cardinality (`cardinality(eql_v3.match_term(...))`, read
/// back from SQL). Classifying by measurement rather than by plaintext length
/// keeps properties 1–3 honest even for inputs whose tokenization is not
/// letter-run shaped (property 4 separately pins the length ⇒ cardinality
/// premise for the all-letter generator).
struct MatchRow {
    plaintext: String,
    payload_json: String,
    bloom_cardinality: i32,
}

impl MatchRow {
    fn bloom_is_empty(&self) -> bool {
        self.bloom_cardinality == 0
    }
}

/// Cast a payload JSON literal to the match domain.
fn cast(payload_json: &str) -> String {
    format!("'{}'::jsonb::{DOMAIN}", payload_json.replace('\'', "''"))
}

/// Render a payload JSON literal as bare `jsonb` (for the `(domain, jsonb)`
/// overload of `eql_v3.matches`, which casts the needle itself).
fn jsonb(payload_json: &str) -> String {
    format!("'{}'::jsonb", payload_json.replace('\'', "''"))
}

/// Batch-encrypt `values` with the `match` index (one ZeroKMS round trip) and
/// read back each payload's bloom cardinality in one `SELECT`.
async fn encrypt_match_rows(pool: &PgPool, values: &[String]) -> Result<Vec<MatchRow>> {
    let payloads = encrypt_store(
        "proptest_empty_bloom",
        "payload",
        values,
        // `match` alone: the bloom `bf` is the only term under test, and
        // omitting `ore` keeps the empty string encryptable (its `ob: []`
        // would otherwise be the issue-#262 CHECK failure, which is an
        // `_ord_ore` concern unrelated to this guard).
        &[IndexKind::Match],
    )
    .await?;
    anyhow::ensure!(
        payloads.len() == values.len(),
        "encrypt_store returned {} payloads for {} plaintext values",
        payloads.len(),
        values.len()
    );

    let payload_jsons: Vec<String> = payloads.iter().map(|p| p.to_string()).collect();
    let sql = format!(
        "SELECT {}",
        payload_jsons
            .iter()
            .map(|p| format!("cardinality(eql_v3.match_term({}))", cast(p)))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let row = sqlx::query(&sql)
        .fetch_one(pool)
        .await
        .with_context(|| format!("bloom-cardinality batch query: {sql}"))?;

    values
        .iter()
        .zip(payload_jsons)
        .enumerate()
        .map(|(i, (plaintext, payload_json))| {
            let bloom_cardinality: i32 = row
                .try_get(i)
                .with_context(|| format!("reading cardinality column {i} of: {sql}"))?;
            Ok(MatchRow {
                plaintext: plaintext.clone(),
                payload_json,
                bloom_cardinality,
            })
        })
        .collect()
}

/// Property 4 — the premise: sub-trigram plaintexts extract an empty bloom;
/// all-letter plaintexts at/above the floor extract a non-empty one. The
/// generator emits `[a-z]*` only, so `chars().count()` against the floor is a
/// complete classification for every generated value (no tokenizer-splitting
/// ambiguity from whitespace/punctuation).
fn assert_bloom_premise(rows: &[MatchRow]) -> Result<()> {
    for row in rows {
        let len = row.plaintext.chars().count();
        if len < TRIGRAM_FLOOR {
            anyhow::ensure!(
                row.bloom_is_empty(),
                "sub-trigram plaintext {:?} ({len} chars < floor {TRIGRAM_FLOOR}) must extract \
                 an empty bloom, got cardinality {}",
                row.plaintext,
                row.bloom_cardinality
            );
        } else {
            anyhow::ensure!(
                !row.bloom_is_empty(),
                "plaintext {:?} ({len} chars >= floor {TRIGRAM_FLOOR}) must extract a non-empty \
                 bloom, got cardinality 0",
                row.plaintext
            );
        }
    }
    Ok(())
}

/// Properties 1–3 over every ordered pair `(value, needle)`, plus the
/// deterministic-hit cells (equal plaintexts, substring needles).
async fn assert_guard_pairs(pool: &PgPool, rows: &[MatchRow]) -> Result<()> {
    for value in rows {
        for needle in rows {
            let v = cast(&value.payload_json);
            let n = cast(&needle.payload_json);
            let n_jsonb = jsonb(&needle.payload_json);
            let sql = format!(
                "SELECT ({v}) @@ ({n}), eql_v3.matches({v}, {n}), eql_v3.matches({v}, {n_jsonb})"
            );
            let (op_hit, fn_hit, fn_jsonb_hit): (Option<bool>, Option<bool>, Option<bool>) =
                sqlx::query_as(&sql)
                    .fetch_one(pool)
                    .await
                    .with_context(|| format!("guard pair query: {sql}"))?;
            let op_hit = op_hit.context("`@@` returned NULL for non-NULL operands")?;

            let pv = &value.plaintext;
            let pn = &needle.plaintext;

            // Property 3: operator ≡ by-name function ≡ (domain, jsonb) overload.
            anyhow::ensure!(
                fn_hit == Some(op_hit),
                "eql_v3.matches({pv:?}, {pn:?}) = {fn_hit:?} disagrees with `@@` = {op_hit}"
            );
            anyhow::ensure!(
                fn_jsonb_hit == Some(op_hit),
                "eql_v3.matches({pv:?}, {pn:?}::jsonb) = {fn_jsonb_hit:?} disagrees with \
                 `@@` = {op_hit}"
            );

            if needle.bloom_is_empty() {
                // Properties 1 (vice-versa) + 2: an empty needle matches a value
                // iff the value's own bloom is also empty ('' LIKE '' — never
                // the pre-guard match-everything).
                let want = value.bloom_is_empty();
                anyhow::ensure!(
                    op_hit == want,
                    "empty-bloom needle {pn:?} vs value {pv:?} (bloom cardinality {}): \
                     expected {want}, got {op_hit}",
                    value.bloom_cardinality
                );
            } else if value.bloom_is_empty() {
                // Property 1: a non-empty needle can never be contained by an
                // empty value bloom (the 'catty' LIKE 'cat'-shaped miss).
                anyhow::ensure!(
                    !op_hit,
                    "non-empty needle {pn:?} must not match empty-bloom value {pv:?}"
                );
            } else if pv == pn {
                // Both non-empty, equal plaintexts: bloom terms are keyed but
                // deterministic, so independently encrypted ciphertexts of one
                // plaintext must match (no false negatives).
                anyhow::ensure!(
                    op_hit,
                    "equal plaintexts {pv:?} must match across independently encrypted \
                     ciphertexts"
                );
            } else if pv.contains(pn.as_str()) {
                // Both non-empty, needle a substring of value: the needle's
                // n-grams are a subset of the value's, so the bloom must hit
                // (no false negatives).
                anyhow::ensure!(
                    op_hit,
                    "substring needle {pn:?} must match its superstring value {pv:?}"
                );
            }
            // Remaining cell (both non-empty, unequal, not a substring): a hit
            // may be a legitimate bloom false positive — no plaintext oracle,
            // property 3 above is the only assertion.
        }
    }
    Ok(())
}

/// Per-case plaintext batch: 2–6 random strings, each drawn sub-trigram
/// (`[a-z]{0,2}` — including `""`, the canonical `LIKE ''` needle) or
/// full-length (`[a-z]{3,8}`), biased toward the sub-trigram values the guard
/// exists for.
fn batch_strategy() -> impl Strategy<Value = Vec<String>> {
    let sub = proptest::string::string_regex("[a-z]{0,2}").expect("valid regex");
    let full = proptest::string::string_regex("[a-z]{3,8}").expect("valid regex");
    prop::collection::vec(prop_oneof![sub, full], 2..7)
}

/// Deterministic seeds appended to every generated batch:
/// - `""` / `"a"` / `"pq"` — the three sub-trigram shapes (empty, one char,
///   the PR #421 pinned example), guaranteeing every case exercises the guard;
/// - `"aardvark"` — the non-empty control from the example tests;
/// - a duplicate of the batch's first value — the equal-plaintext /
///   distinct-ciphertext cell always fires;
/// - a 3-char prefix of the first full-length value — the substring-needle
///   deterministic hit always fires. The fixed seeds (which include the
///   full-length `"aardvark"`) are appended *before* the prefix is selected, so
///   even a batch of only sub-trigram generated values still yields a
///   full-length value to prefix.
fn seeded(mut values: Vec<String>) -> Vec<String> {
    let dup = values[0].clone();
    // Append the fixed seeds before selecting `prefix`: `"aardvark"` guarantees
    // a value at/above the trigram floor exists, so `prefix` is never `None`
    // (an all-sub-trigram generated batch would otherwise skip the
    // substring-needle pair the doc above promises always fires).
    values.extend(["", "a", "pq", "aardvark"].iter().map(|s| s.to_string()));
    let prefix = values
        .iter()
        .find(|v| v.chars().count() >= TRIGRAM_FLOOR)
        .map(|v| v.chars().take(TRIGRAM_FLOOR).collect::<String>());
    values.push(dup);
    values.extend(prefix);
    values
}

/// Each case is one ZeroKMS batch (like the scalar e2e oracle), so the case
/// count stays low; the deterministic seeds mean even one case covers all four
/// properties.
#[test]
fn empty_bloom_guard_oracle() -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let pool: PgPool = rt.block_on(connect_pool())?;
    rt.block_on(ensure_eql_installed(&pool, &super::migrator()))?;

    let mut runner = TestRunner::new(Config {
        cases: 8,
        // Shrinking re-encrypts (another ZeroKMS batch per attempt) and fresh
        // ciphertext can't be replayed across runs — disabled like e2e_oracle.
        max_shrink_iters: 0,
        failure_persistence: None,
        ..Config::default()
    });
    runner
        .run(&batch_strategy(), |values| {
            let values = seeded(values);
            let rows = rt
                .block_on(encrypt_match_rows(&pool, &values))
                // `{e:#}` keeps anyhow's full cause chain.
                .map_err(|e| TestCaseError::fail(format!("encrypt: {e:#}")))?;
            assert_bloom_premise(&rows)
                .map_err(|e| TestCaseError::fail(format!("bloom premise: {e:#}")))?;
            rt.block_on(assert_guard_pairs(&pool, &rows))
                .map_err(|e| TestCaseError::fail(format!("guard pairs: {e:#}")))?;
            Ok(())
        })
        .map_err(|e| anyhow::anyhow!("empty-bloom guard property failed: {e}"))
}
