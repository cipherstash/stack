//! Shared helpers + test-stamping macro for the per-type `<T>_ord_ope`
//! literal-payload smoke suites (one top-level module per ordered scalar, so
//! the `test:matrix:catalog-coverage` gate's `<t>_<seg>::*` pattern sees every
//! catalog `ord_ope` domain covered).
//!
//! The CLLW-OPE term (`op`) is a hex-encoded ciphertext that is
//! order-preserving under native bytea comparison, so ordering assertions can
//! be stated directly on hand-built hex strings — deterministic, no
//! encryption/fixtures needed.
//!
//! **Real ciphertexts.** cipherstash-client 0.38.1 emits `op`
//! for `ope`-indexed scalar columns, the generated `eql_v3_<T>` fixtures
//! declare the `ope` index, and the conversion routes the term through — so
//! next to the literal-payload smoke tests (which verify the SQL surface:
//! routing, inlining, index engagement, CHECK discipline) every per-type
//! module also stamps [`ope_ord_fixture_smoke!`]: real-ciphertext assertions
//! that the CLLW-OPE ciphertext order matches plaintext order (ORDER BY +
//! range predicates against the in-table plaintext oracle). CLLW-OPE
//! determinism (equal plaintexts produce byte-identical `op` terms; the
//! integer families' `=`/`<>` route through `op`, so a randomized term would
//! silently produce false negatives) is pinned on the doubles fixtures by
//! `property::cross_ciphertext` and, live, by
//! `fixtures::cipherstash::live_tests`.

/// Literal cast expression for a `public.<domain>` payload carrying BOTH the
/// exact-equality term `hm` and the CLLW-OPE hex term `op`. Domain CHECKs
/// assert key *presence*, not absence of extras, so one builder serves both
/// the `[Ope]` integer-family domains (which ignore `hm`) and text's
/// `[Hm, Ope]` (which requires it).
pub fn ope_cast(domain: &str, hm: &str, op_hex: &str) -> String {
    format!(
        "'{{\"v\":3,\"i\":{{}},\"c\":\"x\",\"hm\":\"{hm}\",\"op\":\"{op_hex}\"}}'::jsonb::public.{domain}"
    )
}

/// Stamp the shared `_ord_ope` smoke tests for one domain. The assertions are
/// routing-agnostic: ordering pairs differ in BOTH `hm` and `op` (so they hold
/// whether `<` routes through `op` — every type — and whether `=`/`<>` route
/// through `op` (integer families) or `hm` (text)); the inequality case
/// differs in both terms for the same reason. Type-specific behaviour (text's
/// hm-routed equality, blockers, ORDER BY, aggregates) lives in the per-type
/// module files next to the macro invocation.
#[macro_export]
macro_rules! ope_ord_smoke {
    ($domain:literal) => {
        use sqlx::PgPool;

        #[sqlx::test]
        async fn ord_ope_orders_by_decoded_bytes(pool: PgPool) -> anyhow::Result<()> {
            // Native bytea order over the decoded hex. Note: for valid
            // (even-length, lowercase) hex, lexicographic hex-STRING order
            // coincides with decoded-bytea order — each byte maps to two hex
            // digits monotonically and the prefix rules agree — so no such
            // pair can discriminate the two orders; these assertions pin
            // decode-and-compare correctness, including the mixed-length
            // prefix rule ("00" < "0100").
            for (lo, hi) in [("00ff", "0100"), ("00", "0100"), ("0a", "ff")] {
                let lt: bool = sqlx::query_scalar(&format!(
                    "SELECT ({}) < ({})",
                    $crate::ope_support::ope_cast($domain, "aa", lo),
                    $crate::ope_support::ope_cast($domain, "bb", hi)
                ))
                .fetch_one(&pool)
                .await?;
                assert!(lt, "{}: op {lo} must sort before op {hi}", $domain);

                let gt: bool = sqlx::query_scalar(&format!(
                    "SELECT ({}) > ({})",
                    $crate::ope_support::ope_cast($domain, "aa", hi),
                    $crate::ope_support::ope_cast($domain, "bb", lo)
                ))
                .fetch_one(&pool)
                .await?;
                assert!(gt, "{}: op {hi} must sort after op {lo}", $domain);
            }
            Ok(())
        }

        #[sqlx::test]
        async fn ord_ope_equality_and_inequality(pool: PgPool) -> anyhow::Result<()> {
            // Identical payloads compare equal under either routing (`op` for
            // the integer families, `hm` for text).
            let eq: bool = sqlx::query_scalar(&format!(
                "SELECT ({}) = ({})",
                $crate::ope_support::ope_cast($domain, "aa", "00ffab"),
                $crate::ope_support::ope_cast($domain, "aa", "00ffab")
            ))
            .fetch_one(&pool)
            .await?;
            assert!(eq, "{}: identical payloads must compare equal", $domain);

            // Differ in BOTH terms => not-equal under either routing.
            let neq: bool = sqlx::query_scalar(&format!(
                "SELECT ({}) <> ({})",
                $crate::ope_support::ope_cast($domain, "aa", "00ffab"),
                $crate::ope_support::ope_cast($domain, "bb", "00ffac")
            ))
            .fetch_one(&pool)
            .await?;
            assert!(
                neq,
                "{}: differing payloads must compare not-equal",
                $domain
            );
            Ok(())
        }

        #[sqlx::test]
        async fn ord_ope_check_requires_op(pool: PgPool) -> anyhow::Result<()> {
            // The domain CHECK requires the `op` key; a payload with only the
            // envelope + hm fails at the cast boundary (hm is present, so for
            // text the sole missing key is `op` too).
            let err = sqlx::query(&format!(
                "SELECT '{{\"v\":3,\"i\":{{}},\"c\":\"x\",\"hm\":\"aa\"}}'::jsonb::public.{}",
                $domain
            ))
            .execute(&pool)
            .await
            .unwrap_err();
            assert!(
                format!("{err}").contains("check constraint"),
                "{}: missing op must violate the domain CHECK, got: {err}",
                $domain
            );
            Ok(())
        }
    };
}

/// Stamp the real-ciphertext `_ord_ope` fixture tests for one scalar.
/// The generated `fixtures.eql_v3_<T>` table carries
/// client-encrypted payloads whose `op` term came out of cipherstash-client's
/// `ope` index (0.38.1+), so these assertions exercise the actual CLLW-OPE
/// cryptography against the in-table `plaintext` oracle — the coverage the
/// hand-built literal suites above deliberately do not claim.
///
/// - `$domain`  — the ope domain name (`"integer_ord_ope"`).
/// - `$scalar`  — the Rust plaintext type (`i32`), which must be `ScalarType`.
/// - `$script`  — the fixture script name (`"eql_v3_integer"`).
///
/// The fixtures path is relative to the per-type module files in
/// `tests/encrypted_domain/ope/` (all nine invokers live in this directory),
/// mirroring the matrix's `script_path` convention.
#[macro_export]
macro_rules! ope_ord_fixture_smoke {
    ($domain:literal, $scalar:ty, $script:literal) => {
        #[sqlx::test(fixtures(path = "../../../fixtures", scripts($script)))]
        async fn ord_ope_fixture_payloads_cast_and_carry_op(
            pool: sqlx::PgPool,
        ) -> anyhow::Result<()> {
            use eql_tests::scalar_domains::ScalarType;
            let table = <$scalar as ScalarType>::fixture_table_name();
            let n = <$scalar as ScalarType>::fixture_values().len() as i64;

            // Every generated payload carries a string `op` (CLLW-OPE) term…
            let with_op: i64 = sqlx::query_scalar(&format!(
                "SELECT COUNT(*) FROM {table} \
                 WHERE payload ? 'op' AND jsonb_typeof(payload->'op') = 'string'",
            ))
            .fetch_one(&pool)
            .await?;
            assert_eq!(
                with_op, n,
                "{}: every fixture payload must carry a string `op` term \
                 (regenerate fixtures on cipherstash-client 0.38.1+)",
                $domain
            );

            // …and every payload casts into the ope domain (the CHECK accepts
            // a real client ciphertext; a cast failure errors the query).
            let cast_ok: i64 = sqlx::query_scalar(&format!(
                "SELECT COUNT((payload)::public.{}) FROM {table}",
                $domain
            ))
            .fetch_one(&pool)
            .await?;
            assert_eq!(
                cast_ok, n,
                "{}: every fixture payload must cast into the domain",
                $domain
            );
            Ok(())
        }

        #[sqlx::test(fixtures(path = "../../../fixtures", scripts($script)))]
        async fn ord_ope_fixture_order_matches_plaintext_order(
            pool: sqlx::PgPool,
        ) -> anyhow::Result<()> {
            use eql_tests::scalar_domains::ScalarType;
            let table = <$scalar as ScalarType>::fixture_table_name();

            // The headline crypto property: CLLW-OPE ciphertext order (native
            // bytea comparison over the decoded `op` hex, via the extractor)
            // must equal plaintext order. Same Rust-sort oracle as the
            // matrix's ORDER BY arms.
            let mut expected: Vec<$scalar> = <$scalar as ScalarType>::fixture_values().to_vec();
            expected.sort();

            let asc: Vec<$scalar> = sqlx::query_scalar(&format!(
                "SELECT plaintext FROM {table} \
                 ORDER BY eql_v3.ord_term((payload)::public.{})",
                $domain
            ))
            .fetch_all(&pool)
            .await?;
            assert_eq!(
                asc, expected,
                "{}: ORDER BY ord_term over real ciphertexts must sort in \
                 plaintext order",
                $domain
            );

            let desc: Vec<$scalar> = sqlx::query_scalar(&format!(
                "SELECT plaintext FROM {table} \
                 ORDER BY eql_v3.ord_term((payload)::public.{}) DESC",
                $domain
            ))
            .fetch_all(&pool)
            .await?;
            let mut expected_desc = expected.clone();
            expected_desc.reverse();
            assert_eq!(
                desc, expected_desc,
                "{}: ORDER BY ord_term DESC over real ciphertexts must \
                 sort in reverse plaintext order",
                $domain
            );
            Ok(())
        }

        #[sqlx::test(fixtures(path = "../../../fixtures", scripts($script)))]
        async fn ord_ope_fixture_range_and_equality_match_plaintext_oracle(
            pool: sqlx::PgPool,
        ) -> anyhow::Result<()> {
            use eql_tests::scalar_domains::{OrderedScalar, ScalarType};
            let table = <$scalar as ScalarType>::fixture_table_name();

            // Pivot on the interior (mid) fixture value: fetch ITS real
            // payload from the table and compare every ordering/equality
            // operator's row set against the plaintext oracle. For the
            // integer families `=`/`<>` route through `op` itself, so this is
            // the real-crypto proof that op-routed equality returns exactly
            // the equal-plaintext rows (sound because CLLW-OPE is
            // deterministic); for text they route through `hm` per catalog
            // ordering.
            let mid: $scalar = <$scalar as OrderedScalar>::mid_pivot();
            let mid_lit = <$scalar as ScalarType>::to_sql_literal(&mid);
            let pivot_json: String = sqlx::query_scalar(&format!(
                "SELECT payload::text FROM {table} WHERE plaintext = {mid_lit}",
            ))
            .fetch_one(&pool)
            .await?;
            let pivot_cast = format!(
                "'{}'::jsonb::public.{}",
                pivot_json.replace('\'', "''"),
                $domain
            );

            // The term-only query operand is the pivot payload minus its
            // ciphertext `c`, cast to `query_<domain>` (prefix naming). Every
            // predicate must match the same oracle through the
            // `(storage, query_<domain>)` operators as through the
            // full-envelope operand.
            let pivot_query_cast = {
                let mut v: serde_json::Value =
                    serde_json::from_str(&pivot_json).expect("pivot payload is valid JSON");
                if let Some(o) = v.as_object_mut() {
                    o.remove("c");
                }
                // The query twin joins `query_` to the BARE name — the
                // `eql_v3_` version prefix applies to public-schema
                // column types only, not the eql_v3-schema query operands.
                format!(
                    "'{}'::jsonb::eql_v3.query_{}",
                    v.to_string().replace('\'', "''"),
                    $domain
                        .strip_prefix(eql_domains::PUBLIC_TYPNAME_PREFIX)
                        .unwrap_or($domain)
                )
            };

            let values: Vec<$scalar> = <$scalar as ScalarType>::fixture_values().to_vec();
            for op in ["<", "<=", ">", ">=", "=", "<>"] {
                let mut expected: Vec<$scalar> = values
                    .iter()
                    .filter(|v| match op {
                        "<" => **v < mid,
                        "<=" => **v <= mid,
                        ">" => **v > mid,
                        ">=" => **v >= mid,
                        "=" => **v == mid,
                        "<>" => **v != mid,
                        other => unreachable!("unexpected operator {other}"),
                    })
                    .cloned()
                    .collect();
                expected.sort();
                for (label, rhs) in [("storage", &pivot_cast), ("query", &pivot_query_cast)] {
                    let sql = format!(
                        "SELECT plaintext FROM {table} \
                         WHERE (payload)::public.{domain} {op} ({rhs})",
                        domain = $domain,
                    );
                    let mut actual: Vec<$scalar> =
                        sqlx::query_scalar(&sql).fetch_all(&pool).await?;
                    actual.sort();
                    assert_eq!(
                        actual, expected,
                        "{}: `{op}` against the real mid-pivot ciphertext ({label} operand) \
                         must match the plaintext oracle (SQL: {sql})",
                        $domain
                    );
                }
            }
            Ok(())
        }
    };
}
