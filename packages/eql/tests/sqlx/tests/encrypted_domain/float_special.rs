//! Float edge-case behavioural regression suite (CIP — real/double).
//!
//! Captures the NaN / `-0.0` / `+0.0` / `±Inf` behaviour that the shared
//! all-pairs oracle deliberately excludes from its fixtures (NaN is unordered
//! and unspecified in the encoder; `-0.0` canonicalizes to `+0.0`). It encrypts
//! the special values FRESH through cipherstash at test time, so NaN never
//! enters the `double` fixture table.
//!
//! IMPORTANT: the NaN eq/order outcomes asserted here are an **artifact of the
//! canonical NaN bit pattern + deterministic index terms (hm/ore are pure
//! functions of plaintext+key)**, NOT a supported guarantee, and they diverge
//! from IEEE (`NaN != NaN`). They are discovered-and-locked on first run.
//!
//! **The two ordering domains disagree on `-0.0` vs `+0.0`.** `_ord_ore`
//! (block-ORE) rides the `orderable-bytes` encoder, which canonicalizes
//! `-0.0 -> +0.0` before encoding, so the two are order-equal there. `_ord`
//! (CLLW-OPE) does NOT canonicalize: their `op` terms differ outright and it
//! orders `-0.0 < +0.0`. The previous canary comment here predicted exactly this
//! ("a dormant alternative encoder, `cllw-ore`, instead distinguishes them");
//! the flip happened when the `_ord` default moved from block-ORE to CLLW-OPE.
//! Both behaviours are pinned below, one test per domain — for `ORDER BY` and
//! for `=`. The `=` split on `_ord` shares its root cause (and its
//! `known_failure` marker) with the `_eq` split in #387, so a fix there turns
//! the `_ord` pin RED rather than letting the two domains silently diverge.

use anyhow::Result;
use eql_tests::fixtures::cipherstash::encrypt_store;
use eql_tests::fixtures::eql_plaintext::EqlPlaintext;
use eql_tests::fixtures::index_kind::IndexKind;
use eql_tests::known_failure;
use eql_tests::known_failure::ISSUE_FLOAT_SIGNED_ZERO_EQ;
use eql_tests::property::{connect_pool, ensure_eql_installed};
use eql_tests::scalar_domains::{ScalarType, Variant, F4, F8};
use sqlx::PgPool;

/// The signed-zero pair (`-0.0`, `+0.0`) for a float scalar. `SignedScalar`
/// already yields `+0.0` via `origin()`, but not `-0.0`, so this local trait
/// supplies both and lets the ±0.0 tests run over `real` (F4) as well as
/// `double` (F8) — they share the same crypto path, so both must be pinned.
trait SignedZeroPair: EqlPlaintext + ScalarType {
    fn neg_zero() -> Self;
    fn pos_zero() -> Self;
}

impl SignedZeroPair for F4 {
    fn neg_zero() -> Self {
        F4(-0.0)
    }
    fn pos_zero() -> Self {
        F4(0.0)
    }
}

impl SignedZeroPair for F8 {
    fn neg_zero() -> Self {
        F8(-0.0)
    }
    fn pos_zero() -> Self {
        F8(0.0)
    }
}

/// Encrypt one batch of float special values into payload JSON strings, one
/// ZeroKMS round trip. Mirrors `e2e_oracle::encrypt_rows` but returns only the
/// payloads (these tests key on position, not plaintext). `encrypt_store`
/// encrypts through cipherstash-client directly — it needs no `PgPool` — and
/// returns v3-envelope payloads (converted via eql_bindings::from_v2), so
/// the casts below satisfy the `v = '3'` domain CHECKs. Generic over the float
/// scalar so the ±0.0 tests can encrypt `real` (F4) and `double` (F8) alike.
async fn encrypt_specials<T: EqlPlaintext>(values: &[T]) -> Result<Vec<String>> {
    let payloads = encrypt_store(
        "float_special",
        "payload",
        values,
        // `Ope` is required for the `_ord` casts below (its CHECK requires `op`);
        // `Ore` for the `_ord_ore` casts. Both are requested so one encryption
        // batch serves the OPE and block-ORE ordering paths.
        &[IndexKind::Unique, IndexKind::Ore, IndexKind::Ope],
    )
    .await?;
    Ok(payloads.into_iter().map(|p| p.to_string()).collect())
}

/// Encrypt the ±0.0 pair for the float scalar `T` in one ZeroKMS round trip,
/// returning `[payload(-0.0), payload(+0.0)]`. Shared by every ±0.0 test so each
/// runs identically over `real` and `double`.
async fn signed_zero_payloads<T: SignedZeroPair>() -> Result<Vec<String>> {
    encrypt_specials(&[T::neg_zero(), T::pos_zero()]).await
}

/// `T`'s SQL domain for `variant` (e.g. `public.eql_v3_real_ord` /
/// `public.eql_v3_double_ord`). Lets the generic ±0.0 helpers name the right
/// per-type domain in both the cast and the failure message.
fn domain<T: ScalarType>(variant: Variant) -> String {
    T::sql_domain(variant)
}

/// Cast a payload literal to `public.eql_v3_double` and read it back, proving the domain
/// CHECK accepts the encrypted special value.
async fn cast_passes_check(pool: &PgPool, payload: &str) -> Result<()> {
    let sql = "SELECT ($1::jsonb::public.eql_v3_double) IS NOT NULL";
    let ok: bool = sqlx::query_scalar(sql)
        .bind(payload)
        .fetch_one(pool)
        .await?;
    anyhow::ensure!(
        ok,
        "payload failed the public.eql_v3_double CHECK: {payload}"
    );
    Ok(())
}

/// Compare two payloads under an operator on `public.eql_v3_double_ord` — the default
/// ordering domain, backed by CLLW-OPE (`op`). Used by the NaN/±Inf pins, which
/// stay `double`-only (the ±0.0 pins parameterise over `real`/`double` via
/// `cmp_on` + `domain::<T>` instead).
async fn ord_cmp(pool: &PgPool, a: &str, op: &str, b: &str) -> Result<bool> {
    cmp_on(pool, "public.eql_v3_double_ord", a, op, b).await
}

async fn cmp_on(pool: &PgPool, d: &str, a: &str, op: &str, b: &str) -> Result<bool> {
    let sql = format!("SELECT ($1::jsonb::{d} {op} $2::jsonb::{d})");
    Ok(sqlx::query_scalar(&sql)
        .bind(a)
        .bind(b)
        .fetch_one(pool)
        .await?)
}

/// Equality under the `_eq` domain (HMAC).
async fn eq_cmp(pool: &PgPool, a: &str, b: &str) -> Result<bool> {
    let d = "public.eql_v3_double_eq";
    let sql = format!("SELECT ($1::jsonb::{d} = $2::jsonb::{d})");
    Ok(sqlx::query_scalar(&sql)
        .bind(a)
        .bind(b)
        .fetch_one(pool)
        .await?)
}

async fn setup() -> Result<PgPool> {
    let pool = connect_pool().await?;
    ensure_eql_installed(&pool, &crate::property::migrator()).await?;
    Ok(pool)
}

#[tokio::test]
async fn nan_encrypts_and_passes_check() -> Result<()> {
    // Encrypting f64::NAN succeeds (no panic) and yields a structurally valid
    // public.eql_v3_double payload. This is the one universal NaN guarantee.
    let pool = setup().await?;
    let payloads = encrypt_specials(&[F8(f64::NAN)]).await?;
    assert_eq!(payloads.len(), 1);
    cast_passes_check(&pool, &payloads[0]).await?;
    Ok(())
}

#[tokio::test]
async fn two_encryptions_of_same_nan_bits_compare_equal() -> Result<()> {
    // ARTIFACT, NOT A GUARANTEE: index terms are deterministic functions of
    // plaintext+key, so two encryptions of the SAME canonical NaN bit pattern
    // produce the same hm/ore terms and compare equal under `=` — diverging from
    // IEEE (NaN != NaN). Locked on first run; if the encoder's canonical NaN
    // handling changes, this fails loudly and the comment must be revisited.
    let pool = setup().await?;
    let p = encrypt_specials(&[F8(f64::NAN), F8(f64::NAN)]).await?;
    let equal = eq_cmp(&pool, &p[0], &p[1]).await?;
    assert!(
        equal,
        "two encryptions of canonical NaN compare equal (artifact of deterministic terms)"
    );
    Ok(())
}

/// Generic body of `negative_zero_and_positive_zero_share_ore_order`, run per
/// float type: block-ORE orders `-0.0` and `+0.0` equal on `T`'s `_ord_ore`.
async fn share_ore_order<T: SignedZeroPair>(pool: &PgPool) -> Result<()> {
    let d = domain::<T>(Variant::OrdOre);
    let p = signed_zero_payloads::<T>().await?;
    anyhow::ensure!(
        !cmp_on(pool, &d, &p[0], "<", &p[1]).await?,
        "-0.0 not < +0.0 under block-ORE ({d})"
    );
    anyhow::ensure!(
        !cmp_on(pool, &d, &p[1], "<", &p[0]).await?,
        "+0.0 not < -0.0 under block-ORE ({d})"
    );
    Ok(())
}

#[tokio::test]
async fn negative_zero_and_positive_zero_share_ore_order() -> Result<()> {
    // Block-ORE rides the `orderable-bytes` encoder, which canonicalizes
    // -0.0 -> +0.0 before encoding, so `_ord_ore` orders them equal — matching
    // IEEE (-0.0 == 0.0). Contrast `negative_zero_orders_below_positive_zero_
    // under_ope`: the OPE term does NOT canonicalize. `real` and `double` share
    // the encoder, so both are pinned.
    let pool = setup().await?;
    share_ore_order::<F4>(&pool).await?;
    share_ore_order::<F8>(&pool).await
}

/// Generic body of `negative_zero_orders_below_positive_zero_under_ope`, run per
/// float type: CLLW-OPE orders `-0.0 < +0.0` on `T`'s `_ord`.
async fn orders_below_under_ope<T: SignedZeroPair>(pool: &PgPool) -> Result<()> {
    let d = domain::<T>(Variant::Ord);
    let p = signed_zero_payloads::<T>().await?;
    anyhow::ensure!(
        cmp_on(pool, &d, &p[0], "<", &p[1]).await?,
        "-0.0 < +0.0 under CLLW-OPE ({d})"
    );
    anyhow::ensure!(
        !cmp_on(pool, &d, &p[1], "<", &p[0]).await?,
        "+0.0 not < -0.0 under CLLW-OPE ({d})"
    );
    Ok(())
}

#[tokio::test]
async fn negative_zero_orders_below_positive_zero_under_ope() -> Result<()> {
    // CLLW-OPE does NOT canonicalize the sign of zero: `op(-0.0)` and `op(+0.0)`
    // are different ciphertexts, and native bytea comparison puts `-0.0` first.
    // So the OPE-backed `_ord` domain DIVERGES from IEEE here, where block-ORE
    // agreed with it. This is a deliberate, pinned consequence of `_ord` moving
    // to CLLW-OPE — a float column that must treat ±0.0 as equal for ORDER BY
    // should be typed `_ord_ore`. `real` and `double` share the SEM, so both are
    // pinned.
    let pool = setup().await?;
    orders_below_under_ope::<F4>(&pool).await?;
    orders_below_under_ope::<F8>(&pool).await
}

/// `-0.0` and `+0.0` are IEEE-equal, so encrypted `=` on `_eq` must agree.
///
/// KNOWN FAILURE ([#387]): it does not. `cipherstash-client` feeds the raw
/// `f64::to_be_bytes()` — sign bit included — into the `hm` HMAC, so the two
/// zeroes hash differently and `WHERE col = 0.0` misses rows stored as `-0.0`.
/// The `orderable-bytes` ORE encoder canonicalizes `-0.0 -> +0.0`, so `ob`
/// disagrees with `hm` about the same pair. Unrelated to the `_ord` ordering
/// SEM: it reproduces identically on the block-ORE default.
///
/// The assertion below is written the way it SHOULD pass. [`known_failure`]
/// inverts it: this test goes green while #387 reproduces, and turns RED the
/// moment the bug is fixed — at which point delete the marker and keep the
/// assertion.
///
/// Split out of the ordering assertions because it used to run first and abort
/// the test, so the ORE ordering canary below it had never actually executed.
///
/// [#387]: https://github.com/cipherstash/encrypt-query-language/issues/387
///
/// Generic body of `negative_zero_and_positive_zero_compare_equal_under_eq`, run
/// per float type against `T`'s `_eq` domain (e.g. `public.eql_v3_real_eq` /
/// `public.eql_v3_double_eq`). Keeps the `known_failure` inversion intact per
/// type.
async fn eq_split<T: SignedZeroPair>(pool: &PgPool) -> Result<()> {
    let d = domain::<T>(Variant::Eq);
    let p = signed_zero_payloads::<T>().await?;

    let equal = cmp_on(pool, &d, &p[0], "=", &p[1]).await?;
    let assertion = if equal {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "encrypted `=` on {d} returned false for -0.0 vs +0.0"
        ))
    };
    known_failure(
        ISSUE_FLOAT_SIGNED_ZERO_EQ,
        &format!("-0.0 == +0.0 under {d}"),
        assertion,
    )
}

#[tokio::test]
async fn negative_zero_and_positive_zero_compare_equal_under_eq() -> Result<()> {
    let pool = setup().await?;
    eq_split::<F4>(&pool).await?;
    eq_split::<F8>(&pool).await
}

/// `=` on the OPE-backed `_ord` domain splits `±0.0` too — pinned, and pinned
/// to the SAME issue as `_eq`.
///
/// This is the assertion the changeset's "`_ord` `=` is consistent with `_eq`"
/// rationale rests on, and it is the one that must fail when that rationale
/// stops holding. `_ord` compares its `op` term, and CLLW-OPE derives `op` from
/// the same raw `f64::to_be_bytes()` (sign bit included) that [#387] feeds into
/// the `hm` HMAC — so the two zeroes land on different `op` ciphertexts and `=`
/// returns false. Fixing #387 at its root (canonicalizing the sign of zero in
/// `Plaintext::to_vec()`) fixes `hm` and `op` together: this test then turns
/// RED, the marker must go, and the "consistent with `_eq`" wording in the
/// changeset must be revisited rather than quietly outliving its premise.
///
/// Without this pin, a fix to #387 would silently leave `_ord` `=` splitting
/// `±0.0` while `_eq` stopped — the exact divergence the rationale denies.
///
/// Contrast [`negative_zero_and_positive_zero_compare_equal_under_ord_ore`]:
/// block-ORE canonicalizes, so `=` there already agrees with IEEE and needs no
/// marker. `real` shares this SEM with `double`; both are pinned, as everywhere
/// else in this module.
///
/// [#387]: https://github.com/cipherstash/encrypt-query-language/issues/387
///
/// Generic body of `negative_zero_and_positive_zero_compare_equal_under_ord`,
/// run per float type against `T`'s OPE-backed `_ord` domain. Keeps the
/// `known_failure` inversion intact per type.
async fn ord_split<T: SignedZeroPair>(pool: &PgPool) -> Result<()> {
    let d = domain::<T>(Variant::Ord);
    let p = signed_zero_payloads::<T>().await?;

    let equal = cmp_on(pool, &d, &p[0], "=", &p[1]).await?;
    let assertion = if equal {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "encrypted `=` on {d} returned false for -0.0 vs +0.0"
        ))
    };
    known_failure(
        ISSUE_FLOAT_SIGNED_ZERO_EQ,
        &format!("-0.0 == +0.0 under {d}"),
        assertion,
    )
}

#[tokio::test]
async fn negative_zero_and_positive_zero_compare_equal_under_ord() -> Result<()> {
    let pool = setup().await?;
    ord_split::<F4>(&pool).await?;
    ord_split::<F8>(&pool).await
}

/// Generic body of `negative_zero_and_positive_zero_compare_equal_under_ord_ore`,
/// run per float type: `=` on `T`'s block-ORE `_ord_ore` agrees with IEEE.
async fn ord_ore_equal<T: SignedZeroPair>(pool: &PgPool) -> Result<()> {
    let d = domain::<T>(Variant::OrdOre);
    let p = signed_zero_payloads::<T>().await?;
    anyhow::ensure!(
        cmp_on(pool, &d, &p[0], "=", &p[1]).await?,
        "-0.0 = +0.0 under block-ORE `_ord_ore` \
         (orderable-bytes canonicalizes the sign of zero) ({d})"
    );
    Ok(())
}

/// `=` on the block-ORE `_ord_ore` domain agrees with IEEE: the
/// `orderable-bytes` encoder canonicalizes `-0.0 -> +0.0` before encoding, so
/// both zeroes share one `ob` term. Asserted unconditionally — this is the
/// behaviour `_ord` had before the CLLW-OPE flip, and the reason a float column
/// needing IEEE `±0.0` semantics should be typed `_ord_ore`. `real` and `double`
/// share the encoder, so both are pinned.
#[tokio::test]
async fn negative_zero_and_positive_zero_compare_equal_under_ord_ore() -> Result<()> {
    let pool = setup().await?;
    ord_ore_equal::<F4>(&pool).await?;
    ord_ore_equal::<F8>(&pool).await
}

#[tokio::test]
async fn infinities_order_correctly() -> Result<()> {
    // Redundant spot-check of the boundary ordering: -Inf < 0 < +Inf through the
    // encrypted _ord domain (no decryption).
    let pool = setup().await?;
    let p = encrypt_specials(&[F8(f64::NEG_INFINITY), F8(0.0), F8(f64::INFINITY)]).await?;
    assert!(ord_cmp(&pool, &p[0], "<", &p[1]).await?, "-Inf < 0");
    assert!(ord_cmp(&pool, &p[1], "<", &p[2]).await?, "0 < +Inf");
    assert!(ord_cmp(&pool, &p[0], "<", &p[2]).await?, "-Inf < +Inf");
    Ok(())
}

#[tokio::test]
async fn nan_order_position_is_deterministic_and_total() -> Result<()> {
    // TRIPWIRE for encoder drift — NOT a direction guarantee.
    //
    // NaN is "unordered and unspecified" by design, so we deliberately do NOT
    // pin WHERE NaN sorts relative to finite / ±Inf values (that position is an
    // encoder artifact and may change). But the btree index the `_ord` domain
    // rides on (now CLLW-OPE over bytea) requires a *total, deterministic*
    // order: the same
    // plaintext must always land at the same position, and every pair must
    // resolve to exactly one of `<` / `=` / `>`. If a future encoder change
    // makes NaN's position non-deterministic (same bits, different sort slot ->
    // btree corruption) or non-total (a comparison that follows IEEE and returns
    // false both ways), this fails loudly. The NaN==NaN equality artifact is
    // locked separately in `two_encryptions_of_same_nan_bits_compare_equal`;
    // this guards the ORDER side of the same deterministic-terms property.
    let pool = setup().await?;
    // Two independent encryptions of canonical NaN, plus a spread of references.
    let p = encrypt_specials(&[
        F8(f64::NAN),          // 0: NaN (encryption A)
        F8(f64::NAN),          // 1: NaN (encryption B)
        F8(f64::NEG_INFINITY), // 2
        F8(0.0),               // 3
        F8(f64::INFINITY),     // 4
    ])
    .await?;
    let (nan_a, nan_b) = (&p[0], &p[1]);

    for (label, r) in [("-Inf", &p[2]), ("0", &p[3]), ("+Inf", &p[4])] {
        let lt = ord_cmp(&pool, nan_a, "<", r).await?;
        let eq = ord_cmp(&pool, nan_a, "=", r).await?;
        let gt = ord_cmp(&pool, nan_a, ">", r).await?;
        // Totality: exactly one of < = > holds (NaN is NOT IEEE-incomparable here).
        assert_eq!(
            [lt, eq, gt].iter().filter(|b| **b).count(),
            1,
            "NaN vs {label} is not a total order: (<, =, >) = ({lt}, {eq}, {gt})"
        );
        // Determinism: a second independent NaN encryption lands identically.
        let (lt_b, eq_b, gt_b) = (
            ord_cmp(&pool, nan_b, "<", r).await?,
            ord_cmp(&pool, nan_b, "=", r).await?,
            ord_cmp(&pool, nan_b, ">", r).await?,
        );
        assert_eq!(
            (lt, eq, gt),
            (lt_b, eq_b, gt_b),
            "NaN's order position vs {label} is not stable across re-encryption \
             (deterministic index terms broken)"
        );
    }
    Ok(())
}
