//! Type-generic substrate for the encrypted-scalar-domain test matrix.
//!
//! Adding a new encrypted scalar type (e.g. `i64` for bigint, `f64` for
//! double) is one `<T> => <R>` line in the `scalar_types!` list
//! (`scalar_types.rs`) plus an `EqlPlaintext` impl and a catalog row.
//! The `impl ScalarType` below is generated from that list. Everything
//! else — the four `public.<T>{,_eq,_ord,_ord_ore}` domains, per-domain
//! payload shapes, supported operators, index extractor expressions,
//! ground-truth result sets — is derived from `T::PG_TYPE`,
//! `T::fixture_values()`, and the `Variant` enum.
//!
//! # Plaintext oracle columns: `PG_TYPE` vs `PLAINTEXT_SQL_TYPE`
//!
//! EQL stores encrypted values as **jsonb**: every `public.<T>*` domain is
//! `CREATE DOMAIN … AS jsonb`, and the ciphertext + index terms live inside the
//! JSON payload. No concrete Postgres scalar type appears in the product at all.
//!
//! The concrete Postgres type shows up in exactly one place — the **plaintext
//! oracle** columns these tests build alongside the jsonb payload: the fixture
//! tables (`fixtures.eql_v3_<T>`) and the matrix temp tables. Those columns hold
//! the cleartext ground truth that the encrypted results are checked against
//! (`ORDER BY` order, decode-and-compare, min/max/eq pivots). So `PG_TYPE` /
//! `PLAINTEXT_SQL_TYPE` are purely a *test-harness* concern; the catalog,
//! codegen, and bindings only ever know the jsonb domain *name*.
//!
//! `ScalarType` carries two members for the two roles that one string used to
//! play:
//!
//! - [`ScalarType::PG_TYPE`] — the **EQL domain token / identifier**: the suffix
//!   in the SQL domain name (`public.<PG_TYPE>_ord`) and the fixture table name
//!   (`fixtures.eql_v3_<PG_TYPE>`), plus capability lookups. Never a plaintext
//!   column type.
//! - [`ScalarType::PLAINTEXT_SQL_TYPE`] — the **actual Postgres storage type**
//!   of the cleartext value in the oracle columns. Defaults to `PG_TYPE`.
//!
//! For every scalar except `timestamp` the two coincide — `integer`, `date`,
//! `numeric`, … are each a valid Postgres type equal to their domain token.
//! `timestamp` is the sole divergence: its domain token is `timestamp` (chosen
//! to match the cipherstash cast / `ColumnType::Timestamp` / `Plaintext::Timestamp`
//! naming), but the encrypted value is a UTC **instant** — `chrono::DateTime<Utc>`,
//! the only sub-day temporal `Plaintext` variant cipherstash offers — whose
//! faithful Postgres type is `timestamp with time zone`, not the SQL-standard
//! (tz-naive) `timestamp`. The temporal impls therefore override
//! `PLAINTEXT_SQL_TYPE`, deriving it from `EqlPlaintext` (the `ScalarKind`-keyed
//! source the fixture generator also uses) so it cannot drift from a literal.
//!
//! ## Why the oracle stays `timestamp with time zone`, not `timestamp`
//!
//! The tests only assert ordering/equality, which are monotonic under any
//! faithful relabelling — so this is a deliberate choice, not a hard constraint.
//! Two reasons make the tz-aware oracle the better one:
//!
//! 1. **It would force the harness type to `NaiveDateTime`.** sqlx binds
//!    `DateTime<Utc>` only to `timestamptz` and `NaiveDateTime` only to
//!    `timestamp`, and the oracle column is decoded straight back into the
//!    scalar type. A bare `timestamp` column would require flipping the scalar
//!    from `DateTime<Utc>` to `NaiveDateTime`, rippling through the
//!    `EqlPlaintext`/encryption wiring (encryption still needs a `DateTime<Utc>`,
//!    so `to_plaintext` would call `.and_utc()` — the instant reappearing), the
//!    fixture strings, `parse`/`sql_lit`, and every test that names the type.
//! 2. **A no-tz column has no fixed instant.** Writing or casting between
//!    `timestamptz` and `timestamp` applies `AT TIME ZONE current_setting('TimeZone')`,
//!    so a `timestamp` oracle would become **session-timezone-dependent** (fine
//!    under UTC CI, silently shifted for a dev in another zone). Keeping the
//!    oracle `timestamp with time zone` makes it a faithful, environment-
//!    independent record of the encrypted instant — for the price of one const.
//!
//! Keeping `PLAINTEXT_SQL_TYPE` on `ScalarType` (rather than reading
//! `EqlPlaintext` directly at each use site) also covers view scalars like
//! `JsonbEntryInteger`, which are `ScalarType`s but deliberately *not*
//! `EqlPlaintext`s; those inherit the `PG_TYPE` default.

use anyhow::{bail, Context, Result};
use eql_domains::{Term, CATALOG};
use sqlx::PgPool;
use std::fmt::{Debug, Display};

/// One impl per scalar type. Two `const`s and the rest defaults.
pub trait ScalarType:
    Clone
    + Ord
    + Default
    + Debug
    + Display
    + Send
    + Sync
    + Unpin
    + 'static
    + for<'r> sqlx::Decode<'r, sqlx::Postgres>
    + sqlx::Type<sqlx::Postgres>
{
    /// The EQL domain token / identifier — the suffix in the SQL domain name
    /// (`public.<PG_TYPE>_ord`) and the fixture script/table name
    /// (`fixtures.eql_v3_<PG_TYPE>`). Examples: `"integer"`, `"timestamp"`. This is
    /// an *identifier*, not necessarily a valid plaintext column type — see
    /// [`ScalarType::PLAINTEXT_SQL_TYPE`] and the module docs.
    const PG_TYPE: &'static str;

    /// Postgres storage type of the `plaintext` oracle column, for tests that
    /// materialise a plaintext column or a typed `NULL` sentinel. Defaults to
    /// `PG_TYPE`, which is a valid plaintext type for every catalog scalar
    /// except `timestamp` (whose domain token is `timestamp` but whose plaintext
    /// is `timestamp with time zone`, a UTC instant) — the temporal impls
    /// override it, deriving the value from `EqlPlaintext` (the same
    /// `ScalarKind`-keyed source the fixture generator uses) so it cannot drift.
    /// Kept on `ScalarType`, not read from `EqlPlaintext` directly, because some
    /// test scalars (`JsonbEntryInteger`) are `ScalarType`s but deliberately NOT
    /// `EqlPlaintext`s; those inherit the `PG_TYPE` default. See the module docs
    /// for why the oracle stays tz-aware rather than becoming a bare `timestamp`.
    const PLAINTEXT_SQL_TYPE: &'static str = Self::PG_TYPE;

    /// Distinct plaintext values present in the fixture, in a stable
    /// order that MUST match fixture insertion order (the SQL script's
    /// `id` sequence). Callers rely on this: the fixture-shape test
    /// compares this slice element-wise against the `ORDER BY id`
    /// plaintext column, and the scale/index arms index positionally
    /// (`[0]`, `[len / 2]`) without sorting. A lazily-built `Vec` impl
    /// must therefore be built deterministically in that same order.
    ///
    /// A method rather than a `const` because non-integer scalars (e.g.
    /// `chrono::NaiveDate`, whose `from_ymd_opt` is not `const`) cannot be
    /// materialised into a const slice; the harness builds those into a
    /// `LazyLock<Vec<_>>` and returns a borrow of it (see `date_values`).
    /// Integer scalars return their `eql_domains::<T>_VALUES` const directly.
    ///
    /// For types driven by `scalar_matrix!` (caps = [eq, ord]), the values MUST
    /// include the three `OrderedScalar` pivots (`min_pivot()`, `max_pivot()`,
    /// `mid_pivot()`): the matrix uses those as comparison pivots and fetches
    /// each one's ciphertext via `fetch_fixture_payload`, which fails loudly if
    /// the row is absent.
    fn fixture_values() -> &'static [Self];

    /// `fixtures.eql_v3_<pg_type>`.
    fn fixture_table_name() -> String {
        format!("fixtures.eql_v3_{}", Self::PG_TYPE)
    }

    /// SQL domain the comparable value is cast to. Default: the generated
    /// scalar domain `public.<pg_type><variant_suffix>`. A non-scalar surface
    /// (e.g. a SteVec entry, whose single domain `public.eql_v3_json_entry` is
    /// variant-independent) overrides this to ignore the suffix.
    fn sql_domain(variant: Variant) -> String {
        format!("public.eql_v3_{}{}", Self::PG_TYPE, variant.suffix())
    }

    /// SQL expression that yields the comparable value from a fixture row.
    /// Default: the bare `payload` column (a whole encrypted-scalar payload).
    /// A SteVec-entry view overrides this with an extraction expression such
    /// as `(payload -> '<selector>')`, which already has type
    /// `public.eql_v3_json_entry`. The expression is cast to `sql_domain(variant)`
    /// at every call site, so a redundant `::public.eql_v3_json_entry` cast on an
    /// already-entry expression is a harmless no-op.
    fn column_expr() -> String {
        "payload".to_string()
    }

    /// A valid payload literal for this SQL domain family. Used by NULL
    /// propagation and typecheck tests where the payload is bound but never
    /// decrypted. Default: scalar root-envelope placeholder.
    fn placeholder_payload() -> &'static str {
        crate::helpers::PLACEHOLDER_PAYLOAD
    }

    /// Equality extractor expression for a domain-typed value expression.
    /// Default scalar Eq path is `eql_v3.eq_term(value)`.
    fn eq_extractor_expr(value_expr: &str) -> String {
        format!("eql_v3.eq_term({value_expr})")
    }

    /// Ordering extractor expression for a domain-typed value expression.
    ///
    /// The default is **catalog-derived**: it reads the variant's ordering
    /// `Term` and uses that term's own extractor name, so `_ord` (backed by
    /// `Term::Ope`) yields `eql_v3.ord_term(value)` while `_ord_ore`
    /// (backed by `Term::Ore`) yields `eql_v3.ord_term_ore(value)`. Hardcoding
    /// either name here would silently desync the harness from the generated
    /// SQL the moment a domain's ordering SEM changes.
    ///
    /// Takes `variant` because a single `T` spans several domains with
    /// different ordering terms. SteVec entries override this to
    /// the `public.jsonb_entry` overload of `eql_v3.ord_term(value)`,
    /// ignoring the variant: their ordering term
    /// lives inside the payload shape, not in the flat catalog `terms` list
    /// (`JsonbEntryInteger::PG_TYPE` is `"integer"`, whose `_ord` is OPE — a
    /// catalog lookup would give the wrong extractor).
    fn ord_extractor_expr(variant: Variant, value_expr: &str) -> String {
        let term = variant.ordering_term(Self::PG_TYPE).unwrap_or_else(|| {
            panic!(
                "ord_extractor_expr on non-ordered ({}, {variant:?})",
                Self::PG_TYPE
            )
        });
        format!("eql_v3.{}({value_expr})", term.extractor())
    }

    /// SQL-literal rendering via `Display`. Takes `&Self` so a non-`Copy`
    /// scalar (e.g. `String`) can be rendered without being consumed. Override
    /// for types whose `Display` form isn't a valid SQL literal (e.g. strings,
    /// dates).
    fn to_sql_literal(value: &Self) -> String {
        value.to_string()
    }

    /// Ground-truth result set for `WHERE col op pivot`. Default works
    /// for any `Ord` scalar; override only for non-orderable types.
    fn expected_forward(op: &str, pivot: Self) -> Vec<Self> {
        // `&Self`-taking predicate so the default impl stays generic over a
        // merely-`Clone` (non-`Copy`) scalar like `String`.
        let predicate: fn(&Self, &Self) -> bool = match op {
            "=" => |a, b| a == b,
            "<>" => |a, b| a != b,
            "<" => |a, b| a < b,
            "<=" => |a, b| a <= b,
            ">" => |a, b| a > b,
            ">=" => |a, b| a >= b,
            other => panic!("expected_forward: unsupported operator {other}"),
        };
        let mut values: Vec<Self> = Self::fixture_values()
            .iter()
            .filter(|v| predicate(v, &pivot))
            .cloned()
            .collect();
        values.sort();
        values
    }

    /// A proptest strategy producing fresh plaintexts for the e2e oracle.
    ///
    /// The e2e suite encrypts each generated value end-to-end through ZeroKMS,
    /// so the strategy MUST only produce values the type's EQL cast accepts.
    ///
    /// Required (not defaulted on purpose): a `where Self: Arbitrary` bound on a
    /// provided default leaks into the method's contract for EVERY caller —
    /// including the generic `T: ScalarType` oracle drivers — so `String` /
    /// `Decimal` / `NaiveDate` (not `Arbitrary`) could never satisfy it, even
    /// though they override the body. Making it required keeps the bound off the
    /// signature. Integers supply the full `any::<Self>()` range (proc-macro
    /// generated, in `eql-tests-macros`); non-integer scalars sample their
    /// cast-valid fixture set — the only bounded strategy `Arbitrary` can't give
    /// them, and always cast-valid because every fixture already round-trips.
    fn arbitrary_value() -> proptest::strategy::BoxedStrategy<Self>;
}

/// An **ordered** scalar — one whose `_ord` domains support `<`/`<=`/`>`/`>=`.
/// Carries the three comparison anchors the `scalar_matrix!` ordered arm sweeps:
/// the `min`/`max` boundaries and an interior `mid` pivot. All three must be
/// present verbatim in `fixture_values()` (the matrix fetches each pivot's
/// ciphertext via `fetch_fixture_payload`).
///
/// `min`/`max` are boundary anchors; `mid` is an interior anchor used by the
/// correctness/cross-shape sweep and the ORDER-BY-with-filter arm. `mid`
/// defaults to `Self::default()` — for signed scalars that is the numeric
/// origin (`0`, epoch), which is a fine interior anchor; lexicographic scalars
/// (e.g. `String`, whose `Default` is the degenerate empty string) override it
/// with a real median fixture.
pub trait OrderedScalar: ScalarType {
    /// The low boundary pivot — the smallest `fixture_values()` entry. Derived
    /// (the `ScalarType` supertrait bounds `Ord + Clone`), so it is a fixture
    /// row by construction and cannot drift out of the fixture table. No impl
    /// overrides this.
    fn min_pivot() -> Self {
        Self::fixture_values()
            .iter()
            .min()
            .expect("an ordered scalar must have at least one fixture value")
            .clone()
    }

    /// The high boundary pivot — the largest `fixture_values()` entry. Derived,
    /// like `min_pivot()`. No impl overrides this.
    fn max_pivot() -> Self {
        Self::fixture_values()
            .iter()
            .max()
            .expect("an ordered scalar must have at least one fixture value")
            .clone()
    }

    /// The interior pivot. Defaults to `Self::default()` (the numeric origin for
    /// signed scalars); override where `Default` is not a usable fixture anchor.
    /// Present verbatim in `fixture_values()`.
    fn mid_pivot() -> Self {
        Self::default()
    }
}

/// A **signed** scalar — an ordered scalar with a numeric origin / sign
/// boundary (`int`, `date`). `text` is `OrderedScalar` but **not**
/// `SignedScalar`: lexicographic order has no origin. The bound gates the
/// signed-only sign-boundary test, so a `text` instantiation of it is a compile
/// error.
pub trait SignedScalar: OrderedScalar {
    /// The numeric origin (the sign boundary): `0` for integers, the epoch for
    /// dates. Fixtures straddle it (negatives below, positives above).
    fn origin() -> Self;
}

/// A scalar with a **bloom-filter match** capability (the `@@` fuzzy match /
/// `eql_v3.matches`) — currently only `text`, the one kind that
/// declares a `Bloom`-bearing domain (`_match`/`_search`). Provides three fixture
/// plaintexts with known n-gram relationships so the generated match arms can
/// assert true hits and a deterministic miss. The bound gates the match arms: a non-match scalar
/// never declares `_search`, so the `caps = [eq, ord, search]` matrix arm (the
/// only one emitting match cases) is never instantiated for it.
pub trait MatchScalar: ScalarType {
    /// A "haystack" plaintext whose bloom filter contains [`needle`](Self::needle)
    /// (they share n-grams). Present verbatim in `fixture_values()`.
    fn haystack() -> Self;

    /// A "needle" plaintext that is a sub-token of [`haystack`](Self::haystack).
    /// Present verbatim in `fixture_values()`.
    fn needle() -> Self;

    /// A plaintext n-gram-**disjoint** from [`needle`](Self::needle), so
    /// `needle @@ disjoint` is a deterministic miss (a bloom filter only admits
    /// false positives, never false negatives). Present verbatim in
    /// `fixture_values()`.
    fn disjoint() -> Self;
}

// The per-type `impl ScalarType` blocks for the **integer** scalars (each
// carrying its `PG_TYPE` token, `fixture_values() = eql_domains::<TOKEN>_VALUES`,
// and `min_pivot()`/`max_pivot()` = `Self::MIN`/`Self::MAX`) are generated from
// the single harness list in `scalar_types.rs`. To add an integer type, add a
// `token => rust_type` line there — not an impl here.
//
// Temporal scalars (`chrono::NaiveDate`, and `DateTime<Utc>` in the stacked
// timestamp PR) are hand-written below instead: their fixture values cannot be
// a `const` slice (chrono constructors are not `const`), and their pivots are
// explicit sentinels rather than `Self::MIN`/`Self::MAX`. The macro emits only
// integer impls.
crate::scalar_types!(scalar_type_impls);

/// Generate the test wiring for one chrono-backed (temporal) scalar from its
/// catalog row: a `LazyLock<Vec<T>>` parsing the catalog fixture strings, a
/// public `<accessor>()` returning a borrow of it, `impl ScalarType for T`, and
/// a `#[cfg(test)]` module asserting the parsed values track the catalog and
/// include the pivots. The chrono analogue of `eql_domains::int_values!`
/// (integers materialise a `const` slice; temporals can't, so values live in a
/// `LazyLock`). `parse`/`sql_lit` are expressions so each type supplies its own
/// chrono parsing and SQL literal form. Boundary pivots are not parameters: they
/// derive from `fixture_values()` via the `OrderedScalar` defaults.
macro_rules! temporal_values {
    (
        cell      = $cell:ident,
        accessor  = $accessor:ident,
        rust_type = $ty:ty,
        spec      = $spec:path,
        variant   = $variant:ident,
        pg_type   = $pg:literal,
        parse     = $parse:expr,
        sql_lit   = $sql_lit:expr $(,)?
    ) => {
        static $cell: std::sync::LazyLock<Vec<$ty>> = std::sync::LazyLock::new(|| {
            let parse: fn(&str) -> $ty = $parse;
            $spec
                .values
                .iter()
                .map(|f| match f {
                    ::eql_domains::Fixture::$variant(s) => parse(s),
                    other => panic!(concat!("non-", $pg, " fixture in ", $pg, " catalog row: {:?}"), other),
                })
                .collect()
        });

        #[doc = concat!("Typed `", stringify!($ty), "` fixtures for `", $pg, "`, parsed once from the catalog.")]
        pub fn $accessor() -> &'static [$ty] {
            &$cell
        }

        impl ScalarType for $ty {
            const PG_TYPE: &'static str = $pg;
            // Derived from `EqlPlaintext` (the `ScalarKind`-keyed source of
            // truth), so the temporal plaintext type cannot drift from the one
            // the fixture generator uses. For `timestamp` this resolves to
            // `timestamp with time zone`, not the `timestamp` domain token.
            const PLAINTEXT_SQL_TYPE: &'static str =
                <$ty as $crate::fixtures::EqlPlaintext>::PLAINTEXT_SQL_TYPE.as_str();
            fn fixture_values() -> &'static [$ty] { $accessor() }
            fn to_sql_literal(value: &$ty) -> String {
                let f: fn(&$ty) -> String = $sql_lit;
                f(value)
            }
            fn arbitrary_value() -> proptest::strategy::BoxedStrategy<$ty> {
                use proptest::strategy::Strategy;
                // Sample the catalog fixture values — every one is cast-valid and
                // already exercised by the fixture suite; the e2e novelty is that
                // the SAME plaintext is independently re-encrypted, which the
                // duplicate-injection in run_e2e_property guarantees.
                proptest::sample::select($accessor().to_vec()).boxed()
            }
        }

        impl OrderedScalar for $ty {
            // Boundary pivots derive from `fixture_values()`; `mid_pivot`
            // inherits `Self::default()` (the epoch), which is `origin()` and a
            // real fixture. Nothing to override.
        }

        impl SignedScalar for $ty {
            // Temporal scalars encrypt as a signed offset from the epoch, so the
            // numeric origin is `Self::default()` (e.g. `1970-01-01`); fixtures
            // straddle it (earlier dates below, later dates above).
            fn origin() -> $ty { <$ty as ::core::default::Default>::default() }
        }

        #[cfg(test)]
        mod $accessor {
            use super::*;
            #[test]
            fn values_match_catalog_fixtures() {
                let parse: fn(&str) -> $ty = $parse;
                let want: Vec<$ty> = $spec.values.iter().map(|f| match f {
                    ::eql_domains::Fixture::$variant(s) => parse(s),
                    other => panic!("non-{} fixture: {:?}", $pg, other),
                }).collect();
                assert_eq!($accessor(), want.as_slice());
            }
            #[test]
            fn pivots_present_in_fixtures() {
                let vals = $accessor();
                assert!(vals.contains(&<$ty as OrderedScalar>::min_pivot()), "min pivot missing");
                assert!(vals.contains(&<$ty as OrderedScalar>::max_pivot()), "max pivot missing");
                // The matrix sweeps the interior `mid_pivot()` (here the default
                // origin) on every ordered suite and fetches its ciphertext via
                // `fetch_fixture_payload`, so it must be present verbatim too.
                assert!(vals.contains(&<$ty as OrderedScalar>::mid_pivot()), "mid/default pivot missing");
                assert_eq!(
                    <$ty as OrderedScalar>::mid_pivot(),
                    <$ty as SignedScalar>::origin(),
                    "for a signed temporal scalar mid_pivot == origin",
                );
            }
        }
    };
}

/// Materialise a scalar's catalog fixtures into a `LazyLock<Vec<$ty>>` plus a
/// public accessor, parsing each `Fixture` via the supplied closure. The
/// kind-agnostic core shared by every non-integer scalar: `temporal_values!`
/// adds the chrono-specific `ScalarType`/`OrderedScalar`/`SignedScalar` wiring on
/// top, while `text`/`numeric` supply their own (they are not signed). Integer
/// scalars do not use this — they materialise a `const` slice in `eql-domains`
/// (`int_values!`) and impl `ScalarType` via the proc-macro.
///
/// `$variant` is the `eql_domains::Fixture` variant this scalar's rows use
/// (`Text`/`Numeric`/`Date`/`Timestamp`); `$parse` maps each `&Fixture` to
/// `$ty` (and owns its own loud "wrong variant" panic). The accessor is `pub` so
/// the `eql_v3_<T>` fixture module can hand the slice to `scalar_fixture!`.
macro_rules! lazy_values {
    (
        cell      = $cell:ident,
        accessor  = $accessor:ident,
        rust_type = $ty:ty,
        spec      = $spec:path,
        variant   = $variant:ident,
        pg_type   = $pg:literal,
        parse     = $parse:expr $(,)?
    ) => {
        static $cell: std::sync::LazyLock<Vec<$ty>> = std::sync::LazyLock::new(|| {
            let parse: fn(&::eql_domains::Fixture) -> $ty = $parse;
            $spec.values.iter().map(parse).collect()
        });

        #[doc = concat!("Typed `", stringify!($ty), "` fixtures for `", $pg, "`, materialised once from the catalog.")]
        pub fn $accessor() -> &'static [$ty] {
            &$cell
        }
    };
}

// `date`'s `ScalarType` wiring is generated from its catalog row by
// `temporal_values!` — the chrono analogue of the integer `int_values!` path.
// Values can't be a `const` slice (`from_ymd_opt` is not `const`), so they live
// in a `LazyLock<Vec<_>>` behind `date_values()`. `date_values()` is public so
// the `eql_v3_date` fixture module (emitted by `scalar_types!(fixture_modules)`)
// can hand the slice to `scalar_fixture!`.
temporal_values! {
    cell      = DATE_VALUES_CELL,
    accessor  = date_values,
    rust_type = chrono::NaiveDate,
    spec      = eql_domains::DATE_FIXTURES,
    variant   = Date,
    pg_type   = "date",
    parse     = |s| chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .expect("catalog date fixture must be YYYY-MM-DD"),
    sql_lit   = |v| format!("'{v}'"),
}

// `timestamp`'s `ScalarType` wiring, generated from its catalog row by the
// same `temporal_values!` path as `date`. timestamp is ordered (its catalog
// row uses the ordered domain shape, 12-block ORE), and the *value* wiring is
// identical to any temporal scalar: RFC3339 strings parsed once into
// `DateTime<Utc>` behind `timestamp_values()`. The pivots are retained as the
// three min/mid/max anchors the matrix sweeps.
temporal_values! {
    cell      = TIMESTAMP_VALUES_CELL,
    accessor  = timestamp_values,
    rust_type = chrono::DateTime<chrono::Utc>,
    spec      = eql_domains::TIMESTAMP_FIXTURES,
    variant   = Timestamp,
    pg_type   = "timestamp",
    parse     = |s| chrono::DateTime::parse_from_rfc3339(s)
        .expect("catalog timestamp fixture must be RFC3339")
        .with_timezone(&chrono::Utc),
    sql_lit   = |v| format!("'{}'", v.to_rfc3339()),
}

/// Focused guards for the timestamp value wiring that the `temporal_values!`
/// auto-generated tests can't cover, because every catalog fixture is already
/// `…Z` (UTC). Both tests intentionally live in the harness, not in
/// `eql-domains`, which is deliberately zero-dep (no chrono).
#[cfg(test)]
mod timestamp_value_guards {
    use super::*;

    // Mirror of the `temporal_values!` parse closure above. Kept independent so
    // a regression that drops the offset→UTC conversion in the macro invocation
    // is caught here rather than re-running the (all-UTC, tautological) catalog
    // fixtures.
    fn parse(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s)
            .expect("RFC3339")
            .with_timezone(&chrono::Utc)
    }

    /// The type's headline guarantee ("Values are UTC-normalized") exercised
    /// with a genuinely non-UTC input. Passes today; fails the moment the parse
    /// path stops converting offsets to UTC (e.g. a switch to `.naive_utc()` or
    /// constructing the `DateTime<Utc>` from the naive local time).
    #[test]
    fn rfc3339_offset_is_normalized_to_utc() {
        use chrono::{Datelike, Timelike};
        // 05:00 at +05:00 is midnight UTC — same instant as the Z form.
        assert_eq!(
            parse("2000-01-01T05:00:00+05:00"),
            parse("2000-01-01T00:00:00Z"),
        );
        // …and it lands on the UTC wall-clock, not the offset-local one.
        let utc = parse("2000-01-01T05:00:00+05:00");
        assert_eq!((utc.hour(), utc.day()), (0, 1));
    }

    /// `eql-domains::invariant_tests::fixture_values_are_distinct_by_resolved_number`
    /// keys `Fixture::Timestamp` by its literal string, so two RFC3339 strings
    /// that denote the same UTC instant (e.g. `…00:00Z` vs `…01:00+01:00`) would
    /// pass as "distinct" there. The fixture *table* keys on the parsed
    /// `DateTime<Utc>`, so an aliasing pair would silently insert duplicate
    /// `plaintext` rows and break `fetch_fixture_payload`'s `fetch_one`. This
    /// guards distinctness by instant, which is the property the table relies on.
    #[test]
    fn fixtures_are_distinct_by_instant() {
        use std::collections::HashSet;
        let vals = timestamp_values(); // &[DateTime<Utc>], parsed from the catalog
        let unique: HashSet<_> = vals.iter().collect();
        assert_eq!(
            unique.len(),
            vals.len(),
            "two timestamp fixtures alias to the same UTC instant",
        );
    }
}

// `text` is hand-written rather than driven by `temporal_values!`: it is an
// owned `String` (not chrono-backed), so it materialises its values from the
// `eql_domains::TEXT_VALUES` const slice rather than parsing catalog strings.
// `text_values()` is public so the `eql_v3_text` fixture module (emitted by
// `scalar_types!(fixture_modules)`) can hand the slice to `scalar_fixture!`.

// `text`'s value wiring now goes through the shared `lazy_values!` materializer
// (the same macro `numeric` uses), parsing the catalog's `Fixture::Text` rows
// directly. `text_values()` stays public so the `eql_v3_text` fixture module
// (emitted by `scalar_types!(fixture_modules)`) can hand the slice to
// `scalar_fixture!`. The `to_sql_literal` / `mid_pivot` / `MatchScalar` methods
// below are `text`'s genuinely-differing bits and remain hand-written.
lazy_values! {
    cell      = TEXT_VALUES_CELL,
    accessor  = text_values,
    rust_type = String,
    spec      = eql_domains::TEXT_FIXTURES,
    variant   = Text,
    pg_type   = "text",
    parse     = |f| match f {
        eql_domains::Fixture::Text(s) => s.to_string(),
        other => panic!("non-text fixture in text catalog row: {other:?}"),
    },
}

impl ScalarType for String {
    const PG_TYPE: &'static str = "text";

    fn fixture_values() -> &'static [Self] {
        text_values()
    }

    /// `Display` for a `String` is the unquoted text, which is not a valid SQL
    /// literal; quote it and double any embedded single quotes.
    fn to_sql_literal(value: &Self) -> String {
        format!("'{}'", value.replace('\'', "''"))
    }

    fn arbitrary_value() -> proptest::strategy::BoxedStrategy<Self> {
        use proptest::strategy::Strategy;
        proptest::sample::select(text_values().to_vec()).boxed()
    }
}

impl OrderedScalar for String {
    /// Interior pivot — a real median fixture. `String::default()` is `""`,
    /// which is degenerate for ORE (issue #262), so `text` overrides the
    /// inherited default with a genuine middle value. The boundary pivots are
    /// inherited (derived from `fixture_values()` = `"aard"`/`"zzzz"`).
    fn mid_pivot() -> Self {
        "frank".to_string()
    }
}

impl MatchScalar for String {
    /// `"aardvark"` — its bloom filter contains `"aard"` (shared 3-grams
    /// `aar`, `ard`). Matches the haystack used by the sibling `text_match`
    /// behavioural suite. Present verbatim in `TEXT_FIXTURES`.
    fn haystack() -> Self {
        "aardvark".to_string()
    }

    /// `"aard"` — a sub-token of `"aardvark"`.
    fn needle() -> Self {
        "aard".to_string()
    }

    /// `"zzzz"` — 3-gram-disjoint from `"aard"` (`zzz` vs `aar`/`ard`), so
    /// `aard @@ zzzz` is a deterministic miss. Kept disjoint in `TEXT_FIXTURES`
    /// precisely for this assertion.
    fn disjoint() -> Self {
        "zzzz".to_string()
    }
}

// `String` is deliberately NOT `SignedScalar`: lexicographic text has no
// numeric origin / sign boundary. The signed-only sign-boundary test bounds on
// `SignedScalar`, so a `String` instantiation of it would not compile.

// `numeric` is hand-written (like `text`): an owned `rust_decimal::Decimal`,
// not chrono-backed, so it parses the catalog's `Fixture::Numeric` strings into
// a `LazyLock<Vec<Decimal>>` rather than going through `temporal_values!`. The
// catalog stays zero-dep, so the parse happens here, not in `eql-domains`.

// `numeric`'s value wiring goes through the shared `lazy_values!` materializer
// (same as `text`), parsing the catalog's `Fixture::Numeric` strings into
// `Decimal`. `numeric_values()` stays public so the `eql_v3_numeric` fixture
// module (emitted by `scalar_types!(fixture_modules)`) can hand the slice to
// `scalar_fixture!`. `numeric` has no `to_sql_literal`/`mid_pivot` overrides —
// only the value materialization is shared.
lazy_values! {
    cell      = NUMERIC_VALUES_CELL,
    accessor  = numeric_values,
    rust_type = rust_decimal::Decimal,
    spec      = eql_domains::NUMERIC_FIXTURES,
    variant   = Numeric,
    pg_type   = "numeric",
    parse     = |f| match f {
        eql_domains::Fixture::Numeric(s) => {
            use std::str::FromStr;
            rust_decimal::Decimal::from_str(s)
                .unwrap_or_else(|e| panic!("invalid numeric catalog fixture {s:?}: {e}"))
        }
        other => panic!("non-numeric fixture in numeric catalog row: {other:?}"),
    },
}

impl ScalarType for rust_decimal::Decimal {
    const PG_TYPE: &'static str = "numeric";

    fn fixture_values() -> &'static [Self] {
        numeric_values()
    }
    // `to_sql_literal` inherits the default (`value.to_string()`): a `Decimal`'s
    // `Display` form (e.g. `-1000000000000`, `0.001`) is a valid SQL numeric
    // literal, so no quoting/override is needed (unlike `text` / `date`).

    fn arbitrary_value() -> proptest::strategy::BoxedStrategy<Self> {
        use proptest::strategy::Strategy;
        proptest::sample::select(numeric_values().to_vec()).boxed()
    }
}

impl OrderedScalar for rust_decimal::Decimal {
    // Boundary pivots derive from `fixture_values()` (= ±1_000_000_000_000);
    // `mid_pivot` inherits `Decimal::ZERO` (`Default`), a real fixture and the
    // numeric origin. Nothing to override.
}

// `Decimal` is deliberately NOT `SignedScalar`: like `text`, it is an
// ordered non-integer kind. The signed-only sign-boundary test bounds on
// `SignedScalar`, so it is not instantiated for numeric.

/// `eql-domains`' distinctness invariant keys `Fixture::Numeric` by its literal
/// string, so `"1"` and `"1.0"` would pass there as "distinct". But they denote
/// the same `Decimal` value (and collide in the ORE ciphertext, per ore-rs's
/// `equivalent_forms_collide_in_ciphertext`), so an aliasing pair would insert
/// duplicate `plaintext` rows and break `fetch_fixture_payload`'s `fetch_one`.
/// This guards distinctness by parsed value, which is the property the fixture
/// table relies on.
#[cfg(test)]
mod numeric_value_guards {
    use super::*;

    #[test]
    fn fixtures_are_distinct_by_value() {
        use std::collections::HashSet;
        let vals = numeric_values(); // &[Decimal], parsed from the catalog
        let unique: HashSet<_> = vals.iter().collect();
        assert_eq!(
            unique.len(),
            vals.len(),
            "two numeric fixtures alias to the same Decimal value",
        );
    }

    /// `mid_pivot` is the only pivot `numeric` does not derive (it inherits
    /// `Decimal::ZERO`). The matrix fetches its ciphertext via
    /// `fetch_fixture_payload`, so `0` must be a fixture row present verbatim.
    #[test]
    fn mid_pivot_is_a_fixture() {
        let values = numeric_values();
        let mid = <rust_decimal::Decimal as OrderedScalar>::mid_pivot();
        assert!(
            values.contains(&mid),
            "numeric mid_pivot {mid:?} must be a fixture"
        );
    }
}

// `bool` is hand-written (the proc-macro emits `impl ScalarType` only for the
// integer kinds). It is the **storage-only / encryption-only** scalar: a single
// term-less `eql_v3.bool` domain, no `_eq`/`_ord`, so it is deliberately NOT
// `OrderedScalar`/`SignedScalar`/`MatchScalar` — it has no comparison or match
// capability. The `caps = [storage]` matrix arm never references a pivot, so the
// absence of `OrderedScalar` is fine (and intentional). Values come from the
// catalog's two `Fixture::Bool` rows.

/// Typed `bool` fixture values, built once from `bool`'s catalog row, in catalog
/// order (`[false, true]`). Public so the `eql_v3_boolean` fixture module (emitted
/// by `scalar_types!(fixture_modules)`) can hand the slice to `scalar_fixture!`.
static BOOLEAN_VALUES_CELL: std::sync::LazyLock<Vec<bool>> = std::sync::LazyLock::new(|| {
    eql_domains::BOOLEAN_FIXTURES
        .values
        .iter()
        .map(|f| match f {
            eql_domains::Fixture::Bool(b) => *b,
            other => panic!("non-bool fixture in bool catalog row: {other:?}"),
        })
        .collect()
});

/// The `bool` fixture values, in catalog order. Public so the `eql_v3_boolean`
/// fixture module can hand the slice to `scalar_fixture!`.
pub fn boolean_values() -> &'static [bool] {
    &BOOLEAN_VALUES_CELL
}

impl ScalarType for bool {
    const PG_TYPE: &'static str = "boolean";

    fn fixture_values() -> &'static [Self] {
        boolean_values()
    }
    // `to_sql_literal` inherits the default (`value.to_string()` => `true`/`false`),
    // which is a valid SQL boolean literal, so no override is needed.

    // `bool` is storage-only and never feeds an oracle suite, but `arbitrary_value`
    // is a required `ScalarType` method, so sample its two fixtures like every
    // other non-integer scalar.
    fn arbitrary_value() -> proptest::strategy::BoxedStrategy<Self> {
        use proptest::strategy::Strategy;
        proptest::sample::select(boolean_values().to_vec()).boxed()
    }
}

// `bool` is deliberately NOT `OrderedScalar` / `SignedScalar` / `MatchScalar`:
// it is encryption-only (no `_eq`/`_ord`/`_match` domain), so it has no
// comparison pivots, no sign boundary, and no bloom-match capability. Any
// instantiation of an ordered/signed/match-bounded test for `bool` is a compile
// error — exactly the guarantee we want for a storage-only scalar.

#[cfg(test)]
mod bool_value_tests {
    use super::*;

    /// The harness value list matches the catalog `BOOLEAN_FIXTURES.values` and carries
    /// both boolean values — the oracle cannot drift from the catalog the fixture
    /// generator encrypts.
    #[test]
    fn bool_values_match_catalog_and_cover_both() {
        assert_eq!(boolean_values(), &[false, true]);
        assert!(boolean_values().contains(&false));
        assert!(boolean_values().contains(&true));
        assert_eq!(<bool as ScalarType>::PG_TYPE, "boolean");
        assert_eq!(
            <bool as ScalarType>::fixture_table_name(),
            "fixtures.eql_v3_boolean"
        );
    }
}

#[cfg(test)]
mod text_value_tests {
    use super::*;

    /// The `min`/`mid`/`max` pivots resolve to fixture rows present verbatim, so
    /// `fetch_fixture_payload` can resolve each one's ciphertext.
    #[test]
    fn text_pivots_are_in_fixture_values() {
        let values = <String as ScalarType>::fixture_values();
        let min = <String as OrderedScalar>::min_pivot();
        let mid = <String as OrderedScalar>::mid_pivot();
        let max = <String as OrderedScalar>::max_pivot();
        assert!(values.contains(&min), "min_pivot {min:?} must be a fixture");
        assert!(values.contains(&mid), "mid_pivot {mid:?} must be a fixture");
        assert!(values.contains(&max), "max_pivot {max:?} must be a fixture");
        assert!(min <= mid && mid <= max, "min <= mid <= max must hold");
        // text has no numeric origin: the empty string is not a fixture.
        assert!(
            !values.iter().any(|v| v.is_empty()),
            "the empty string must not be a text fixture"
        );
    }

    /// The `MatchScalar` haystack/needle/disjoint plaintexts must each be a
    /// fixture row present verbatim, so `fetch_fixture_payload` can resolve each
    /// one's ciphertext when the `_search`/`_match` arms run. The doc comments on
    /// the trait promise this invariant; pin it so a fixture change that drops one
    /// of the three fails here instead of at query time.
    #[test]
    fn text_match_pivots_are_in_fixture_values() {
        let values = <String as ScalarType>::fixture_values();
        let haystack = <String as MatchScalar>::haystack();
        let needle = <String as MatchScalar>::needle();
        let disjoint = <String as MatchScalar>::disjoint();
        assert!(
            values.contains(&haystack),
            "haystack {haystack:?} must be a fixture"
        );
        assert!(
            values.contains(&needle),
            "needle {needle:?} must be a fixture"
        );
        assert!(
            values.contains(&disjoint),
            "disjoint {disjoint:?} must be a fixture"
        );
    }

    /// The harness value list matches the catalog `TEXT_VALUES` in order — the
    /// oracle cannot drift from the catalog the fixture generator encrypts.
    #[test]
    fn text_values_match_catalog() {
        let got: Vec<&str> = <String as ScalarType>::fixture_values()
            .iter()
            .map(|s| s.as_str())
            .collect();
        assert_eq!(got, eql_domains::TEXT_VALUES.to_vec());
    }

    /// Directly exercises the `String` `to_sql_literal` override's
    /// single-quote-doubling branch. Every `TEXT_VALUES` fixture is quote-free,
    /// so no DB-backed test reaches the `.replace('\'', "''")`; this pins it so a
    /// quoting/injection regression in the override is caught. (The sibling
    /// `sql_string_literal` helper is tested separately — this covers the
    /// trait method itself.)
    #[test]
    fn text_to_sql_literal_escapes_single_quotes() {
        assert_eq!(
            <String as ScalarType>::to_sql_literal(&"O'Brien".to_string()),
            "'O''Brien'"
        );
        // a quote-free value is wrapped but otherwise untouched
        assert_eq!(
            <String as ScalarType>::to_sql_literal(&"frank".to_string()),
            "'frank'"
        );
    }
}

// `real`/`double` are hand-written (like `text`/`numeric`): the proc-macro
// emits `impl ScalarType` only for the integer kinds, and `f32`/`f64` are not
// `Ord` (which `ScalarType` requires), so the newtypes `F4`/`F8` carry `Ord` via
// `total_cmp`. Both widths encrypt through the SINGLE f64 crypto path
// (`Plaintext::Float`), so `real` vs `double` is purely a Postgres-surface
// distinction. The newtype + trait impls are necessarily per-width (different
// inner primitive, `PG_TYPE`, pivots, and `as f64` widening), so they are
// hand-written, but the value materialiser is the kind-agnostic part and reuses
// the shared `lazy_values!` macro (as `text`/`numeric` do).

/// Harness newtype over `f32` for the `real` scalar. `f32` is not `Ord`, which
/// `ScalarType` requires, so `Ord` is derived from `total_cmp` — safe because NaN
/// is never a fixture (guarded in `float_value_guards`). `#[sqlx(transparent)]`
/// delegates `Type`/`Decode` to the inner `f32` against Postgres `real`.
/// `Default` is `F4(0.0)` (the numeric origin / mid pivot).
///
/// `#[derive(sqlx::Type)]` + `#[sqlx(transparent)]` already generates the
/// delegating `Type` AND `Decode` (and `Encode`) impls for the newtype, so we do
/// NOT also `#[derive(sqlx::Decode)]` — that would be a conflicting impl.
#[derive(Debug, Clone, Copy, sqlx::Type)]
#[sqlx(transparent)]
pub struct F4(pub f32);

// `PartialEq` is hand-written via `total_cmp` (not derived) so it stays
// consistent with the `Ord`/`Eq` impls below: derived IEEE equality breaks
// `Eq`'s reflexivity for NaN and disagrees with `total_cmp` on signed zero.
impl PartialEq for F4 {
    fn eq(&self, other: &Self) -> bool {
        self.0.total_cmp(&other.0) == std::cmp::Ordering::Equal
    }
}
impl Eq for F4 {}
impl Ord for F4 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.total_cmp(&other.0)
    }
}
impl PartialOrd for F4 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Default for F4 {
    fn default() -> Self {
        F4(0.0)
    }
}
impl std::fmt::Display for F4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Harness newtype over `f64` for the `double` scalar. Same design as `F4`:
/// `Ord` via `total_cmp`, `#[sqlx(transparent)]` against Postgres
/// `double precision`, `Default = F8(0.0)`. Like `F4`, the transparent
/// `sqlx::Type` derive also supplies `Decode`/`Encode`, so they are not derived
/// separately.
#[derive(Debug, Clone, Copy, sqlx::Type)]
#[sqlx(transparent)]
pub struct F8(pub f64);

// `PartialEq` is hand-written via `total_cmp` (not derived); see `F4` above.
impl PartialEq for F8 {
    fn eq(&self, other: &Self) -> bool {
        self.0.total_cmp(&other.0) == std::cmp::Ordering::Equal
    }
}
impl Eq for F8 {}
impl Ord for F8 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.total_cmp(&other.0)
    }
}
impl PartialOrd for F8 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Default for F8 {
    fn default() -> Self {
        F8(0.0)
    }
}
impl std::fmt::Display for F8 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// `real`/`double` value wiring goes through the shared `lazy_values!`
// materialiser (the same macro `text`/`numeric` use), parsing the catalog's
// `Fixture::Float` strings into the newtype. Rust's `str::parse::<f32>` accepts
// `"inf"`/`"-inf"`/`"nan"`, so the ±Inf pivots parse natively (NaN is excluded by
// the catalog guards). `real_values()`/`double_values()` are public so the
// `eql_v3_real`/`eql_v3_double` fixture modules (emitted by
// `scalar_types!(fixture_modules)`) can hand the slice to `scalar_fixture!`.
lazy_values! {
    cell      = REAL_VALUES_CELL,
    accessor  = real_values,
    rust_type = F4,
    spec      = eql_domains::REAL_FIXTURES,
    variant   = Float,
    pg_type   = "real",
    parse     = |f| match f {
        eql_domains::Fixture::Float(s) => F4(s
            .parse()
            .unwrap_or_else(|e| panic!("invalid real catalog fixture {s:?}: {e}"))),
        other => panic!("non-float fixture in real catalog row: {other:?}"),
    },
}

lazy_values! {
    cell      = DOUBLE_VALUES_CELL,
    accessor  = double_values,
    rust_type = F8,
    spec      = eql_domains::DOUBLE_FIXTURES,
    variant   = Float,
    pg_type   = "double",
    parse     = |f| match f {
        eql_domains::Fixture::Float(s) => F8(s
            .parse()
            .unwrap_or_else(|e| panic!("invalid double catalog fixture {s:?}: {e}"))),
        other => panic!("non-float fixture in double catalog row: {other:?}"),
    },
}

/// Render an f64 as a Postgres float SQL literal. Finite values use the numeric
/// Display form; non-finite values use the quoted `'Infinity'` / `'-Infinity'`
/// special-input form (`'inf'` from Rust's Display is NOT a valid SQL float).
fn float_sql_literal(x: f64) -> String {
    if x.is_infinite() {
        if x.is_sign_positive() {
            "'Infinity'".to_string()
        } else {
            "'-Infinity'".to_string()
        }
    } else {
        format!("{x}")
    }
}

impl ScalarType for F4 {
    const PG_TYPE: &'static str = "real";
    // `real` happens to be a valid native SQL type, but derive the oracle column
    // type from `EqlPlaintext` anyway (symmetric with F8) so the mapping is
    // explicit rather than relying on the domain token coinciding with a native
    // type name.
    const PLAINTEXT_SQL_TYPE: &'static str =
        <F4 as crate::fixtures::EqlPlaintext>::PLAINTEXT_SQL_TYPE.as_str();

    fn fixture_values() -> &'static [Self] {
        real_values()
    }

    fn to_sql_literal(value: &Self) -> String {
        float_sql_literal(value.0 as f64)
    }

    fn arbitrary_value() -> proptest::strategy::BoxedStrategy<Self> {
        use proptest::strategy::Strategy;
        // Sample the cast-valid fixture set (no NaN/-0.0/non-finite novelty
        // beyond the fixtures). Every value already round-trips through `real`.
        proptest::sample::select(real_values().to_vec()).boxed()
    }
}

impl OrderedScalar for F4 {
    // Boundary pivots derive from `fixture_values()` (= ±Inf); `mid_pivot`
    // inherits `Self::default()` = `F4(0.0)`, a real fixture and the origin.
}

impl SignedScalar for F4 {
    /// Floats are signed about `0.0`; fixtures straddle it.
    fn origin() -> Self {
        F4(0.0)
    }
}

impl ScalarType for F8 {
    const PG_TYPE: &'static str = "double";
    // The domain token `double` is NOT a valid native SQL type name (that is
    // `double precision`), so the plaintext oracle column cannot default to
    // `PG_TYPE`. Derive it from `EqlPlaintext` (the `ScalarKind`-keyed source of
    // truth) so it stays `double precision` and cannot drift from the encrypt
    // cast — the same PG_TYPE-vs-PLAINTEXT_SQL_TYPE split `timestamp` uses.
    const PLAINTEXT_SQL_TYPE: &'static str =
        <F8 as crate::fixtures::EqlPlaintext>::PLAINTEXT_SQL_TYPE.as_str();

    fn fixture_values() -> &'static [Self] {
        double_values()
    }

    fn to_sql_literal(value: &Self) -> String {
        float_sql_literal(value.0)
    }

    fn arbitrary_value() -> proptest::strategy::BoxedStrategy<Self> {
        use proptest::strategy::Strategy;
        proptest::sample::select(double_values().to_vec()).boxed()
    }
}

impl OrderedScalar for F8 {}

impl SignedScalar for F8 {
    fn origin() -> Self {
        F8(0.0)
    }
}

/// Guards for the float value wiring: the runtime properties the fixture table
/// relies on (catalog parity, no NaN/`-0.0`, pivots present), plus the f32→f64
/// widening contract the single-crypto-path design rests on.
#[cfg(test)]
mod float_value_guards {
    use super::*;

    #[test]
    fn real_values_match_catalog_and_are_finite_non_negative_zero() {
        let vals = real_values();
        // Parsed from the catalog, in order.
        let want: Vec<F4> = eql_domains::REAL_FIXTURES
            .values
            .iter()
            .map(|f| match f {
                eql_domains::Fixture::Float(s) => F4(s.parse().unwrap()),
                other => panic!("non-float fixture: {other:?}"),
            })
            .collect();
        assert_eq!(vals, want.as_slice());
        // No NaN, no -0.0 (the encoder canonicalizes -0.0 -> +0.0; a duplicate
        // would break fetch_fixture_payload's fetch_one).
        for v in vals {
            assert!(!v.0.is_nan(), "{v:?} is NaN");
            assert!(!(v.0 == 0.0 && v.0.is_sign_negative()), "{v:?} is -0.0");
        }
    }

    #[test]
    fn double_values_match_catalog_and_are_finite_non_negative_zero() {
        let vals = double_values();
        let want: Vec<F8> = eql_domains::DOUBLE_FIXTURES
            .values
            .iter()
            .map(|f| match f {
                eql_domains::Fixture::Float(s) => F8(s.parse().unwrap()),
                other => panic!("non-float fixture: {other:?}"),
            })
            .collect();
        assert_eq!(vals, want.as_slice());
        for v in vals {
            assert!(!v.0.is_nan(), "{v:?} is NaN");
            assert!(!(v.0 == 0.0 && v.0.is_sign_negative()), "{v:?} is -0.0");
        }
    }

    #[test]
    fn float_pivots_and_origin_are_fixtures() {
        // min/max/origin must be present verbatim (fetch_fixture_payload fetches
        // each pivot's ciphertext at test time).
        assert!(real_values().contains(&<F4 as OrderedScalar>::min_pivot()));
        assert!(real_values().contains(&<F4 as OrderedScalar>::max_pivot()));
        assert!(real_values().contains(&<F4 as SignedScalar>::origin()));
        assert_eq!(<F4 as SignedScalar>::origin(), F4(0.0));
        assert!(double_values().contains(&<F8 as OrderedScalar>::min_pivot()));
        assert!(double_values().contains(&<F8 as OrderedScalar>::max_pivot()));
        assert!(double_values().contains(&<F8 as SignedScalar>::origin()));
        assert_eq!(<F8 as SignedScalar>::origin(), F8(0.0));
    }

    #[test]
    fn float_min_max_pivots_are_the_infinities() {
        assert_eq!(<F4 as OrderedScalar>::min_pivot(), F4(f32::NEG_INFINITY));
        assert_eq!(<F4 as OrderedScalar>::max_pivot(), F4(f32::INFINITY));
        assert_eq!(<F8 as OrderedScalar>::min_pivot(), F8(f64::NEG_INFINITY));
        assert_eq!(<F8 as OrderedScalar>::max_pivot(), F8(f64::INFINITY));
    }

    /// The whole single-crypto-path design rests on "f32→f64 widening is exact
    /// and monotonic". Every catalog fixture is exact-in-f32 (powers of two /
    /// halves) and `arbitrary_value()` only samples those, so the property is
    /// otherwise untested for f32 values that have NO exact f64-of-an-f32 quirk.
    /// Exercise a deliberately NON-representable-in-decimal f32 (`0.1f32`, whose
    /// nearest f32 differs from `0.1f64`) and confirm the f32 ordering survives
    /// the widening to f64 — i.e. `a < b` as f32 iff `(a as f64) < (b as f64)`
    /// for the EXACT bits the crypto path encrypts (`to_plaintext` does
    /// `self.0 as f64`). This is a pure-Rust guard; it does not touch the DB.
    #[test]
    fn f32_to_f64_widening_is_order_preserving_for_non_representable_values() {
        // Spread of f32 values that are not "nice" in decimal, straddling 0.
        let xs: [f32; 7] = [-0.3, -0.1, -0.0625, 0.0, 0.1, 0.2, 0.3];
        for w in xs.windows(2) {
            let (a, b) = (w[0], w[1]);
            // f32 strict order matches the widened f64 strict order, bit-for-bit
            // on the value the f64 crypto path actually sees.
            assert_eq!(
                a < b,
                (a as f64) < (b as f64),
                "widening {a} -> {} reordered relative to {b} -> {}",
                a as f64,
                b as f64
            );
            // total_cmp (the newtype's Ord source) agrees with the widened cmp.
            assert_eq!(
                a.total_cmp(&b),
                (a as f64).total_cmp(&(b as f64)),
                "F4 Ord (total_cmp) disagrees with widened F8 Ord for {a} vs {b}"
            );
        }
    }
}

/// Per-domain capability + payload shape, resolved from `CATALOG`. Each
/// variant maps to a domain suffix (`Eq` => `_eq`, `Search` => `_search`,
/// …); its terms, required payload keys, supported operators, and
/// per-operator extractors are derived from the catalog row for a given
/// scalar `token`, never hardcoded. This is the SAME single source codegen
/// renders from, so the harness routing cannot drift from the generated SQL.
/// `Ord` and `OrdOre` are deliberate twins — same operator surface,
/// different SQL domain names — for the scheme-explicit vs converged-name
/// migration story.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    Storage,
    Eq,
    Ord,
    OrdOre,
    Search,
    SearchOre,
}

impl Variant {
    /// Every variant the family can materialise, in declaration order. Not
    /// every scalar declares every variant (only `text` declares `_search` /
    /// `_search_ore`), so iteration sites that span scalars must filter with
    /// [`Variant::is_declared_for`].
    pub const ALL: &'static [Variant] = &[
        Variant::Storage,
        Variant::Eq,
        Variant::Ord,
        Variant::OrdOre,
        Variant::Search,
        Variant::SearchOre,
    ];

    pub const fn suffix(self) -> &'static str {
        match self {
            Variant::Storage => "",
            Variant::Eq => "_eq",
            Variant::Ord => "_ord",
            Variant::OrdOre => "_ord_ore",
            Variant::Search => "_search",
            Variant::SearchOre => "_search_ore",
        }
    }

    /// The bare catalog domain name this variant maps to (no leading `_`), as
    /// stored in `Domain::name` / looked up via `DomainFamily::domain_by_name`.
    /// `suffix()` is the SQL-qualifying form (`_eq`); this is the catalog key
    /// (`eq`). Storage is the empty bare name.
    pub const fn name(self) -> &'static str {
        match self {
            Variant::Storage => "",
            Variant::Eq => "eq",
            Variant::Ord => "ord",
            Variant::OrdOre => "ord_ore",
            Variant::Search => "search",
            Variant::SearchOre => "search_ore",
        }
    }

    /// The fixed index terms this variant's domain carries for scalar `token`,
    /// from `CATALOG`. Panics if the `(token, suffix())` pair is not declared —
    /// the resolution backstop test guarantees every instantiated pair
    /// resolves, so a panic here means the matrix and catalog drifted. Guard
    /// cross-scalar iteration with [`Variant::is_declared_for`].
    pub fn terms_for(self, token: &str) -> &'static [Term] {
        CATALOG
            .iter()
            .find(|s| s.name == token)
            .and_then(|s| s.domain_by_name(self.name()))
            .map(|d| d.terms)
            .unwrap_or_else(|| {
                panic!(
                    "no catalog domain for ({token}, {self:?}) suffix `{}`",
                    self.suffix()
                )
            })
    }

    /// True when scalar `token` declares this variant's domain in `CATALOG`.
    /// Use to filter `Variant::ALL` when iterating across scalars that do not
    /// all declare the same variants (e.g. only `text` declares `_search`).
    pub fn is_declared_for(self, token: &str) -> bool {
        CATALOG
            .iter()
            .find(|s| s.name == token)
            .and_then(|s| s.domain_by_name(self.name()))
            .is_some()
    }

    /// Top-level JSONB keys the variant's domain CHECK requires for `token`:
    /// the EQL envelope (`v`, `i`, `c`) plus each term's payload key
    /// (`hm`/`ob`/`op`/`bf`), in term order. Catalog-derived — `text_ord` yields
    /// `[v, i, c, hm, op]`; `text_search` yields `[v, i, c, hm, op, bf]`, and
    /// its block-ORE sibling `text_search_ore` yields `[v, i, c, hm, ob, bf]`.
    /// The matrix `payload_check` arm iterates this to assert each key's absence
    /// is rejected at the cast.
    pub fn payload_required_keys(self, token: &str) -> Vec<&'static str> {
        let mut keys = vec!["v", "i", "c"];
        keys.extend(Term::term_json_keys(self.terms_for(token)));
        keys
    }

    /// True when the variant's domain supports `=`/`<>` for `token`.
    pub fn supports_eq(self, token: &str) -> bool {
        Term::operators_for_terms(self.terms_for(token)).contains(&"=")
    }

    /// True when the variant's domain supports the four ordering operators.
    pub fn supports_ord(self, token: &str) -> bool {
        self.ordering_term(token).is_some()
    }

    /// The variant's ordering [`Term`] for `token` — the first term that
    /// provides ordering — or `None` if the domain is not ordered.
    ///
    /// This is what makes the ordering surface catalog-driven rather than
    /// hardcoded to one SEM. `_ord` / `_search` are backed by `Term::Ope` and
    /// `_ord_ore` / `_search_ore` by
    /// `Term::Ore`, so the extractor name (`ord_term` vs `ord_term_ore`), the
    /// payload key (`op` vs `ob`), and the returned SEM type (a `bytea`-backed
    /// domain vs an ORE composite) all differ between them. Callers that need
    /// to know *which* ordering term they are looking at — the extractor-identity
    /// oracle, chiefly — branch on this rather than assuming block-ORE.
    pub fn ordering_term(self, token: &str) -> Option<Term> {
        self.terms_for(token)
            .iter()
            .copied()
            .find(|t| t.provides_ordering())
    }

    /// The `eql_v3`-qualified extractor that serves `op` on this variant's
    /// domain for `token`, or `None` if unsupported (or `Storage`). Derived via
    /// `Term::extractor_for_operator` — the SAME single source codegen uses, so
    /// the harness routing cannot diverge from the generated SQL. For
    /// `text_ord` `[Hm, Ope]`, `=` => `eql_v3.eq_term`, `<` => `eql_v3.ord_term`.
    pub fn extractor_for_op(self, token: &str, op: &str) -> Option<String> {
        Term::extractor_for_operator(self.terms_for(token), op).map(|f| format!("eql_v3.{f}"))
    }

    /// The `eql_v3`-qualified extractor of this variant's first
    /// extractor-bearing term for `token`, or `None` for `Storage`. Used where
    /// a single representative extractor is needed independent of any operator
    /// (e.g. the `COUNT(DISTINCT)` deduplication arm). For a multi-term domain
    /// this is the first term's extractor (`text_ord` `[Hm, Ore]` => `eq_term`).
    pub fn primary_extractor(self, token: &str) -> Option<String> {
        Term::extractor_terms(self.terms_for(token))
            .first()
            .map(|t| format!("eql_v3.{}", t.extractor()))
    }
}

/// Runtime spec built from `(T, Variant)`. The matrix macro consumes
/// this; nothing here is `const` because `sql_domain` is derived via
/// `format!` from `T::PG_TYPE`. The domains live in the `public` schema,
/// so `sql_domain` is schema-qualified (e.g. `public.eql_v3_integer_eq`).
#[derive(Debug, Clone)]
pub struct ScalarDomainSpec {
    pub sql_domain: String,
    /// SQL expression yielding the comparable value (default `"payload"`).
    pub column_expr: String,
    pub variant: Variant,
    pub placeholder_payload: &'static str,
    pub eq_extractor: fn(&str) -> String,
    /// Takes the variant because one `T` spans domains with different ordering
    /// terms. Call via [`ScalarDomainSpec::ord_extractor_expr`], which supplies
    /// `self.variant`.
    pub ord_extractor: fn(Variant, &str) -> String,
    /// The variant's ordering term (`Term::Ope` for `_ord` / `_search`,
    /// `Term::Ore` for `_ord_ore` / `_search_ore`), or `None` when the domain is
    /// not ordered.
    ///
    /// Read from `CATALOG` via `T::PG_TYPE`, so it is meaningless for a SteVec
    /// entry view, whose `PG_TYPE` names the wrapped scalar rather than its own
    /// structural term (`JsonbEntryInteger` reports `Some(Term::Ope)` but orders
    /// by `op`). Only the property oracles read this field, and they are
    /// instantiated solely with real scalar types — never with an entry view.
    /// Use [`ScalarDomainSpec::ord_extractor_expr`], which honours the
    /// `ord_extractor` override, when you need the extractor itself.
    pub ord_term: Option<Term>,
    /// The scalar's catalog token (`T::PG_TYPE`, e.g. `"integer"`, `"text"`).
    /// Carried so the delegating capability methods can resolve the variant's
    /// terms from `CATALOG` without the call site re-supplying the token.
    pub token: &'static str,
}

impl ScalarDomainSpec {
    pub fn new<T: ScalarType>(variant: Variant) -> Self {
        Self {
            sql_domain: T::sql_domain(variant),
            column_expr: T::column_expr(),
            variant,
            placeholder_payload: T::placeholder_payload(),
            eq_extractor: T::eq_extractor_expr,
            ord_extractor: T::ord_extractor_expr,
            ord_term: variant.ordering_term(T::PG_TYPE),
            token: T::PG_TYPE,
        }
    }

    /// The ordering extractor applied to `value_expr`, using this spec's
    /// variant. Prefer this over poking `ord_extractor` directly.
    pub fn ord_extractor_expr(&self, value_expr: &str) -> String {
        (self.ord_extractor)(self.variant, value_expr)
    }

    pub fn supports_eq(&self) -> bool {
        self.variant.supports_eq(self.token)
    }

    pub fn supports_ord(&self) -> bool {
        self.variant.supports_ord(self.token)
    }

    /// Top-level JSONB keys the domain CHECK requires (envelope + term keys).
    pub fn payload_required_keys(&self) -> Vec<&'static str> {
        self.variant.payload_required_keys(self.token)
    }

    /// The `eql_v3`-qualified extractor serving `op`, or `None` if unsupported.
    pub fn extractor_for_op(&self, op: &str) -> Option<String> {
        self.variant.extractor_for_op(self.token, op)
    }

    /// A single representative extractor (first term's), independent of any
    /// operator. `None` for `Storage`.
    pub fn primary_extractor(&self) -> Option<String> {
        self.variant.primary_extractor(self.token)
    }

    /// Extractor expression for the variant's discriminating term applied to
    /// `value_expr`. Routes through the per-type `eq_extractor` / `ord_extractor`
    /// seams, so scalars produce `eql_v3.eq_term(...)` and the ordering
    /// extractor their catalog term names (`eql_v3.ord_term(...)` for `_ord` /
    /// `_search`, `eql_v3.ord_term_ore(...)` for `_ord_ore` / `_search_ore`),
    /// while a SteVec-entry
    /// view produces `eql_v3.eq_term(...)` / `eql_v3.ord_term(...)` (the
    /// `public.jsonb_entry` overload).
    /// `Storage` has no discriminating term and returns `None`. `Search` /
    /// `SearchOre` (the combined domains, which provide ordering) route through
    /// the ordered extractor like `Ord`/`OrdOre`.
    pub fn extractor_expr(&self, value_expr: &str) -> Option<String> {
        match self.variant {
            Variant::Storage => None,
            Variant::Eq => Some((self.eq_extractor)(value_expr)),
            Variant::Ord | Variant::OrdOre | Variant::Search | Variant::SearchOre => {
                Some(self.ord_extractor_expr(value_expr))
            }
        }
    }
}

/// The single `eql_v3`-qualified extractor that serves EVERY operator in
/// `ops` for `spec`'s domain — the value codegen would put in a functional
/// index for this combo. Catalog-derived via [`ScalarDomainSpec::extractor_for_op`]
/// (i.e. `Term::extractor_for_operator`), so the index-engagement matrix never
/// restates the extractor as a literal.
///
/// A single functional index serves one extractor, so the matrix combos that
/// drive these tests group only operators that share an extractor. This asserts
/// that invariant: if `ops` mix extractors (e.g. text's `=` -> `eq_term` and
/// `<` -> `ord_term` in one combo) it errors loudly rather than silently
/// indexing only the first op's extractor. An op the domain does not support at
/// all is likewise an error.
pub fn combo_extractor(spec: &ScalarDomainSpec, ops: &[&str]) -> Result<String> {
    let mut chosen: Option<String> = None;
    for &op in ops {
        let ex = spec.extractor_for_op(op).ok_or_else(|| {
            anyhow::anyhow!(
                "{} declares no extractor for `{}` but it is wired as an \
index-engagement combo op",
                spec.sql_domain,
                op,
            )
        })?;
        match &chosen {
            None => chosen = Some(ex),
            Some(prev) if *prev != ex => bail!(
                "combo for {} mixes extractors ({prev} for an earlier op, {ex} \
for `{op}`) — one functional index cannot serve both; split into separate \
combos with distinct dom_names",
                spec.sql_domain,
            ),
            Some(_) => {}
        }
    }
    chosen.ok_or_else(|| anyhow::anyhow!("combo for {} has no ops", spec.sql_domain))
}

/// True when scalar `token` declares any domain carrying the `Bloom` term —
/// i.e. its proxy-generated fixture payload includes a `bf` (bloom-filter) key.
/// Catalog-derived: only `text` (via `_match`/`_search`) declares a Bloom
/// domain, so only text fixtures carry `bf`. Note the proxy always emits `hm`
/// and `ob` for every scalar's fixture regardless of the declared domains, so
/// those two are asserted unconditionally; `bf` is the term that actually
/// tracks the catalog.
pub fn token_has_bloom_term(token: &str) -> bool {
    CATALOG
        .iter()
        .find(|s| s.name == token)
        .map(|s| s.domains.iter().any(|d| d.terms.contains(&Term::Bloom)))
        .unwrap_or(false)
}

/// True when scalar `token` declares any domain carrying the `Ope` term —
/// i.e. its generated fixture is encrypted with the `ope` index and its
/// payload includes an `op` (CLLW-OPE) key: a single hex string, natively
/// bytea-sortable after hex-decode (cipherstash-client 0.38.1+).
/// Catalog-derived: every ordered family declares an `_ord_ope` domain, so
/// every non-storage-only scalar's fixture carries `op`; a storage-only
/// scalar (`boolean`) does not.
pub fn token_has_ope_term(token: &str) -> bool {
    CATALOG
        .iter()
        .find(|s| s.name == token)
        .map(|s| s.domains.iter().any(|d| d.terms.contains(&Term::Ope)))
        .unwrap_or(false)
}

/// True when scalar `token` is **storage-only / encryption-only** (a single
/// term-less domain, no `_eq`/`_ord`/`_match`) — e.g. `bool`. Catalog-derived
/// via `DomainFamily::is_storage_only`. Such a type's fixture is encrypted with no
/// search index, so its payload carries only `{v,i,c}` (no `hm`/`ob`/`bf`); the
/// fixture-shape assertions branch on this.
pub fn token_is_storage_only(token: &str) -> bool {
    CATALOG
        .iter()
        .find(|s| s.name == token)
        .map(|s| s.is_storage_only())
        .unwrap_or(false)
}

/// SQL string-literal escaping for direct interpolation.
pub fn sql_string_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// `a op b` and `b op' a` return the same row set when `op'` is the
/// commutator of `op`. Used by the cross-shape arm when the column moves
/// to the right operand.
pub fn commute_op(op: &str) -> &'static str {
    match op {
        "=" => "=",
        "<>" => "<>",
        "<" => ">",
        "<=" => ">=",
        ">" => "<",
        ">=" => "<=",
        other => panic!("commute_op: unsupported operator {other}"),
    }
}

/// Fetch the payload row keyed by `plaintext` from `T`'s fixture table.
pub async fn fetch_fixture_payload<T: ScalarType>(pool: &PgPool, plaintext: T) -> Result<String> {
    let sql = format!(
        "SELECT ({col})::text FROM {table} WHERE plaintext = {lit}",
        col = T::column_expr(),
        table = T::fixture_table_name(),
        lit = T::to_sql_literal(&plaintext),
    );
    sqlx::query_scalar(&sql)
        .fetch_one(pool)
        .await
        .with_context(|| {
            format!(
                "fetching {} payload for plaintext={:?}",
                T::fixture_table_name(),
                plaintext
            )
        })
}

/// Sorted plaintexts matching `predicate` against `T`'s fixture table.
async fn scalar_plaintexts_matching<T: ScalarType>(
    pool: &PgPool,
    predicate: &str,
) -> Result<Vec<T>> {
    let sql = format!(
        "SELECT plaintext FROM {table} WHERE {predicate} ORDER BY plaintext",
        table = T::fixture_table_name(),
    );
    let mut rows: Vec<T> = sqlx::query_scalar(&sql)
        .fetch_all(pool)
        .await
        .with_context(|| format!("running scalar plaintext query: {sql}"))?;
    rows.sort();
    Ok(rows)
}

/// Run `predicate` against `T`'s fixture; assert plaintexts equal `expected`.
pub async fn assert_scalar_plaintexts<T: ScalarType>(
    pool: &PgPool,
    domain: &str,
    op: &str,
    predicate: &str,
    expected: &[T],
) -> Result<()> {
    let actual = scalar_plaintexts_matching::<T>(pool, predicate).await?;
    let mut want = expected.to_vec();
    want.sort();
    assert_eq!(
        actual, want,
        "domain={domain} operator={op} predicate={predicate} must match expected plaintexts"
    );
    Ok(())
}

/// Unified raise-assertion: query must error and the message must contain
/// `expected_msg`. Covers blocker raises (`expected_msg = "operator X is
/// not supported for {domain}"`) and native-operator absence
/// (`"operator does not exist"`). Bind slots are `Option<&str>`: `Some`
/// = bind the payload, `None` = bind NULL.
pub async fn assert_raises(
    pool: &PgPool,
    sql: &str,
    binds: &[Option<&str>],
    expected_msg: &str,
) -> Result<()> {
    let mut q = sqlx::query(sql);
    for b in binds {
        q = q.bind(*b);
    }
    let result = q.fetch_one(pool).await;
    let err = match result {
        Ok(_) => bail!("SQL must raise: {sql}"),
        Err(e) => e.to_string(),
    };
    if !err.contains(expected_msg) {
        bail!("SQL={sql} expected error containing {expected_msg:?}, got {err}");
    }
    Ok(())
}

/// Unified NULL-result assertion: the query must succeed and return NULL.
/// Used for supported operators where STRICT semantics propagate NULL.
pub async fn assert_null(pool: &PgPool, sql: &str, binds: &[Option<&str>]) -> Result<()> {
    let mut q = sqlx::query_scalar::<_, Option<bool>>(sql);
    for b in binds {
        q = q.bind(*b);
    }
    let result: Option<bool> = q
        .fetch_one(pool)
        .await
        .with_context(|| format!("running null-result assertion: {sql}"))?;
    if result.is_some() {
        bail!("SQL={sql} with NULL operand must yield NULL, got {result:?}");
    }
    Ok(())
}

/// Blocker error message — the contract every encrypted-domain blocker
/// must satisfy regardless of arg shape or NULL configuration.
pub fn blocker_msg(domain: &str, op: &str) -> String {
    format!("operator {op} is not supported for {domain}")
}

#[cfg(test)]
mod helper_panic_tests {
    use super::*;

    // The cross-shape arm only ever passes the six comparison operators to these
    // helpers; an unexpected symbol is a harness bug and must fail loudly rather
    // than silently mis-route a row set. These pin that guard.

    #[test]
    fn commute_op_maps_the_six_comparisons() {
        assert_eq!(commute_op("="), "=");
        assert_eq!(commute_op("<>"), "<>");
        assert_eq!(commute_op("<"), ">");
        assert_eq!(commute_op("<="), ">=");
        assert_eq!(commute_op(">"), "<");
        assert_eq!(commute_op(">="), "<=");
    }

    #[test]
    #[should_panic(expected = "commute_op: unsupported operator")]
    fn commute_op_panics_on_unsupported() {
        let _ = commute_op("@>");
    }

    #[test]
    #[should_panic(expected = "expected_forward: unsupported operator")]
    fn expected_forward_panics_on_unsupported() {
        let _ = <i32 as ScalarType>::expected_forward("@>", 0);
    }
}

#[cfg(test)]
mod seam_tests {
    use super::*;

    /// The access-path / extractor seam defaults must reproduce today's scalar
    /// SQL exactly: bare `payload`, `eql_v3.<pg_type><suffix>`, and the ordering
    /// extractor named by the domain's catalog term — `ord_term` on the
    /// OPE-backed `_ord`, `ord_term_ore` on the ORE-backed `_ord_ore`. A view type
    /// that overrides these (e.g. `JsonbEntryInteger`) is what makes entry reuse
    /// possible — but the defaults are the no-regression contract.
    #[test]
    fn scalar_defaults_reproduce_today_sql() {
        let spec = ScalarDomainSpec::new::<i32>(Variant::Ord);
        assert_eq!(spec.column_expr, "payload");
        assert_eq!(spec.sql_domain, "public.eql_v3_integer_ord");
        assert_eq!(spec.ord_term, Some(Term::Ope));
        assert_eq!(
            spec.extractor_expr("value"),
            Some("eql_v3.ord_term(value)".to_string()),
        );
        assert_eq!(
            (spec.eq_extractor)("value"),
            "eql_v3.eq_term(value)".to_string(),
        );
        assert_eq!(
            spec.placeholder_payload,
            crate::helpers::PLACEHOLDER_PAYLOAD
        );

        // `_ord_ore` is the block-ORE surface, and must NOT follow `_ord`.
        let ore = ScalarDomainSpec::new::<i32>(Variant::OrdOre);
        assert_eq!(ore.sql_domain, "public.eql_v3_integer_ord_ore");
        assert_eq!(ore.ord_term, Some(Term::Ore));
        assert_eq!(
            ore.extractor_expr("value"),
            Some("eql_v3.ord_term_ore(value)".to_string()),
        );
    }

    /// The Eq variant routes through the equality extractor; Storage has none.
    #[test]
    fn scalar_eq_and_storage_extractor_routes() {
        let eq = ScalarDomainSpec::new::<i32>(Variant::Eq);
        assert_eq!(eq.sql_domain, "public.eql_v3_integer_eq");
        assert_eq!(
            eq.extractor_expr("value"),
            Some("eql_v3.eq_term(value)".to_string())
        );

        let storage = ScalarDomainSpec::new::<i32>(Variant::Storage);
        assert_eq!(storage.sql_domain, "public.eql_v3_integer");
        assert_eq!(storage.extractor_expr("value"), None);
    }
}

#[cfg(test)]
mod catalog_resolution_tests {
    use super::*;

    /// The runtime `(token, suffix)` lookup behind `Variant::terms_for` fails as
    /// a panic. Backstop it: every `(scalar, Variant::suffix())` pair the matrix
    /// could instantiate must resolve in `CATALOG`, and the resolved term set
    /// must agree with the catalog row — a drift between the `Variant` model and
    /// the catalog would otherwise only surface when that specific DB test runs.
    #[test]
    fn every_matrix_variant_pair_resolves_in_catalog() {
        for spec in eql_domains::scalar_families() {
            for variant in Variant::ALL {
                let suffix = variant.suffix();
                // A variant is instantiated for a token iff that token declares
                // the suffix; only assert those pairs.
                if let Some(d) = spec.domain_by_name(variant.name()) {
                    assert!(
                        variant.is_declared_for(spec.name),
                        "{}{} declared in CATALOG but is_declared_for is false",
                        spec.name,
                        suffix
                    );
                    assert_eq!(
                        variant.terms_for(spec.name),
                        d.terms,
                        "{}{} term set drift between Variant and CATALOG",
                        spec.name,
                        suffix
                    );
                }
            }
        }
    }

    // `combo_extractor` replaced the hand-written extractor literals in the
    // index-engagement matrix combos; these pin the catalog-derived results the
    // matrix now relies on (no DB needed).

    #[test]
    fn combo_extractor_integer_ord_serves_all_ops_via_ord_term() {
        // integer `_ord` = [Ope]: every op (eq + the four ord ops) resolves to the
        // single ord_term extractor, so the combo is single-extractor.
        let spec = ScalarDomainSpec::new::<i32>(Variant::Ord);
        assert_eq!(
            combo_extractor(&spec, &["=", "<", "<=", ">", ">="]).unwrap(),
            "eql_v3.ord_term",
        );
        // integer `_ord_ore` = [Ore]: same single-extractor property, block-ORE,
        // reached by the qualified extractor name.
        let ore = ScalarDomainSpec::new::<i32>(Variant::OrdOre);
        assert_eq!(
            combo_extractor(&ore, &["=", "<", "<=", ">", ">="]).unwrap(),
            "eql_v3.ord_term_ore",
        );
    }

    #[test]
    fn combo_extractor_text_ord_splits_eq_from_ord() {
        // text `_ord` = [Hm, Ope]: `=` routes through eq_term, the ord ops
        // through ord_term. A single index cannot serve both, so each must be
        // its own combo — proven here by `=`-only and ord-only succeeding while
        // a mixed combo errors.
        let spec = ScalarDomainSpec::new::<String>(Variant::Ord);
        assert_eq!(combo_extractor(&spec, &["="]).unwrap(), "eql_v3.eq_term");
        assert_eq!(
            combo_extractor(&spec, &["<", "<=", ">", ">="]).unwrap(),
            "eql_v3.ord_term",
        );
        let mixed = combo_extractor(&spec, &["=", "<"]);
        assert!(
            mixed.is_err(),
            "a combo mixing eq + ord ops on text _ord must error (two extractors)",
        );

        // text `_ord_ore` = [Hm, Ore]: same split, block-ORE ordering.
        let ore = ScalarDomainSpec::new::<String>(Variant::OrdOre);
        assert_eq!(combo_extractor(&ore, &["="]).unwrap(), "eql_v3.eq_term");
        assert_eq!(
            combo_extractor(&ore, &["<", "<=", ">", ">="]).unwrap(),
            "eql_v3.ord_term_ore",
        );
    }

    #[test]
    fn combo_extractor_errors_on_unsupported_op() {
        // `@>` is not served by any extractor on integer `_eq` ([Hm]).
        let spec = ScalarDomainSpec::new::<i32>(Variant::Eq);
        assert!(combo_extractor(&spec, &["@>"]).is_err());
    }
}

#[cfg(test)]
mod pivot_derivation_tests {
    use super::*;

    /// The invariant that lets `min_pivot`/`max_pivot` be DERIVED from
    /// `fixture_values()` instead of hand-written: for every ordered scalar the
    /// boundary pivots equal the extremes of its own fixture list. Passes with
    /// the current hand-written pivots (they already equal the extremes) and
    /// keeps passing once the trait derives them — so it guards the refactor in
    /// both directions.
    fn boundary_pivots_are_fixture_extremes<T: OrderedScalar>() {
        let values = T::fixture_values();
        let want_min = values.iter().min().expect("≥1 fixture").clone();
        let want_max = values.iter().max().expect("≥1 fixture").clone();
        assert_eq!(
            T::min_pivot(),
            want_min,
            "min_pivot must be the smallest fixture"
        );
        assert_eq!(
            T::max_pivot(),
            want_max,
            "max_pivot must be the largest fixture"
        );
    }

    #[test]
    fn every_ordered_scalar_pivots_on_its_fixture_extremes() {
        boundary_pivots_are_fixture_extremes::<i16>();
        boundary_pivots_are_fixture_extremes::<i32>();
        boundary_pivots_are_fixture_extremes::<i64>();
        boundary_pivots_are_fixture_extremes::<chrono::NaiveDate>();
        boundary_pivots_are_fixture_extremes::<chrono::DateTime<chrono::Utc>>();
        boundary_pivots_are_fixture_extremes::<rust_decimal::Decimal>();
        boundary_pivots_are_fixture_extremes::<String>();
        boundary_pivots_are_fixture_extremes::<F4>();
        boundary_pivots_are_fixture_extremes::<F8>();
    }
}

#[cfg(test)]
mod arbitrary_value_tests {
    use super::*;
    use proptest::strategy::Strategy;
    use proptest::test_runner::TestRunner;

    fn draws_a_value<T: ScalarType>() {
        let strat = T::arbitrary_value();
        let mut runner = TestRunner::default();
        // A single successful draw proves the strategy is wired and non-empty.
        let tree = strat
            .new_tree(&mut runner)
            .expect("arbitrary_value strategy must produce a value");
        let _v: T = proptest::strategy::ValueTree::current(&tree);
    }

    #[test]
    fn every_ordered_scalar_has_a_working_value_strategy() {
        draws_a_value::<i16>();
        draws_a_value::<i32>();
        draws_a_value::<i64>();
        draws_a_value::<chrono::NaiveDate>();
        draws_a_value::<chrono::DateTime<chrono::Utc>>();
        draws_a_value::<rust_decimal::Decimal>();
        draws_a_value::<String>();
        draws_a_value::<F4>();
        draws_a_value::<F8>();
    }
}

#[cfg(test)]
mod oracle_inventory_tests {
    use super::*;
    use eql_domains::CATALOG;

    /// The set of catalog tokens that should get an `eq` + `ord` fixture/e2e
    /// oracle suite is exactly the ordered (non-storage-only) scalars. Pin it so
    /// the catalog-driven suite macros (fixture_oracle / e2e_oracle) cannot drift
    /// from the catalog. `bool` is storage-only and must be excluded.
    #[test]
    fn ordered_scalar_tokens_match_catalog() {
        // `supports_ord` calls `terms_for`, which PANICS on an undeclared
        // (token, suffix) pair, so guard with `is_declared_for` first — bool has
        // no `_ord` domain and must short-circuit to false, not panic.
        let ordered: Vec<&str> = CATALOG
            .iter()
            .filter(|s| Variant::Ord.is_declared_for(s.name) && Variant::Ord.supports_ord(s.name))
            .map(|s| s.name)
            .collect();
        assert_eq!(
            ordered,
            vec![
                "integer",
                "smallint",
                "bigint",
                "date",
                "timestamp",
                "numeric",
                "text",
                "real",
                "double"
            ],
        );
        // bool is storage-only: no ordered domain, so it is excluded.
        assert!(!ordered.contains(&"boolean"));
    }

    /// Drift guard: the ordered-scalar set below is the EXACT list that must
    /// appear as `fixture_oracle_suite!(…, ordered)` in `fixture_oracle.rs` AND
    /// `e2e_oracle_suite!(…)` in `e2e_oracle.rs`. Those macro lists live in the
    /// test binary and cannot be introspected from here, so this test pins the
    /// expected set; a new ordered scalar added to CATALOG fails here until both
    /// suite lists are updated. (The matrix tier has its own gate:
    /// `mise run test:matrix:inventory`.)
    #[test]
    fn ordered_scalars_requiring_oracle_wiring() {
        // Same `is_declared_for` guard as above: `supports_ord` panics on a
        // scalar with no `_ord` domain (bool), so short-circuit first.
        let ordered: Vec<&str> = CATALOG
            .iter()
            .filter(|s| Variant::Ord.is_declared_for(s.name) && Variant::Ord.supports_ord(s.name))
            .map(|s| s.name)
            .collect();
        // Keep in lockstep with the fixture_oracle_suite! / e2e_oracle_suite!
        // instantiation lists.
        assert_eq!(
            ordered,
            vec![
                "integer",
                "smallint",
                "bigint",
                "date",
                "timestamp",
                "numeric",
                "text",
                "real",
                "double"
            ],
            "a new ordered scalar must be wired into BOTH oracle suites \
             (fixture_oracle.rs and e2e_oracle.rs)"
        );
    }
}
