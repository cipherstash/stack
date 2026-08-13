//! [`Fixture`] — the value-kind-tagged plaintext fixture value, its
//! `numeric_value` impl, and the `fixtures!` builder macro. Def + impl + macro
//! co-located here (the fixture-layer vocabulary).

use super::kind::ScalarKind;

/// Builds a `&[Fixture]`. The `int <ty>;` arm (a tt-muncher over `Min`/`Max`/
/// `Zero` and `N(<lit>)`) range-checks each literal against `<ty>` at compile
/// time via `const _RANGE_CHECK`, so out-of-range literals do not compile;
/// `text;`/`numeric;`/`jsonb;` wrap string literals. The reject case has no
/// in-crate test (macro isn't exported, no `trybuild` under zero-deps) — verify
/// by hand with a bad `N(..)`.
macro_rules! fixtures {
    (int $t:ty; $($body:tt)*) => { fixtures!(@int $t; [] $($body)*) };
    (@int $t:ty; [$($acc:expr),*]) => { &[$($acc),*] };
    (@int $t:ty; [$($acc:expr),*] , $($r:tt)*) => { fixtures!(@int $t; [$($acc),*] $($r)*) };
    (@int $t:ty; [$($acc:expr),*] Min  $($r:tt)*) => { fixtures!(@int $t; [$($acc,)* Fixture::Min ] $($r)*) };
    (@int $t:ty; [$($acc:expr),*] Max  $($r:tt)*) => { fixtures!(@int $t; [$($acc,)* Fixture::Max ] $($r)*) };
    (@int $t:ty; [$($acc:expr),*] Zero $($r:tt)*) => { fixtures!(@int $t; [$($acc,)* Fixture::Zero] $($r)*) };
    (@int $t:ty; [$($acc:expr),*] N($v:literal) $($r:tt)*) => {
        fixtures!(@int $t; [$($acc,)* Fixture::Int({ const _RANGE_CHECK: $t = $v; $v as i128 })] $($r)*)
    };
    (text;    $($s:literal),* $(,)?) => { &[$(Fixture::Text($s)),*] };
    (numeric; $($s:literal),* $(,)?) => { &[$(Fixture::Numeric($s)),*] };
    (jsonb;   $($s:literal),* $(,)?) => { &[$(Fixture::Jsonb($s)),*] };
    (date;    $($s:literal),* $(,)?) => { &[$(Fixture::Date($s)),*] };
    (timestamp; $($s:literal),* $(,)?) => { &[$(Fixture::Timestamp($s)),*] };
    (bool;    $($b:literal),* $(,)?) => { &[$(Fixture::Bool($b)),*] };
    (float;   $($s:literal),* $(,)?) => { &[$(Fixture::Float($s)),*] };
}

/// A single fixture plaintext value, value-kind tagged: `Min`/`Max`/`Zero` are
/// the integer matrix pivots (resolved per-kind); `Int` is an integer literal;
/// `Numeric`/`Text`/`Jsonb` carry rendered string literals.
///
/// `fixtures!` range-checks `Int` literals at compile time, but a hand-built
/// `Fixture::Int(n)` is not — hence the runtime invariant tests. `Int(MIN)` and
/// `Min` resolve to the same numeric value via `numeric_value`.
/// (`numeric_value` is impl'd below.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fixture {
    Min,
    Max,
    Zero,
    Int(i128),
    Numeric(&'static str),
    Text(&'static str),
    Jsonb(&'static str),
    /// An ISO-8601 date string (`"1970-01-01"`). The catalog stays zero-dep, so
    /// the string is parsed into a `chrono::NaiveDate` in the SQLx harness, not
    /// here. Distinct by literal, like the other string-backed fixtures.
    Date(&'static str),
    /// An RFC3339 UTC timestamp string (`"1970-01-01T00:00:00Z"`). The catalog
    /// stays zero-dep, so the string is parsed into a `chrono::DateTime<Utc>` in
    /// the SQLx harness, not here. Distinct by literal, like `Date`.
    Timestamp(&'static str),
    /// A boolean plaintext (`true` / `false`). The `bool` scalar is
    /// storage-only, so this fixture is encrypted (ciphertext only, no index
    /// term) and never participates in a comparison pivot. Distinct by value.
    Bool(bool),
    /// An IEEE-754 float plaintext rendered as a string (`"0.5"`, `"-inf"`).
    /// The catalog stays zero-dep, so the string is parsed into `f32`/`f64` in
    /// the SQLx harness, not here. Distinct by parsed value (the harness
    /// `float_fixtures_are_distinct_by_value` guard enforces this). NaN and
    /// `-0.0` are deliberately excluded; `±Inf` (`"inf"`/`"-inf"`) ARE fixtures.
    Float(&'static str),
}

impl Fixture {
    /// The integer value for this fixture (`Min`/`Max` -> kind bounds, `Zero` ->
    /// 0, `Int(n)` -> n), or `None` for the string-backed kinds. Does not
    /// range-check; `every_fixture_value_is_within_kind_bounds` guards the bounds.
    ///
    /// `const fn` so the `int_values!` materialiser can resolve a whole fixture
    /// list into a typed `&'static` array at compile time.
    pub const fn numeric_value(self, kind: ScalarKind) -> Option<i128> {
        match self {
            // `?` is not allowed in `const fn`, so match `as_bounded_int()`
            // explicitly. A pivot on a non-integer kind resolves to `None`; the
            // `pivot_sentinels_only_appear_with_integer_kinds` catalog test
            // guarantees that combination never reaches a real `CATALOG` row.
            Fixture::Min => match kind.as_bounded_int() {
                Some(k) => Some(k.min_value()),
                None => None,
            },
            Fixture::Max => match kind.as_bounded_int() {
                Some(k) => Some(k.max_value()),
                None => None,
            },
            Fixture::Zero => match kind.as_bounded_int() {
                Some(_) => Some(0),
                None => None,
            },
            // Gate the literal on the integer kinds too, mirroring the sentinels
            // above: a hand-built `Int(n)` on a non-integer kind resolves to
            // `None` rather than fabricating a number for a `Text`/`Date`/`Bool`
            // kind that has no integer projection.
            Fixture::Int(n) => match kind.as_bounded_int() {
                Some(_) => Some(n),
                None => None,
            },
            Fixture::Numeric(_)
            | Fixture::Text(_)
            | Fixture::Jsonb(_)
            | Fixture::Date(_)
            | Fixture::Timestamp(_)
            | Fixture::Float(_)
            | Fixture::Bool(_) => None,
        }
    }
}
