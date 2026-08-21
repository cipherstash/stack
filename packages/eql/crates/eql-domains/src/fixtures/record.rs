//! The fixture-layer record: a `TypeFixtures` per scalar type, pairing a
//! structural catalog row (`&DomainFamily`) with its `ScalarKind` and its
//! plaintext fixture `values`. This is where `kind`/`fixtures` live now that
//! they are off `DomainFamily` — a fixture/test concern, not structural catalog
//! data. The `FIXTURES` table mirrors `CATALOG` order; the `const _` parity
//! block at the bottom of this file replaces the struct's old compiler-enforced
//! 1:1 — a build-time `assert!` over `CATALOG`/`FIXTURES`, not a runtime test.

use super::fixture::Fixture;
use super::kind::ScalarKind;
use crate::DomainFamily;

/// One scalar type's fixture-layer data: the structural catalog row it belongs
/// to (`family`), the native scalar it maps onto (`kind`), and its distinct
/// plaintext fixture `values`. `family` is a reference to the same
/// `DomainFamily` const that `CATALOG` carries, so `family.name` is the join key
/// back to the catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypeFixtures {
    pub family: &'static DomainFamily,
    pub kind: ScalarKind,
    pub values: &'static [Fixture],
}

/// integer fixtures. `N(..)` literals are range-checked against `i32` at compile
/// time by `fixtures!`.
pub const INTEGER_FIXTURES: TypeFixtures = TypeFixtures {
    family: &crate::INTEGER,
    kind: ScalarKind::I32,
    values: fixtures!(int i32;
        Min, N(-100), N(-1), Zero, N(1), N(2), N(5), N(10), N(17), N(25),
        N(42), N(50), N(100), N(250), N(1000), N(9999), Max),
};

/// smallint fixtures (`i16`-range-checked).
pub const SMALLINT_FIXTURES: TypeFixtures = TypeFixtures {
    family: &crate::SMALLINT,
    kind: ScalarKind::I16,
    values: fixtures!(int i16;
        Min, N(-30000), N(-100), N(-1), Zero, N(1), N(2), N(5), N(10), N(17),
        N(25), N(42), N(50), N(100), N(250), N(1000), N(9999), N(30000), Max),
};

/// bigint fixtures (`i64`-range-checked) — the integer set plus two values beyond the
/// i32 range (`±5_000_000_000`) so the matrix exercises the full 64-bit width.
pub const BIGINT_FIXTURES: TypeFixtures = TypeFixtures {
    family: &crate::BIGINT,
    kind: ScalarKind::I64,
    values: fixtures!(int i64;
        Min, N(-5000000000), N(-100), N(-1), Zero, N(1), N(2), N(5), N(10), N(17),
        N(25), N(42), N(50), N(100), N(250), N(1000), N(9999), N(5000000000), Max),
};

/// date fixtures — ISO-8601 strings; the three temporal pivots
/// (`1900-01-01`, `1970-01-01`, `2099-12-31`) MUST be present verbatim.
pub const DATE_FIXTURES: TypeFixtures = TypeFixtures {
    family: &crate::DATE,
    kind: ScalarKind::Date,
    values: fixtures!(date;
        "1900-01-01", "1950-07-15", "1969-12-31", "1970-01-01", "1970-01-02",
        "1980-02-29", "1991-11-09", "1999-12-31", "2000-01-01", "2004-02-29",
        "2012-06-30", "2016-03-15", "2020-10-21", "2024-02-29", "2038-01-19",
        "2099-12-31"),
};

/// timestamp fixtures — RFC3339 UTC strings; the three temporal pivots
/// (`1900-01-01T00:00:00Z`, `1970-01-01T00:00:00Z`, `2099-12-31T23:59:59Z`)
/// MUST be present verbatim.
pub const TIMESTAMP_FIXTURES: TypeFixtures = TypeFixtures {
    family: &crate::TIMESTAMP,
    kind: ScalarKind::Timestamp,
    values: fixtures!(timestamp;
        "1900-01-01T00:00:00Z", "1950-07-15T06:30:00Z", "1969-12-31T23:59:59Z",
        "1970-01-01T00:00:00Z", "1970-01-01T00:00:01Z", "1985-04-12T23:20:50Z",
        "1999-12-31T23:59:59Z", "2000-01-01T00:00:00Z", "2004-02-29T12:00:00Z",
        "2012-06-30T11:59:59Z", "2016-03-15T08:15:30Z", "2020-10-21T14:45:00Z",
        "2024-02-29T17:30:45Z", "2038-01-19T03:14:07Z", "2099-12-31T23:59:59Z"),
};

/// numeric fixtures — distinct by `Decimal` value, mirroring `ore-rs`'s order
/// vectors; includes 0 and the min/max pivots (`±1000000000000`).
pub const NUMERIC_FIXTURES: TypeFixtures = TypeFixtures {
    family: &crate::NUMERIC,
    kind: ScalarKind::Numeric,
    values: fixtures!(numeric;
        "-1000000000000", "-1000000", "-1.001", "-1", "-0.5", "-0.001",
        "0", "0.001", "0.5", "0.999999999", "1", "1.001", "1000000", "1000000000000"),
};

/// text fixtures — lexicographic spread (`aard` min, `frank` mid, `zzzz` max
/// pivots, present verbatim), a known substring pair, and the G3-4b divergence
/// pair (`qabcqbcaqcabqabd` / `abcabd`). The empty string is deliberately absent
/// (issue #262).
pub const TEXT_FIXTURES: TypeFixtures = TypeFixtures {
    family: &crate::TEXT,
    kind: ScalarKind::Text,
    values: fixtures!(text;
        "aard", "aardvark", "alice", "bob", "carol",
        "dave", "erin", "frank", "mallory", "trent", "zzzz",
        "qabcqbcaqcabqabd", "abcabd"),
};

/// boolean fixtures — both values. Storage-only: encrypted (ciphertext only), never
/// a comparison pivot.
pub const BOOLEAN_FIXTURES: TypeFixtures = TypeFixtures {
    family: &crate::BOOLEAN,
    kind: ScalarKind::Bool,
    values: fixtures!(bool; false, true),
};

/// real fixtures — IEEE-754 strings, every value dyadic (f32-exact); pivots
/// `-inf` / `0` / `inf` present verbatim. NaN and `-0.0` excluded.
pub const REAL_FIXTURES: TypeFixtures = TypeFixtures {
    family: &crate::REAL,
    kind: ScalarKind::F32,
    values: fixtures!(float;
        "-inf", "-1024", "-2.25", "-1", "-0.5", "-0.25",
        "0", "0.25", "0.5", "1", "2.25", "1024", "inf"),
};

/// double fixtures — IEEE-754 strings; pivots `-inf` / `0` / `inf` present
/// verbatim. NaN and `-0.0` excluded.
pub const DOUBLE_FIXTURES: TypeFixtures = TypeFixtures {
    family: &crate::DOUBLE,
    kind: ScalarKind::F64,
    values: fixtures!(float;
        "-inf", "-1e300", "-1000000", "-1.5", "-1", "-0.001",
        "0", "0.001", "1", "1.5", "1000000", "1e300", "inf"),
};

/// json fixtures — PLAINTEXT JSON document strings (NOT ciphertext). Mirrors
/// the `v3_ste_vec` document shape (`hello`/`number`/`nested`), distinct by
/// value. The ENCRYPTED SteVec fixture the binding conformance test uses is
/// generated separately by `tests/sqlx/src/fixtures/v3_ste_vec.rs` (FixtureSpec).
pub const JSON_FIXTURES: TypeFixtures = TypeFixtures {
    family: &crate::JSON,
    kind: ScalarKind::Jsonb,
    values: fixtures!(jsonb;
        "{\"hello\":\"world-1\",\"number\":1,\"nested\":{\"deep\":\"constant\"}}",
        "{\"hello\":\"world-2\",\"number\":2,\"nested\":{\"deep\":\"constant\"}}",
        "{\"hello\":\"world-3\",\"number\":3,\"nested\":{\"deep\":\"constant\"}}"),
};

/// The fixture table — one record per scalar type, in `CATALOG` order. The
/// fixture-layer mirror of `CATALOG`; the `const _` parity block below pins the
/// parity at build time.
pub const FIXTURES: &[TypeFixtures] = &[
    INTEGER_FIXTURES,
    SMALLINT_FIXTURES,
    BIGINT_FIXTURES,
    DATE_FIXTURES,
    TIMESTAMP_FIXTURES,
    NUMERIC_FIXTURES,
    TEXT_FIXTURES,
    BOOLEAN_FIXTURES,
    REAL_FIXTURES,
    DOUBLE_FIXTURES,
    JSON_FIXTURES,
];

/// The native scalar [`ScalarKind`] of a catalog family, by `family.name`
/// (`"text"` → [`ScalarKind::Text`]). `None` for a name no family declares.
///
/// The catalog's structural rows (`DomainFamily`) carry only `{name, domains}` —
/// the kind is a fixture-layer field, joined back by name (see the module docs on
/// the `lib.rs` layout split). This is that join, in one place, so consumers
/// needing a family's kind do not each re-inline a `FIXTURES.iter().find(…)`.
pub fn kind_for(family_name: &str) -> Option<ScalarKind> {
    FIXTURES
        .iter()
        .find(|f| f.family.name == family_name)
        .map(|f| f.kind)
}

/// Compile-time `&str` equality, usable in `const` context. `str::eq` /
/// `PartialEq` are not `const fn` on stable, so the parity block below needs its
/// own byte-wise comparison.
const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// A stable `u8` tag per `ScalarKind`, so two kinds can be compared in `const`
/// context (`PartialEq` is not `const fn` on stable). Only the parity block's
/// `family.name` ↔ `kind` binding consumes this.
const fn kind_tag(kind: ScalarKind) -> u8 {
    match kind {
        ScalarKind::I16 => 0,
        ScalarKind::I32 => 1,
        ScalarKind::I64 => 2,
        ScalarKind::Numeric => 3,
        ScalarKind::Text => 4,
        ScalarKind::Jsonb => 5,
        ScalarKind::Date => 6,
        ScalarKind::Timestamp => 7,
        ScalarKind::Bool => 8,
        ScalarKind::F32 => 9,
        ScalarKind::F64 => 10,
    }
}

/// The native scalar each catalog family is supposed to map onto, keyed by
/// `family.name`. The single source the parity block uses to bind every
/// `TypeFixtures.kind` to its family at build time. An unmapped name is a
/// const-eval panic, so a new scalar type cannot be added without naming its
/// expected kind here.
const fn expected_kind(name: &str) -> ScalarKind {
    if str_eq(name, "smallint") {
        ScalarKind::I16
    } else if str_eq(name, "integer") {
        ScalarKind::I32
    } else if str_eq(name, "bigint") {
        ScalarKind::I64
    } else if str_eq(name, "date") {
        ScalarKind::Date
    } else if str_eq(name, "timestamp") {
        ScalarKind::Timestamp
    } else if str_eq(name, "numeric") {
        ScalarKind::Numeric
    } else if str_eq(name, "text") {
        ScalarKind::Text
    } else if str_eq(name, "boolean") {
        ScalarKind::Bool
    } else if str_eq(name, "real") {
        ScalarKind::F32
    } else if str_eq(name, "double") {
        ScalarKind::F64
    } else if str_eq(name, "json") {
        ScalarKind::Jsonb
    } else {
        panic!("unmapped scalar token in expected_kind — name its kind here")
    }
}

/// Compile-time parity guard: `FIXTURES` must mirror `CATALOG` exactly, in
/// order, AND every record's `kind` must match the kind its family maps onto.
/// This is the build-time invariant that REPLACES `DomainFamily`'s old
/// compiler-enforced `kind`/`fixtures` fields — every catalog row has exactly
/// one fixture record and vice-versa, same order, with the right `kind`. As a
/// `const` item it is const-evaluated on every `cargo build`: a missing, extra,
/// or misaligned `TypeFixtures`, or one carrying the wrong `kind` (e.g.
/// `TypeFixtures { family: &BIGINT, kind: I16, .. }`), fails the build with
/// `error[E0080]: evaluation panicked` carrying the message below — it cannot be
/// `#[cfg]`-gated away or skipped by a test filter, so the `kind` mismatch is
/// caught before any consumer (including `eql-tests-macros` expansion) sees
/// `FIXTURES`. It proves NAME + ORDERING + KIND coverage; fixture-VALUE
/// correctness is gated by the in-crate value/invariant tests, not here.
const _: () = {
    assert!(
        FIXTURES.len() == crate::CATALOG.len(),
        "every CATALOG family needs exactly one TypeFixtures (FIXTURES.len() != CATALOG.len())"
    );
    let mut i = 0;
    while i < crate::CATALOG.len() {
        assert!(
            str_eq(crate::CATALOG[i].name, FIXTURES[i].family.name),
            "FIXTURES must mirror CATALOG in order: name mismatch at this index"
        );
        assert!(
            kind_tag(FIXTURES[i].kind) == kind_tag(expected_kind(FIXTURES[i].family.name)),
            "TypeFixtures.kind does not match the kind its family maps onto"
        );
        i += 1;
    }
};

#[cfg(test)]
mod str_eq_tests {
    use super::str_eq;

    /// `str_eq` is the sole new logic the compile-time parity guard relies on,
    /// and the guard only ever exercises the *matching* path against the real
    /// (aligned) `CATALOG`/`FIXTURES`. A bug in `str_eq` that returned `true` for
    /// differing bytes would silently neuter the guard, so pin its behaviour
    /// directly: equal strings match; any length or byte difference does not.
    #[test]
    fn str_eq_matches_iff_byte_identical() {
        assert!(str_eq("", ""));
        assert!(str_eq("ab", "ab"));
        assert!(str_eq("integer", "integer"));
        // Differing length.
        assert!(!str_eq("a", "ab"));
        assert!(!str_eq("ab", "a"));
        assert!(!str_eq("", "a"));
        // Same length, one byte differs (the path that would neuter the guard).
        assert!(!str_eq("a", "b"));
        assert!(!str_eq("integer", "bigint"));
        assert!(!str_eq("date", "bate"));
    }
}
