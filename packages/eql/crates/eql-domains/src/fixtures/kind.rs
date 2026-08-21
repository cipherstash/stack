//! [`ScalarKind`] / [`BoundedIntKind`] — the native scalar a domain maps onto
//! plus the total fixed-width-integer accessors. Defs and impls co-located here
//! (the fixture-layer vocabulary).

/// The fixed-width integer kinds — exactly those scalar kinds with an `i128`
/// range and `MIN`/`MAX`/`Zero` sentinels. These accessors are **total**: every
/// variant answers every method. The non-integer kinds (`Numeric`/`Text`/
/// `Jsonb`/`Date`/`Timestamp`/`Bool`/`F32`/`F64`) are simply not representable
/// here, so there is no partial function to panic — `ScalarKind::Date` cannot
/// call `min_symbol()` because `Date` is not a `BoundedIntKind`. Reach this type
/// from a `ScalarKind` via [`ScalarKind::as_bounded_int`]. (Accessors are impl'd
/// below.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundedIntKind {
    I16,
    I32,
    I64,
}

/// The native scalar a domain type maps onto. The integer kinds (`I16`/`I32`/
/// `I64`) carry i128 bounds; the non-integer kinds (`Numeric`/`Text`/`Jsonb`/
/// `Date`/`Timestamp`/`Bool`/`F32`/`F64`) have no i128 range and string- or
/// bool-backed fixtures. All but `Jsonb` and `Bool` are still ORE-orderable —
/// `Jsonb` has no order, and `Bool` is storage-only (no comparison surface).
/// Capability layer only: `CATALOG` declares which kinds actually exist.
///
/// The bounded-numeric accessors live on the total [`BoundedIntKind`], reached
/// via [`ScalarKind::as_bounded_int`]; non-integer kinds have no such accessor,
/// so misuse is a compile error rather than a runtime panic. (Accessors are
/// impl'd below.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarKind {
    I16,
    I32,
    I64,
    Numeric,
    Text,
    Jsonb,
    /// Calendar date (`chrono::NaiveDate`). Ordered like the integer kinds via
    /// ORE, but string-backed (ISO-8601) at the catalog layer and with no i128
    /// range — so it is *not* `is_int()` and `as_bounded_int()` returns `None`
    /// for it, like the other non-integer kinds. The bounded-numeric accessors
    /// live on `BoundedIntKind`, which `Date` cannot be, so they are
    /// unreachable for it by construction rather than by a runtime panic.
    Date,
    /// UTC timestamp (`chrono::DateTime<Utc>`). Ordered like the integer kinds
    /// via ORE, but string-backed (RFC3339) at the catalog layer and with no
    /// i128 range — so it is *not* `is_int()` and `as_bounded_int()` returns
    /// `None` for it, like the other non-integer kinds. The bounded-numeric
    /// accessors live on `BoundedIntKind`, which `Timestamp` cannot be, so they
    /// are unreachable for it by construction rather than by a runtime panic.
    /// UTC-normalized: cipherstash has no tz-preserving type, so it maps to the
    /// `timestamp` cast and the SQL `timestamp with time zone` plaintext type.
    /// The value is an instant (Postgres `timestamp with time zone`) wearing the
    /// SQL-standard name `timestamp`, matching the cipherstash cast convention.
    Timestamp,
    /// Boolean (`bool`). **Encryption-only / storage-only**: it carries no index
    /// term and is *not* `is_int()`/`is_temporal()`/`is_text()`. A two-value
    /// column has such low cardinality that any searchable index (even HMAC
    /// equality) would trivially leak the plaintext distribution, so the catalog
    /// gives `bool` a single term-less storage domain and no `_eq`/`_ord` — the
    /// value is encrypted at rest and decrypted by the proxy, never searched
    /// server-side. Like the other non-integer kinds, the bounded-numeric
    /// accessors are unreachable for it by construction.
    Bool,
    /// 32-bit IEEE-754 binary float (`f32`, Postgres `real`/`float4`).
    /// Ordered like the integer kinds via ORE, but with no i128 range
    /// (`as_bounded_int()` returns `None`) and string-backed at the catalog
    /// layer. Encrypts through the single f64 float crypto path
    /// (`Plaintext::Float`) — the f32→f64 widening is exact and monotonic.
    F32,
    /// 64-bit IEEE-754 binary float (`f64`, Postgres `double precision`/
    /// `float8`). The native width of the float crypto path (`F32` widens into
    /// it); otherwise classified exactly like [`ScalarKind::F32`].
    F64,
}

impl BoundedIntKind {
    /// The Rust type name as it appears in generated source (e.g. `"i32"`).
    pub const fn rust_type(self) -> &'static str {
        match self {
            BoundedIntKind::I16 => "i16",
            BoundedIntKind::I32 => "i32",
            BoundedIntKind::I64 => "i64",
        }
    }

    /// The `MIN` named-constant symbol (e.g. `"i32::MIN"`).
    pub const fn min_symbol(self) -> &'static str {
        match self {
            BoundedIntKind::I16 => "i16::MIN",
            BoundedIntKind::I32 => "i32::MIN",
            BoundedIntKind::I64 => "i64::MIN",
        }
    }

    /// The `MAX` named-constant symbol (e.g. `"i32::MAX"`).
    pub const fn max_symbol(self) -> &'static str {
        match self {
            BoundedIntKind::I16 => "i16::MAX",
            BoundedIntKind::I32 => "i32::MAX",
            BoundedIntKind::I64 => "i64::MAX",
        }
    }

    /// The zero literal symbol (always `"0"`).
    pub const fn zero_symbol(self) -> &'static str {
        "0"
    }

    /// Inclusive lower bound of the representable range, widened to `i128`.
    pub const fn min_value(self) -> i128 {
        match self {
            BoundedIntKind::I16 => i16::MIN as i128,
            BoundedIntKind::I32 => i32::MIN as i128,
            BoundedIntKind::I64 => i64::MIN as i128,
        }
    }

    /// Inclusive upper bound of the representable range, widened to `i128`.
    pub const fn max_value(self) -> i128 {
        match self {
            BoundedIntKind::I16 => i16::MAX as i128,
            BoundedIntKind::I32 => i32::MAX as i128,
            BoundedIntKind::I64 => i64::MAX as i128,
        }
    }
}

impl ScalarKind {
    /// The fixed-width integer kinds — those with `i128` bounds and
    /// `Min`/`Max`/`Zero` sentinels — projected onto [`BoundedIntKind`], or
    /// `None` for the non-integer kinds. The single boundary where "this kind has
    /// bounds" is decided; the bounded accessors live on `BoundedIntKind` and are
    /// total there. NOT an orderability test: `Numeric`/`Text`/`Date` are
    /// ORE-orderable yet not integers.
    pub const fn as_bounded_int(self) -> Option<BoundedIntKind> {
        match self {
            ScalarKind::I16 => Some(BoundedIntKind::I16),
            ScalarKind::I32 => Some(BoundedIntKind::I32),
            ScalarKind::I64 => Some(BoundedIntKind::I64),
            ScalarKind::Numeric
            | ScalarKind::Text
            | ScalarKind::Jsonb
            | ScalarKind::Bool
            | ScalarKind::F32
            | ScalarKind::F64
            | ScalarKind::Date
            | ScalarKind::Timestamp => None,
        }
    }

    /// True for the fixed-width integer kinds. Gates the bounded-numeric
    /// invariants. Equivalent to `self.as_bounded_int().is_some()`.
    pub const fn is_int(self) -> bool {
        self.as_bounded_int().is_some()
    }

    /// True for chrono-backed temporal kinds (`Date`, `Timestamp`) — the kinds
    /// whose test `ScalarType` impl is generated by `temporal_values!` rather
    /// than the integer proc-macro path. Replaces the `[temporal]` marker.
    pub const fn is_temporal(self) -> bool {
        matches!(self, ScalarKind::Date | ScalarKind::Timestamp)
    }

    /// True for the `Text` kind — an unbounded, owned-`String` scalar. Keeps
    /// "textness" classification in the catalog crate alongside `is_int` /
    /// `is_temporal`, rather than matching the variant at each call site.
    pub const fn is_text(self) -> bool {
        matches!(self, ScalarKind::Text)
    }

    /// True for the IEEE-754 float kinds (`F32`, `F64`) — ordered, non-integer,
    /// string-backed-fixture scalars whose `impl ScalarType` is hand-written in
    /// `scalar_domains.rs` (like `text`/`numeric`). Keeps float classification in
    /// the catalog crate alongside `is_int`/`is_temporal`/`is_text`.
    pub const fn is_float(self) -> bool {
        matches!(self, ScalarKind::F32 | ScalarKind::F64)
    }

    /// Does a JSON document hold this kind's values **as themselves** — is
    /// there a native JSON scalar type for the kind (RFC 8259: string, number,
    /// boolean)?
    ///
    /// This is the PARTICIPATION gate for the `json_entry` cross-type seam.
    /// A family whose values have no native JSON representation has
    /// no JSON leaf to compare against, so its query operands must not bind
    /// `public.eql_v3_json_entry` at all — for ANY operator, not just `=`.
    ///
    /// `Date`/`Timestamp` are the load-bearing `false` rows. JSON has no
    /// date/timestamp type; in practice those values are **marshaled into
    /// strings** (ISO-8601/RFC 3339), so a "date leaf" IS a text leaf and is
    /// served by the TEXT surface (`query_text_ord` — ISO-8601 string order is
    /// chronological order; equality via `@>` containment, since text `=` is
    /// blocked as collated). cipherstash-client agrees mechanically: a SteVec
    /// query term cannot even be built from a temporal plaintext —
    /// `OrderableTerm::try_from(&Plaintext)` returns `Err(invalid_type)` for
    /// `NaiveDate`/`Timestamp` (`json_indexer/ste_vec/priv_state/`
    /// `ste_plaintext_term.rs`, verified against 0.38.1) — so a
    /// `(json_entry, query_date_ord)` operator could never see a real operand;
    /// it would be dead surface reachable only by hand-crafted payloads.
    ///
    /// `Bool` is honestly `true` (JSON has native booleans) but never reaches
    /// the seam: the seam additionally requires a `Term::Ope`-carrying operand,
    /// and `boolean` is storage-only — a bool leaf maps to a structural `Mac`
    /// term, never an orderable `op`. `Jsonb` is `false`: its plaintext is a
    /// whole document, not a scalar leaf; containment (`@>`) serves it.
    ///
    /// This predicate decides WHETHER a family's operands may bind `json_entry`
    /// (for ordering). Equality never binds the extract surface for any family
    /// — it is document containment on the value selector — so there is
    /// no companion "is `=` sound here" predicate to layer with.
    pub const fn has_native_json_leaf(self) -> bool {
        match self {
            // JSON numbers.
            ScalarKind::I16
            | ScalarKind::I32
            | ScalarKind::I64
            | ScalarKind::F32
            | ScalarKind::F64
            | ScalarKind::Numeric => true,
            // JSON strings.
            ScalarKind::Text => true,
            // JSON booleans (never reaches the Ope seam; see doc).
            ScalarKind::Bool => true,
            // No native JSON type — marshaled into strings; the text surface
            // owns those leaves.
            ScalarKind::Date | ScalarKind::Timestamp => false,
            // A document, not a scalar leaf.
            ScalarKind::Jsonb => false,
        }
    }

    /// A debug/identifier string for the kind: the canonical Rust plaintext type
    /// name (`"i32"`, `"chrono::NaiveDate"`, `"rust_decimal::Decimal"`). `Jsonb`
    /// maps to `serde_json::Value` — its plaintext is an arbitrary JSON document.
    /// Its encrypted bindings are NOT the flat-scalar structs the other kinds
    /// generate; they are the hand-written SteVec payload types in
    /// `crates/eql-bindings/src/v3/jsonb.rs` (the SQL generator skips SteVec
    /// shapes). Only call site today is `crates/eql-domains/src/tests.rs`.
    pub const fn rust_type(self) -> &'static str {
        match self {
            ScalarKind::I16 => "i16",
            ScalarKind::I32 => "i32",
            ScalarKind::I64 => "i64",
            ScalarKind::Text => "String",
            ScalarKind::Date => "chrono::NaiveDate",
            ScalarKind::Timestamp => "chrono::DateTime<Utc>",
            ScalarKind::Numeric => "rust_decimal::Decimal",
            ScalarKind::Bool => "bool",
            ScalarKind::F32 => "f32",
            ScalarKind::F64 => "f64",
            ScalarKind::Jsonb => "serde_json::Value",
        }
    }
}
