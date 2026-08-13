//! Scalar/term catalog for EQL encrypted-domain codegen — the single Rust
//! source of truth for every scalar type and term. Std-only, no dependencies.
//!
//! Capability axes are independent: equality covers every kind; order covers
//! every kind except `jsonb` (the ordering terms compare ciphertext, so they
//! are plaintext-agnostic — `text`/`date` order like integers); only the integer
//! kinds have an i128 range with `Min`/`Max`/`Zero` sentinels. `numeric_value`
//! cannot yet express the order of a non-integer fixture set.
//!
//! Public names are consumed verbatim by the later codegen plans — do not rename.
//!
//! **Layout.** This file holds the *structural* catalog: the `DomainFamily`/
//! `Domain`/`Term`/`Role` definitions, the per-type `DomainFamily` rows, and
//! `CATALOG` — so the structural surface reads top-to-bottom. `DomainFamily` is
//! purely `{ name, domains }`; the native-scalar `kind` and the plaintext
//! `fixtures` are a fixture-layer concern that lives in the `fixtures` module
//! (the `ScalarKind`/`Fixture` vocabulary, the per-type `TypeFixtures` records +
//! `FIXTURES` table, and the materialised `*_VALUES` slices), joined back to a
//! catalog row by `name`. The inherent `impl` blocks for the structural types
//! live in sibling modules (`term`, `spec`); the unit tests live in `tests`. The
//! crate-root `pub use fixtures::{…}` below preserves the public fixture-layer
//! paths.

#[macro_use]
mod fixtures;
mod spec;
mod term;

pub use fixtures::{
    kind_for, BoundedIntKind, Fixture, ScalarKind, TypeFixtures, BIGINT_FIXTURES, BIGINT_VALUES,
    BOOLEAN_FIXTURES, DATE_FIXTURES, DOUBLE_FIXTURES, FIXTURES, INTEGER_FIXTURES, INTEGER_VALUES,
    JSON_FIXTURES, NUMERIC_FIXTURES, REAL_FIXTURES, SMALLINT_FIXTURES, SMALLINT_VALUES,
    TEXT_FIXTURES, TEXT_VALUES, TIMESTAMP_FIXTURES,
};

/// Always-present payload keys required by every generated domain CHECK,
/// before the domain's term keys, in order: envelope version (`v`), ident
/// (`i`), ciphertext (`c`).
///
/// Lives here — in the catalog — because it is cross-schema contract data
/// consumed on both sides of the generated surface: `eql-codegen` builds
/// every domain CHECK from it, and `eql-bindings` builds its payload structs
/// and parity tests against it. One definition, so the envelope cannot
/// drift between the SQL and the canonical types.
pub const ENVELOPE_KEYS: &[&str] = &["v", "i", "c"];

/// The version prefix every PUBLIC-SCHEMA EQL type name carries:
/// `public.eql_v3_integer_eq`, `public.eql_v3_json`, …. The prefix
/// keeps EQL domains from shadowing PostgreSQL built-in type names
/// (`integer`, `text`, `json`, …) and gives each EQL version a distinct
/// column-type namespace so multiple EQL versions can coexist in one
/// database. Query-operand domains are NOT prefixed — they live in the
/// `eql_v3` schema, which already versions them.
///
/// Lives here — in the catalog — because it is cross-crate contract data:
/// `eql-codegen` renders every public domain name through it, and
/// `eql-bindings`' parity tests re-derive the expected names from it. The
/// catalog's own names stay bare — the prefix is applied only at SQL-name
/// construction ([`Domain::sql_typname`]); file names, struct identifiers,
/// and matrix test names all keep the bare name.
pub const PUBLIC_TYPNAME_PREFIX: &str = "eql_v3_";

/// A fixed index term known to the scalar materializer.
///
/// `Hm` provides equality; `Ore` and `Ope` provide equality plus ordering —
/// `Ore` is the block-ORE array term (`ob`, compared by the custom N-block
/// protocol) and `Ope` is the CLLW-OPE term (`op`, a hex-encoded ciphertext
/// that is natively bytea-sortable after hex-decode: no custom comparison
/// protocol). `Ope`'s `=`/`<>` claim on the integer families rests on OPE
/// being deterministic — an order-preserving encryption maps equal
/// plaintexts to equal ciphertexts (a randomized term would make `op`-routed
/// equality silently return false negatives). Verified against real
/// ciphertexts (cipherstash-client 0.38.1+): the fixture pipeline
/// covers the `_ord_ope` domains and `property::cross_ciphertext` pins
/// byte-identical `op` terms across independent encryptions of one
/// plaintext. The `json_key`/`extractor`/`ctor` values
/// are the cross-schema SQL contract — changing one is a generated-SQL
/// behaviour change, not a refactor. (The per-term accessors and
/// `*_for_terms` helpers are impl'd in `term`.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Term {
    Hm,
    Ore,
    Bloom,
    Ope,
}

/// The generated-file role of a domain, resolved from its terms by the
/// richest-comparison precedence in [`Role::rank`] (or `Storage` for a term-less
/// domain). Gates ord-only codegen (aggregates) via an exhaustive `==` against
/// [`Role::Ord`] rather than a stringly-typed compare — a typo can no longer
/// silently disable aggregate generation. `label` is the `&'static str` form for
/// any future template/serde consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Storage,
    Eq,
    Ord,
    Match,
}

impl Role {
    /// The lowercase label (`"storage"`/`"eq"`/`"ord"`/`"match"`).
    pub const fn label(self) -> &'static str {
        match self {
            Role::Storage => "storage",
            Role::Eq => "eq",
            Role::Ord => "ord",
            Role::Match => "match",
        }
    }

    /// Precedence used by [`Term::role_for_terms`] to resolve a multi-term
    /// domain to a single generated-file role: the richest comparison capability
    /// wins (`Ord > Eq > Match > Storage`). Ordering subsumes equality, so an
    /// `Ore` term anywhere makes the domain ord-shaped; `Match` (containment) is
    /// a weaker standalone surface; `Storage` is the absence of any term. The
    /// current catalog is single-term, so this only disambiguates a hypothetical
    /// future mixed-term domain — and keeps `role_for_terms` consistent with
    /// [`Term::operators_for_terms`], which already unions across all terms.
    pub const fn rank(self) -> u8 {
        match self {
            Role::Storage => 0,
            Role::Match => 1,
            Role::Eq => 2,
            Role::Ord => 3,
        }
    }
}

/// The structural shape of a domain's payload. Every existing scalar family is
/// [`Shape::Scalar`] (flat `{v,i,c,+terms}`). The SteVec shapes belong to the
/// `json` family and carry document/entry/query payloads whose keys are NOT the
/// flat envelope+term set — `Term`, `Role`, `operators_for_terms`, and
/// `capability_label` continue to assume flat-scalar semantics and are simply
/// never invoked on a SteVec domain (consumers filter/branch on `Shape`).
///
/// Coupling invariant (pinned by `tests::shape_and_terms_are_consistent`): a
/// non-`Scalar` domain always has empty `terms`, and any domain with non-empty
/// `terms` is `Scalar`. Empty `terms` here does NOT mean "no index capability":
/// a SteVec domain is searchable by value-selector presence and, for ordered
/// path entries, an optional CLLW-OPE `op`. These fields live *inside* the
/// payload shape rather than as a flat family-level `Term` list. The `terms`
/// field models only the flat-scalar term set that `Term`/`Role`/
/// `operators_for_terms`/`capability_label` consume; SteVec capability is carried
/// structurally by the `Shape` and is invisible to those flat-term consumers by
/// construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// Flat `{v, i, c, +terms}` — every existing scalar family (default).
    Scalar,
    /// A `json` family SteVec payload: `public.eql_v3_json_search`
    /// (`{v, k, i, h, sv: [entry]}`), `public.eql_v3_json_entry`
    /// (`{s, c, a?, op?, i?, v?, h?}`), or `eql_v3.query_json`
    /// (`{sv: [query-entry]}`). The three differ in payload body but share the
    /// non-flat-scalar shape, so a single variant covers them; `Domain.name`
    /// (`"search"`/`"entry"`/`"query"`) already disambiguates which one a given
    /// domain is (see `Domain::full_name` / `Domain::rust_struct_name`). The
    /// family's fourth domain, the bare storage domain `public.eql_v3_json`, is
    /// `Shape::Scalar`, not SteVec.
    SteVec,
}

/// One generated public domain: a bare domain name joined under the family
/// name (codegen owns the `_` separator) plus the fixed index terms it
/// carries. Name `""` is the storage-only domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Domain {
    pub name: &'static str,
    pub terms: &'static [Term],
    pub shape: Shape,
}

/// A scalar encrypted-domain type's structural surface: its SQL `name` and the
/// generated domains. One row of the Rust `CATALOG`. The native-scalar `kind`
/// and the plaintext `fixtures` are a fixture-layer concern and live in the
/// `fixtures` module's `TypeFixtures` records, joined back by `name`.
/// (`domain_name`/`is_eq_only`/… are impl'd in `spec`.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainFamily {
    pub name: &'static str,
    pub domains: &'static [Domain],
}

/// Domains shared by every ordered-integer scalar, in manifest file order:
/// storage (no terms), `_eq` (hm), `_ord_ore` (ore), `_ord` (ope),
/// `_ord_ope` (ope).
///
/// **`_ord` is the OPE-backed default.** It carries the CLLW-OPE term (`op`):
/// a hex-encoded ciphertext ordered by native bytea comparison after
/// hex-decode. `eql_v3_internal.ope_cllw` is a `DOMAIN ... AS bytea`, so it
/// inherits bytea's comparison operators and DEFAULT btree opclass — no custom
/// comparator, no pgcrypto in the compare path, and a functional btree on
/// `eql_v3.ord_term(col)` needs no superuser-only operator class. `_ord`
/// and `_ord_ope` are therefore the twins now (identical terms, two names).
///
/// `_ord_ore` keeps the block-ORE term (`ob`, compared by the custom N-block
/// protocol in `src/v3/sem/ore_block_256/`) and is the by-name escape hatch for
/// callers who need block-ORE specifically.
const ORDERED_INT_DOMAINS: &[Domain] = &[
    Domain {
        name: "",
        terms: &[],
        shape: Shape::Scalar,
    },
    Domain {
        name: "eq",
        terms: &[Term::Hm],
        shape: Shape::Scalar,
    },
    Domain {
        name: "ord_ore",
        terms: &[Term::Ore],
        shape: Shape::Scalar,
    },
    Domain {
        name: "ord",
        terms: &[Term::Ope],
        shape: Shape::Scalar,
    },
    Domain {
        name: "ord_ope",
        terms: &[Term::Ope],
        shape: Shape::Scalar,
    },
];

/// Equality-only domains: storage (no terms) + `_eq` (hm). The canonical shape
/// for a scalar type that can hash for equality but is not ORE-orderable.
/// **Currently unused:** `timestamp` (the previous sole user) was promoted to
/// the ordered shape once `eql_v3.compare_ore_block_256_term` generalized to N
/// blocks and could order its native 12-block ORE width. Retained — and still
/// validated as a known-valid shape by `every_type_uses_a_known_domain_shape` —
/// so a future non-orderable scalar (e.g. a hash-only type) can reuse it without
/// reconstructing the shape.
#[allow(dead_code)]
const EQ_ONLY_DOMAINS: &[Domain] = &[
    Domain {
        name: "",
        terms: &[],
        shape: Shape::Scalar,
    },
    Domain {
        name: "eq",
        terms: &[Term::Hm],
        shape: Shape::Scalar,
    },
];

const INTEGER: DomainFamily = DomainFamily {
    name: "integer",
    domains: ORDERED_INT_DOMAINS,
};

const SMALLINT: DomainFamily = DomainFamily {
    name: "smallint",
    domains: ORDERED_INT_DOMAINS,
};

const BIGINT: DomainFamily = DomainFamily {
    name: "bigint",
    domains: ORDERED_INT_DOMAINS,
};

/// `date` — an ordered, non-integer scalar. Reuses `ORDERED_INT_DOMAINS` (the
/// ordered shape is identical to the integer scalars); only the
/// kind and fixtures (in `DATE_FIXTURES`) differ.
///
/// Public (unlike the integer specs) because the SQLx harness reads
/// `DATE_FIXTURES.values` directly to parse the ISO strings into
/// `chrono::NaiveDate` at runtime — there is no `DATE_VALUES` const (chrono is
/// not `const`-friendly and `eql-domains` stays zero-dep, so no typed slice is
/// materialised here).
pub const DATE: DomainFamily = DomainFamily {
    name: "date",
    domains: ORDERED_INT_DOMAINS,
};

/// `timestamp` — an **ordered**, UTC-normalized non-integer scalar. Uses the
/// ordered shape (storage, `_eq`, `_ord_ore`, `_ord`, `_ord_ope`). `_ord`/
/// `_ord_ope` order by CLLW-OPE (`op`, native bytea compare); `_ord_ore`
/// orders by block-ORE — cipherstash encrypts `Plaintext::Timestamp` at native
/// 12-block ORE width, which the generalized
/// `eql_v3.compare_ore_block_256_term` comparator orders correctly.
/// Values are UTC-normalized (cipherstash has no tz-preserving type) and encrypt
/// under the `timestamp` cast. NOTE: the value is an instant (Postgres `timestamp
/// with time zone`); it wears the SQL-standard name `timestamp` to match the
/// cipherstash cast/`ColumnType`/`Plaintext` convention. A genuinely
/// without-time-zone `timestamp` (naive wall-clock) is a future, additive type,
/// blocked on cipherstash-client ORE pre-indexing for naive datetimes.
///
/// Public (like `DATE`) because the SQLx harness reads
/// `TIMESTAMP_FIXTURES.values` directly to parse the RFC3339 strings into
/// `chrono::DateTime<Utc>` at runtime (no `TIMESTAMP_VALUES` const;
/// `eql-domains` stays zero-dep).
pub const TIMESTAMP: DomainFamily = DomainFamily {
    name: "timestamp",
    domains: ORDERED_INT_DOMAINS,
};

/// `numeric` — an **ordered** non-integer scalar backed by
/// `rust_decimal::Decimal`. Uses the ordered shape. On `_ord_ore`, cipherstash
/// encrypts `Plaintext::Decimal` at native 14-block ORE width, which the
/// generalized `eql_v3.compare_ore_block_256_term` comparator orders correctly;
/// `_ord`/`_ord_ope` order the CLLW-OPE term by native bytea compare.
/// `numeric_value` returns `None` (no i128 range); ordering is supplied by the
/// harness `Decimal: Ord`, which the ordering terms guarantee agrees with the
/// ciphertext order (equivalent scales collide, like `Decimal`'s own `Ord`).
///
/// Public (like `DATE` / `TIMESTAMP`) so the SQLx harness reads
/// `NUMERIC_FIXTURES.values` directly to parse the decimal strings into
/// `rust_decimal::Decimal` at runtime (the catalog stays zero-dep: no
/// `rust_decimal`).
pub const NUMERIC: DomainFamily = DomainFamily {
    name: "numeric",
    domains: ORDERED_INT_DOMAINS,
};

/// Domains for `text`: the ordered shape (with exact `hm` equality on the
/// ordered domains), a `_match` domain (`Bloom` containment), an `_ord_ope`
/// domain (CLLW-OPE ordering), and the combined `_search` / `_search_ore`
/// domains carrying equality + ordering + match in one type.
///
/// **Equality always routes through `hm`.** Every eq-capable text domain leads
/// with `Hm` so `=`/`<>` resolve to `eq_term`/`hm`, never the ORE (`ob`) or
/// OPE (`op`) ordering term — text ordering terms are not equality-lossless.
/// `Term::Ore`/`Term::Ope` keep their kind-agnostic `=`/`<>` claim; they
/// simply never win because `Hm` precedes them (Option 1, catalog ordering).
/// Integer kinds keep `[Ope]`-only `_ord`/`_ord_ope` and `[Ore]`-only
/// `_ord_ore` domains — ordering-term equality is lossless for them.
///
/// **`_ord` is OPE-backed**, matching `ORDERED_INT_DOMAINS`; `_ord_ore` keeps
/// block-ORE. One consequence is visible to callers: encrypting `""` yields an
/// empty ORE term (`ob: []`) but a well-formed OPE term (`op: "00"`, the bare
/// domain-tag byte, which sorts before every non-empty term). So `text_ord`
/// ACCEPTS the empty string and orders it first, while `text_ord_ore` still
/// rejects it at its non-empty-`ob` CHECK (issue #262).
///
/// **`_search` is OPE-backed too**, for the same reason as `_ord`, and
/// `_search_ore` is its by-name block-ORE escape hatch. The operator surface is
/// identical either way (OPE's six operators are already covered via `Ore`), so
/// the swap is not about capability: it is about which btree operator class an
/// ordered functional index binds. `ope_cllw` is a `DOMAIN ... AS bytea` and so
/// inherits `bytea_ops`, the base type's DEFAULT opclass; `ore_block_256` is a
/// composite whose opclass is hand-written and installed by a `DO` block that
/// silently skips on `insufficient_privilege` (the ordinary case on managed
/// Postgres). Absent that opclass, an ordered index over `ord_term_ore` still
/// CREATEs — Postgres binds `record_ops` — and then never engages. `_search`
/// removes that failure mode rather than reporting it.
///
/// The empty-string consequence mirrors `_ord`/`_ord_ore` exactly: `text_search`
/// ACCEPTS `""` and orders it first, while `text_search_ore` still rejects it at
/// its non-empty-`ob` CHECK (issue #262).
const TEXT_DOMAINS: &[Domain] = &[
    Domain {
        name: "",
        terms: &[],
        shape: Shape::Scalar,
    },
    Domain {
        name: "eq",
        terms: &[Term::Hm],
        shape: Shape::Scalar,
    },
    Domain {
        name: "match",
        terms: &[Term::Bloom],
        shape: Shape::Scalar,
    },
    Domain {
        name: "ord_ore",
        terms: &[Term::Hm, Term::Ore],
        shape: Shape::Scalar,
    },
    Domain {
        name: "ord",
        terms: &[Term::Hm, Term::Ope],
        shape: Shape::Scalar,
    },
    Domain {
        name: "ord_ope",
        terms: &[Term::Hm, Term::Ope],
        shape: Shape::Scalar,
    },
    Domain {
        name: "search_ore",
        terms: &[Term::Hm, Term::Ore, Term::Bloom],
        shape: Shape::Scalar,
    },
    Domain {
        name: "search",
        terms: &[Term::Hm, Term::Ope, Term::Bloom],
        shape: Shape::Scalar,
    },
];

/// Storage-only domains: a single term-less domain (name `""`). The canonical
/// shape for an **encryption-only** scalar — encrypted at rest, decrypted by the
/// proxy, never searched server-side. No `_eq`/`_ord`, so no SEM index term and
/// no comparison surface (every operator on the domain is a blocker). Used by
/// `bool`, whose two-value cardinality makes any searchable index a plaintext
/// leak. Validated as a known-valid shape by `every_type_uses_a_known_domain_shape`.
const STORAGE_ONLY_DOMAINS: &[Domain] = &[Domain {
    name: "",
    terms: &[],
    shape: Shape::Scalar,
}];

/// `bool` — an **encryption-only / storage-only** scalar (`ScalarKind::Bool`).
/// One term-less storage domain (`public.eql_v3_boolean`), no `_eq`/`_ord`: a two-value
/// column has too little cardinality for any searchable index without leaking the
/// plaintext, so the value is encrypted at rest and decrypted by the proxy,
/// never searched server-side. Public so the SQLx harness reads
/// `BOOLEAN_FIXTURES.values` directly (there is no `BOOL_VALUES` materializer — the
/// two values are read straight from the record).
pub const BOOLEAN: DomainFamily = DomainFamily {
    name: "boolean",
    domains: STORAGE_ONLY_DOMAINS,
};

/// `text` — an ordered, non-integer, unbounded scalar. Adds a `_match` domain
/// (the `Bloom` term) on top of the ordered shape. Public because the SQLx
/// harness reads `TEXT_VALUES` (materialised in the `fixtures` module).
pub const TEXT: DomainFamily = DomainFamily {
    name: "text",
    domains: TEXT_DOMAINS,
};

/// `real` — an **ordered**, non-integer scalar (Postgres `real`). Reuses the
/// ordered shape (`ORDERED_INT_DOMAINS`); only kind and fixtures
/// differ. Both float widths encrypt through the SAME f64 crypto path
/// (`Plaintext::Float`), so `real` vs `double` is purely a Postgres-surface
/// distinction. Public (like `DATE`/`NUMERIC`) so the SQLx harness reads
/// `REAL_FIXTURES.values` directly to parse the strings into `f32`.
pub const REAL: DomainFamily = DomainFamily {
    name: "real",
    domains: ORDERED_INT_DOMAINS,
};

/// `double` — an **ordered**, non-integer scalar (Postgres `double precision`),
/// the native width of the float crypto path. Reuses the ordered shape. Public
/// so the SQLx harness reads `DOUBLE_FIXTURES.values` directly to parse into
/// `f64`.
pub const DOUBLE: DomainFamily = DomainFamily {
    name: "double",
    domains: ORDERED_INT_DOMAINS,
};

/// The domains of the `json` family — a **mixed** family: three SteVec
/// (encrypted-JSON) domains plus one bare scalar storage domain.
///
/// The three SteVec domains (`search`/`entry`/`query`) all have empty `terms`
/// but ARE searchable: each carries its index terms *structurally*, inside the
/// payload (`hm` for hash-equality, `op` for CLLW-OPE ordering, one per `sv`
/// leaf), not as a flat family-level `Term`. Empty `terms` records "no
/// flat-scalar term surface," never "no index capability"; the capability is
/// described by the `Shape` and enforced by the hand-written SQL CHECKs under
/// `src/v3/json/`. Their SQL surface is hand-written under `src/v3/json/` and
/// their Rust payload structs are hand-written in
/// `crates/eql-bindings/src/v3/json.rs` (fields/serde not catalog-derivable);
/// the catalog drives only their inventory membership + order. The SQL/bindings
/// generators SKIP these SteVec domains (they iterate scalar domains only).
///
/// The fourth, `Shape::Scalar` domain (bare `name: ""`, `public.eql_v3_json`)
/// is a ciphertext-only storage domain and IS generated — by the scalar
/// materializer, exactly like `public.eql_v3_boolean`. It is why the family is
/// "mixed": `families_with_scalar_domains()` renders its scalar domain(s) while
/// `scalar_families()` still excludes the family wholesale (`is_scalar()` is
/// `.all()`), leaving the hand-written SteVec surface untouched. The
/// scalar/SteVec coupling is pinned by `tests::shape_and_terms_are_consistent`.
///
/// Naming: the bare storage domain is `public.eql_v3_json` (bare = storage,
/// like every scalar), and the searchable SteVec **document** carries the
/// `search` suffix (`public.eql_v3_json_search`), mirroring text's `_search`.
const JSON_DOMAINS: &[Domain] = &[
    Domain {
        // The searchable SteVec document: `public.eql_v3_json_search`. The
        // `search` suffix follows the standard family+suffix convention (like
        // text's `_search`); the bare `public.eql_v3_json` name belongs to the
        // storage domain below.
        name: "search",
        terms: &[],
        shape: Shape::SteVec,
    },
    Domain {
        name: "entry",
        terms: &[],
        shape: Shape::SteVec,
    },
    Domain {
        name: "query",
        terms: &[],
        shape: Shape::SteVec,
    },
    // Bare ciphertext-only storage domain `public.eql_v3_json`: a flat `{v,i,c}`
    // envelope with a root ciphertext and NO SEM index terms (encrypt-at-rest,
    // decrypt-in-proxy, never searched server-side) — structurally a scalar, NOT
    // SteVec. `Shape::Scalar` (so `full_name("json")` → `json` →
    // `sql_typname` → `eql_v3_json`, following the uniform prefix convention),
    // generated by the scalar materializer like every other storage-only domain
    // (cf. `public.eql_v3_boolean`). It is APPENDED (index 3) so the SteVec
    // domains keep indices 0-2 that the index-based `spec` tests rely on. The
    // family stays non-scalar (`is_scalar()` is `.all()`), so `scalar_families()`
    // still excludes it and the hand-written SteVec SQL/bindings are untouched;
    // only the new `families_with_scalar_domains()` seam picks up this one domain.
    Domain {
        name: "",
        terms: &[],
        shape: Shape::Scalar,
    },
];

/// `json` — the encrypted-JSON family (a **mixed** family). Three hand-written
/// SteVec domains: `public.eql_v3_json_search` (searchable document),
/// `public.eql_v3_json_entry` (one sv element), `eql_v3.query_json` (containment
/// needle); their Rust struct *bodies* are hand-written
/// (`crates/eql-bindings/src/v3/json.rs`, not derivable from the catalog), while
/// `Domain::rust_struct_name` derives their *identifiers*
/// (`SteVecDocument`/`SteVecEntry`/`SteVecQuery`) from `Domain.name`. Plus one
/// generated `Shape::Scalar` storage domain, `public.eql_v3_json`
/// (ciphertext-only, no index terms), materialized like every other
/// storage-only scalar.
pub const JSON: DomainFamily = DomainFamily {
    name: "json",
    domains: JSON_DOMAINS,
};

/// The domain-family catalog — the single source of truth. Includes both the
/// scalar (flat) families and the mixed `json` family (SteVec domains + a bare
/// scalar storage domain); scalar-only consumers should iterate
/// [`scalar_families`] instead. Order is significant (it drives
/// inventory/generation order). New types are appended as their SQL surface
/// lands.
pub const CATALOG: &[DomainFamily] = &[
    INTEGER, SMALLINT, BIGINT, DATE, TIMESTAMP, NUMERIC, TEXT, BOOLEAN, REAL, DOUBLE, JSON,
];

/// The scalar (flat) families of `CATALOG`, in order — everything except the
/// mixed `json` family (which is non-scalar because it carries SteVec domains).
/// The DRY entry point for the ~9 scalar-only consumers (`list-types`, the
/// scalar matrix) so they never re-inline the `is_scalar()` filter.
pub fn scalar_families() -> impl Iterator<Item = &'static DomainFamily> {
    CATALOG.iter().filter(|f| f.is_scalar())
}

/// The families of `CATALOG` that contain **at least one** scalar (flat) domain,
/// in order. A superset of [`scalar_families`]: it additionally admits *mixed*
/// families (a family that is not wholly scalar but has some scalar domain — the
/// `json` family, whose bare `public.eql_v3_json` storage domain is scalar
/// while its SteVec domains are not). The seam the SQL/bindings materializers
/// iterate: they render each family's scalar domains and skip its non-scalar
/// ones, so a fully-scalar family is handled identically to before, and a mixed
/// family contributes only its scalar surface. Callers pair this with a
/// per-domain `d.is_scalar()` filter.
pub fn families_with_scalar_domains() -> impl Iterator<Item = &'static DomainFamily> {
    CATALOG
        .iter()
        .filter(|f| f.domains.iter().any(|d| d.is_scalar()))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod proptest_invariants;
