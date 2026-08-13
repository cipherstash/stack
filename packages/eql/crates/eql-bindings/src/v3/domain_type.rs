//! The hand-written `DomainType` trait and its `PhantomData` enumeration
//! plumbing — the stable, NON-generated core of the v3 bindings surface. The
//! per-family payload structs and the `inventory.rs` `all()` list are generated
//! from `eql-domains::CATALOG` by `eql-codegen`; this trait, the schema-id base,
//! and the blanket `PhantomData` impl are authored by hand.

use std::marker::PhantomData;

use schemars::{schema_for, JsonSchema, Schema};
use serde::Deserialize;

/// The PostgreSQL schema every user-COLUMN domain in this module inhabits.
/// The `query_<name>` operand twins are NOT column types and live in `eql_v3`
/// instead — dropping the EQL-owned schema can never drop an
/// application column, and a query operand is never an application column.
pub const SQL_SCHEMA: &str = "public";

/// The version prefix every public-schema column domain's typname carries
/// (`eql_v3_integer_eq`, `eql_v3_json_search`, …). Mirrors
/// `eql_domains::PUBLIC_TYPNAME_PREFIX` (a dev-dependency here, so the
/// literal is repeated); parity with the catalog is pinned exhaustively by
/// `tests/catalog_parity.rs`. Query-operand domains (`query_<name>`,
/// `query_json`) are NOT prefixed — the `eql_v3` schema they live in
/// already versions them.
pub const PUBLIC_TYPNAME_PREFIX: &str = "eql_v3_";

/// Base URL for the canonical `$id` of every published v3 JSON Schema.
/// The per-domain `$id` is `{SCHEMA_ID_BASE}{domain}.json` (see
/// [`DomainType::schema_id`]); `tests/export.rs` injects it at write time.
pub const SCHEMA_ID_BASE: &str = "https://schemas.cipherstash.com/eql/v3/";

/// One v3 domain type — implemented by every payload type, so any payload
/// value can report the SQL domain it inhabits (`payload.sql_domain()`).
///
/// Each token file implements this next to the type it describes; the SQL
/// domain string is defined exactly once, in that impl. `all()` is generated
/// from `eql-domains::CATALOG` (`inventory.rs`), so it cannot drift; the
/// published JSON Schema wire contract is pinned by `tests/catalog_parity.rs`.
/// Public so FFI consumers can enumerate the protocol surface too.
pub trait DomainType {
    /// Fully-qualified SQL domain name, e.g. `"public.eql_v3_integer_eq"` — the
    /// per-type fact everything else derives from, defined once in each
    /// type's impl.
    ///
    /// `where Self: Sized` keeps the trait object-safe (the method is
    /// excluded from the vtable); through `dyn DomainType`, use
    /// [`Self::sql_domain`].
    fn sql_domain_static() -> &'static str
    where
        Self: Sized;

    /// Fully-qualified SQL domain name of this payload value.
    fn sql_domain(&self) -> &'static str;

    /// Unqualified SQL domain name (e.g. `"integer_eq"`) — [`Self::sql_domain`]
    /// minus the schema qualifier (`public.` for column domains, `eql_v3.` for
    /// the query-operand twins); matches `eql-domains`
    /// `DomainFamily::domain_name`.
    fn domain(&self) -> &'static str {
        self.sql_domain()
            .split_once('.')
            .expect("sql_domain must be schema-qualified")
            .1
    }

    /// Canonical `$id` for this domain's published JSON Schema —
    /// `{SCHEMA_ID_BASE}{domain}.json`. The single source of truth for the
    /// identity `tests/export.rs` injects; pinned by `tests/catalog_parity.rs`.
    fn schema_id(&self) -> String {
        format!("{SCHEMA_ID_BASE}{}.json", self.domain())
    }

    /// Required term JSON keys of this domain beyond the envelope
    /// (`hm`/`ob`/`bf`/`op`), in catalog (wire) order. `Some(&[])` for a
    /// storage-only scalar; `None` for the SteVec (jsonb) shapes, whose index
    /// terms live per `sv` leaf rather than as flat payload keys. The
    /// generated scalar impls override this from the catalog
    /// (`eql_domains::Term::term_json_keys`, pinned by
    /// `tests/catalog_parity.rs`), which is how [`crate::from_v2`] resolves a
    /// target domain's required keys without a runtime eql-domains dependency.
    ///
    /// `where Self: Sized` keeps the trait object-safe; through
    /// `dyn DomainType`, use [`Self::term_json_keys`].
    fn term_json_keys_static() -> Option<&'static [&'static str]>
    where
        Self: Sized,
    {
        None
    }

    /// Required term JSON keys of this payload value's domain — the
    /// object-safe form of [`Self::term_json_keys_static`].
    fn term_json_keys(&self) -> Option<&'static [&'static str]> {
        None
    }

    /// Strictly parse `value` as this domain's payload: the concrete struct's
    /// serde `Deserialize` (with `deny_unknown_fields` / `SchemaVersion`
    /// enforcement where the struct declares them), reachable through the
    /// trait object. [`crate::from_v2`] uses this for final validation of
    /// converted payloads; the parsed value is discarded — this is a
    /// validation check, not a constructor.
    fn parse_value(&self, value: &serde_json::Value) -> Result<(), serde_json::Error>;

    /// The type's JSON Schema.
    fn schema(&self) -> Schema;
}

/// Type-level handle: lets [`all`] enumerate the domain types without
/// payload values to box — `Box::new(PhantomData::<IntegerEq>)` is zero-sized,
/// and the delegation goes through [`DomainType::sql_domain_static`], so no
/// payload instance is ever constructed.
///
/// [`all`]: super::all
impl<T> DomainType for PhantomData<T>
where
    T: DomainType + JsonSchema + for<'de> Deserialize<'de>,
{
    fn sql_domain_static() -> &'static str {
        T::sql_domain_static()
    }

    fn sql_domain(&self) -> &'static str {
        T::sql_domain_static()
    }

    fn term_json_keys_static() -> Option<&'static [&'static str]> {
        T::term_json_keys_static()
    }

    fn term_json_keys(&self) -> Option<&'static [&'static str]> {
        T::term_json_keys_static()
    }

    fn parse_value(&self, value: &serde_json::Value) -> Result<(), serde_json::Error> {
        T::deserialize(value).map(|_| ())
    }

    fn schema(&self) -> Schema {
        schema_for!(T)
    }
}
