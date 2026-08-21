//! # eql-bindings — canonical EQL payload types
//!
//! One Rust definition per EQL payload shape — the single source of truth
//! for every tool that produces or consumes EQL payloads
//! (`cipherstash-client`, `protect-ffi`, CipherStash Proxy). TypeScript
//! bindings (`ts-rs`) and JSON Schemas (`schemars`) are generated from
//! these definitions — run `cargo test`, see `bindings/v3/` and
//! `schema/v3/`. The Rust types are the contract.
//!
//! ts-rs rule for the generated flat-scalar payload structs (learned from the
//! original spike): ts-rs silently drops a serde attribute it cannot parse, so
//! keep field-level serde attributes out of generated scalar structs — which
//! the flat-scalar wire rule below already demands. The hand-written SteVec
//! `jsonb` structs are the exception: they deliberately use serde `flatten`,
//! `default`, and `skip_serializing_if` because that wire shape is not
//! derivable from the scalar catalog.
//!
//! The [`v3`] module holds the `eql_v3` encrypted-domain types: one struct
//! per SQL domain (`public.eql_v3_integer_eq`, `public.eql_v3_text_match`, …),
//! *capability-encoded* — index terms are required fields, never `Option`.
//! The generated flat-scalar payload structs mirror the scalar subset of
//! `eql-domains::CATALOG` 1:1, enforced by `tests/catalog_parity.rs`; the
//! hand-written SteVec `jsonb` structs are still listed in the generated
//! inventory so the full `v3::all()` surface remains catalog-ordered.
//!
//! Wire rule: **field names ARE wire names** — no `#[serde(rename)]`
//! anywhere. The struct definition reads exactly like the JSON payload.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

pub mod from_v2;
pub mod sql;
pub mod v3;

/// EQL wire-format version. Hard-coded to `3` for every payload in the
/// [`v3`] tier, whose generated domain CHECKs assert `VALUE->>'v' = '3'`.
/// (The legacy `eql_v2` wire stays `v: 2` — see
/// `docs/reference/schema/eql-payload-v2.*.schema.json`.)
pub const EQL_SCHEMA_VERSION: u16 = 3;

/// The envelope version field (`v`) — always exactly [`EQL_SCHEMA_VERSION`]
/// on the wire.
///
/// Deserialization rejects any other value: the Rust analogue of the domain
/// CHECK's `VALUE->>'v' = '3'`, so a wrong-version payload fails at the type
/// boundary instead of at INSERT. The inner value is private; the only
/// constructible instance is the current version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, TS)]
#[ts(export, export_to = "v3/")]
pub struct SchemaVersion(#[ts(type = "3")] u16);

impl SchemaVersion {
    /// The current (only) wire version, `3`.
    pub const CURRENT: Self = Self(EQL_SCHEMA_VERSION);

    /// The wire value.
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl Default for SchemaVersion {
    fn default() -> Self {
        Self::CURRENT
    }
}

impl<'de> Deserialize<'de> for SchemaVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = u16::deserialize(deserializer)?;
        if v == EQL_SCHEMA_VERSION {
            Ok(Self(v))
        } else {
            Err(serde::de::Error::custom(format!(
                "unsupported EQL schema version {v} (expected {EQL_SCHEMA_VERSION})"
            )))
        }
    }
}

/// Manual schema: pins `v` to the literal `3` (`const`), mirroring the
/// domain CHECK — the derive would emit an unconstrained integer.
impl schemars::JsonSchema for SchemaVersion {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "SchemaVersion".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        // KEEP IN SYNC with the `SchemaVersion` doc comment above — it is the
        // canonical text. A derived `JsonSchema` would copy the doc comment
        // automatically; this manual impl can't, so this hand-written copy
        // must be updated alongside it.
        schemars::json_schema!({
            "type": "integer",
            "const": EQL_SCHEMA_VERSION,
            "description": "The envelope version field (`v`) — always exactly `3` on the wire.",
        })
    }
}

/// Table + column identifier — wire shape `{"t": "...", "c": "..."}`.
///
/// Shared by every payload.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, TS, JsonSchema)]
#[ts(export, export_to = "v3/")]
#[serde(deny_unknown_fields)]
pub struct Identifier {
    /// Table name.
    pub t: String,
    /// Column name.
    pub c: String,
}
