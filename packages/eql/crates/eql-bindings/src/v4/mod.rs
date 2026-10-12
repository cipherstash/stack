//! # `eql_v4` domain payload types
//!
//! EQL v4 is the v3 SQL installed under a second name (ADR-0002): `eql_v3`
//! holds terms written by cipherstash-client, `eql_v4` holds terms written by
//! Stack Encrypt. The structs here are generated from the same catalog as
//! [`crate::v3`], with `eql_v4_*` domain names and a `v` of `4`.
//!
//! **Only these structs derive Stack Encrypt's traits** (`EncryptFrom`,
//! `DecryptInto`, behind the `stack-encrypt` feature). Stack Encrypt's output
//! is not byte-for-byte compatible with cipherstash-client's, so no `eql_v3`
//! struct claims it. Which v4 types derive them is
//! `eql-codegen`'s `ENCRYPTION_DOMAINS`; the rest say why in [`targets`].
//!
//! v4 has no SteVec bindings, payload enums, TypeScript export or
//! published JSON Schema yet; those follow in `@cipherstash/eql` 4.0. The
//! term newtypes and the [`DomainType`] trait are shared with v3.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

pub mod bigint;
pub mod boolean;
pub mod date;
pub mod double;
pub mod integer;
pub mod inventory;
/// Generated bindings for the `json` family's bare scalar storage domain
/// (`public.eql_v4_json`, the `Json` struct).
pub mod json;
pub mod numeric;
pub mod real;
pub mod smallint;
/// Generated: the table of EQL types a Stack Encrypt data plan may name as
/// a field target (`TARGETS`) and the by-name dispatch that runs a
/// producible type's own plan. Gated here, in the hand-written module list,
/// rather than inside the generated file. The descriptor type, the errors
/// and the public entry points are hand-written in
/// [`crate::encryption::targets`].
#[cfg(feature = "stack-encrypt")]
pub mod targets;
pub mod text;
pub mod timestamp;

pub use crate::v3::domain_type::{DomainType, SQL_SCHEMA};
pub use crate::v3::terms;
pub use inventory::{all, all_query};

/// The PostgreSQL typname prefix every `public` v4 domain carries.
pub const PUBLIC_TYPNAME_PREFIX: &str = "eql_v4_";

/// Base URL for the canonical `$id` of a v4 domain's JSON Schema.
pub const SCHEMA_ID_BASE: &str = "https://schemas.cipherstash.com/eql/v4/";

/// EQL v4 wire-format version: the `v` every v4 payload carries, and what the
/// `eql_v4_*` domain CHECKs assert.
pub const EQL_SCHEMA_VERSION: u16 = 4;

/// The envelope version field (`v`) of a v4 payload — always exactly
/// [`EQL_SCHEMA_VERSION`] on the wire.
///
/// Deserialization rejects any other value, so a v3 payload fails at the type
/// boundary instead of at INSERT. The inner value is private; the only
/// constructible instance is `4`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, TS)]
pub struct SchemaVersion(#[ts(type = "4")] u16);

impl SchemaVersion {
    /// The v4 wire version, `4`.
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

/// Manual schema: pins `v` to the literal `4`, mirroring the domain CHECK.
impl JsonSchema for SchemaVersion {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "SchemaVersionV4".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "integer",
            "const": EQL_SCHEMA_VERSION,
            "description": "The envelope version field (`v`) of a v4 payload — always exactly `4` on the wire.",
        })
    }
}
