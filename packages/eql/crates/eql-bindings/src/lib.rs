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
//!
//! Enable the `stack-encrypt` feature to encrypt Rust strings into `TextEq`
//! storage values and `TextEqQuery` search values.
#![cfg_attr(
    feature = "stack-encrypt",
    doc = "See the [complete encryption example](encryption#example), including cipher setup, table/column identifiers, and decryption."
)]
#![cfg_attr(
    feature = "stack-encrypt",
    doc = "A binding that names an EQL type as a string reaches the same plans through [`encryption::targets`]: the catalog-generated table of types a data plan may name as a field target, and the by-name `encrypt` / `decrypt` / `query` dispatch."
)]

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

pub mod from_v2;
pub mod sql;
pub mod v3;
// EQL v4 holds the payloads Stack Encrypt writes (ADR-0002). Only Stack
// Encrypt produces a v4 value, so the module exists only with the
// `stack-encrypt` feature, and its types derive Stack Encrypt's traits
// unconditionally. (A `///` doc here would move `v4`'s own intra-doc links
// out of its scope.)
#[cfg(feature = "stack-encrypt")]
pub mod v4;

#[cfg(feature = "stack-encrypt")]
pub mod encryption;

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
//
// The text above is the v3 binding's doc, and `bindings/v3/SchemaVersion.ts`
// carries it verbatim (see `V3_TS_DOCS`). One type serves every generation:
// `V` is the wire version, and `v3::SchemaVersion` / `v4::SchemaVersion` name
// `SchemaVersion<3>` / `SchemaVersion<4>`. Plain `SchemaVersion` defaults to
// v3, the version this crate released it as.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct SchemaVersion<const V: u16 = EQL_SCHEMA_VERSION>(u16);

impl<const V: u16> SchemaVersion<V> {
    /// The only wire version this type admits, `V`.
    pub const CURRENT: Self = Self(V);

    /// The wire value.
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl<const V: u16> Default for SchemaVersion<V> {
    fn default() -> Self {
        Self::CURRENT
    }
}

impl<'de, const V: u16> Deserialize<'de> for SchemaVersion<V> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = u16::deserialize(deserializer)?;
        if v == V {
            Ok(Self(v))
        } else {
            Err(serde::de::Error::custom(format!(
                "unsupported EQL schema version {v} (expected {V})"
            )))
        }
    }
}

/// Manual schema: pins `v` to the literal `V` (`const`), mirroring the
/// domain CHECK — the derive would emit an unconstrained integer.
impl<const V: u16> schemars::JsonSchema for SchemaVersion<V> {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        match V {
            EQL_SCHEMA_VERSION => "SchemaVersion".into(),
            _ => format!("SchemaVersionV{V}").into(),
        }
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        // KEEP IN SYNC with the `SchemaVersion` doc comment above — it is the
        // canonical text. A derived `JsonSchema` would copy the doc comment
        // automatically; this manual impl can't, so this hand-written copy
        // must be updated alongside it.
        schemars::json_schema!({
            "type": "integer",
            "const": V,
            "description": format!("The envelope version field (`v`) — always exactly `{V}` on the wire."),
        })
    }
}

/// The JSDoc block of `bindings/v3/SchemaVersion.ts`: the doc comment on
/// [`SchemaVersion`], as ts-rs's derive would have written it. KEEP IN SYNC.
const V3_TS_DOCS: &str = "/**\n \
 * The envelope version field (`v`) — always exactly [`EQL_SCHEMA_VERSION`]\n \
 * on the wire.\n \
 *\n \
 * Deserialization rejects any other value: the Rust analogue of the domain\n \
 * CHECK's `VALUE->>'v' = '3'`, so a wrong-version payload fails at the type\n \
 * boundary instead of at INSERT. The inner value is private; the only\n \
 * constructible instance is the current version.\n \
 */\n";

/// Manual TypeScript binding: ts-rs's derive has no const generics. Each
/// version is the literal type `V`; only v3's is exported, as
/// `bindings/v3/SchemaVersion.ts` (`export type SchemaVersion = 3;`).
impl<const V: u16> TS for SchemaVersion<V> {
    type WithoutGenerics = Self;
    const DOCS: Option<&'static str> = if V == EQL_SCHEMA_VERSION {
        Some(V3_TS_DOCS)
    } else {
        None
    };

    fn name() -> String {
        match V {
            EQL_SCHEMA_VERSION => "SchemaVersion".into(),
            _ => format!("SchemaVersionV{V}"),
        }
    }

    fn inline() -> String {
        V.to_string()
    }

    fn inline_flattened() -> String {
        panic!("{} cannot be flattened", Self::name())
    }

    fn decl() -> String {
        format!("type {} = {V};", Self::name())
    }

    fn decl_concrete() -> String {
        Self::decl()
    }

    fn output_path() -> Option<&'static std::path::Path> {
        match V {
            EQL_SCHEMA_VERSION => Some(std::path::Path::new("v3/SchemaVersion.ts")),
            _ => None,
        }
    }
}

#[cfg(test)]
#[test]
fn export_bindings_schemaversion() {
    <SchemaVersion as TS>::export_all().expect("could not export type");
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
