//! Reusable wire-field newtypes shared by every v3 domain payload.
//!
//! Each newtype serializes as its inner value (serde's newtype-struct
//! default), so the wire shape is unchanged — but the *name* survives into
//! generated artifacts: ts-rs exports a named TS alias
//! (`export type Hmac256 = string`) that every domain binding imports, and
//! schemars registers a named definition that every domain schema `$ref`s.
//! A plain Rust `type` alias would vanish in both outputs.
//!
//! Names follow the SEM constructor names in `eql-domains` (`Term::ctor()`):
//! a future scheme change (e.g. a 12-block wide ORE term for timestamp
//! ordering) is a new newtype, not a hunt through `Vec<String>` fields.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// mp_base85 source ciphertext — the `c` envelope key.
///
/// Required by every v3 domain CHECK; present on every payload.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, TS, JsonSchema)]
#[ts(export, export_to = "v3/")]
pub struct Ciphertext(pub String);

/// The document key header — the `h` envelope key of a SteVec document.
///
/// mp_base85-encoded key-retrieval material (IV, key tag, descriptor, keyset
/// id), stored **once** per document: every sv entry encrypts under the
/// document's single data key, and entry nonces are derived from the
/// entries' selectors, so nothing per-entry is repeated. Opaque to SQL — it
/// is carried and grafted (`->` merges it onto extracted entries via
/// `eql_v3.meta_data`), never parsed database-side.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, TS, JsonSchema)]
#[ts(export, export_to = "v3/")]
pub struct KeyHeader(pub String);

/// A SteVec entry's ciphertext — the sv-element `c` key: base85 of the raw
/// AEAD output only.
///
/// NOT a self-describing record (contrast [`Ciphertext`]): the key material
/// lives once in the document's `h` ([`KeyHeader`]) and the AEAD nonce is
/// derived from the entry's selector (`hex_decode(s)[..12]`), so the
/// decryption unit is the entry — `h` + `s` + `c`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, TS, JsonSchema)]
#[ts(export, export_to = "v3/")]
pub struct EntryCiphertext(pub String);

/// HMAC-SHA-256 equality term — the `hm` wire key. Backs the `_eq` domains
/// (`=`, `<>`). SQL-side constructor: `eql_v3_internal.hmac_256`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, TS, JsonSchema)]
#[ts(export, export_to = "v3/")]
pub struct Hmac256(pub String);

/// A SteVec selector — the `s` wire key. Addresses a JSON path leaf within an
/// encrypted document (`public.eql_v3_json_search`); present on every entry and query element.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, TS, JsonSchema)]
#[ts(export, export_to = "v3/")]
pub struct Selector(pub String);

/// CLLW-OPE order term — the `op` wire key. Backs the scalar `_ord` (the
/// default ordering domain), `_ord_ope`, and `text_search` domains, their
/// `query_` operands (`=` `<>` `<` `<=` `>` `>=`), and the ordered
/// (number/string) path entries of a SteVec document (the only per-entry
/// term — `hm` is retired; exact matching is the value-inclusive selector):
/// a hex-encoded CLLW OPE ciphertext, sortable via native bytea comparison
/// after hex-decode — unlike `ob` (block-ORE) it needs no custom comparator.
/// Extracted by `eql_v3.ord_term` (scalar domains and the
/// `public.eql_v3_json_entry` overload alike); SQL-side constructor:
/// `eql_v3_internal.ope_cllw`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, TS, JsonSchema)]
#[ts(export, export_to = "v3/")]
pub struct OpeCllw(pub String);

/// Block-ORE order term — the `ob` wire key. Backs the `_ord_ore` domains and
/// `text_search_ore` (`=` `<>` `<` `<=` `>` `>=`); ORE is lossless over the scalar's
/// domain, so it serves equality too. The block count is width-agnostic on the
/// wire (8 for the int scalars, 12 for timestamp, 14 for numeric) — the
/// array just carries more block strings. Extracted by `eql_v3.ord_term_ore`;
/// SQL-side constructor: `eql_v3_internal.ore_block_256`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, TS, JsonSchema)]
#[ts(export, export_to = "v3/")]
pub struct OreBlock256(pub Vec<String>);

/// Bloom-filter match term — the `bf` wire key. Backs the fuzzy-match `@@`
/// (`eql_v3.matches`) surface on the `_match` domains; the containment operators
/// `@>`/`<@` survive only as internal blockers that raise.
///
/// **Signed** i16, not u16: EQL stores the filter as PostgreSQL `smallint[]`,
/// and filters sized above 32768 emit upper-half bit positions as negative
/// signed values.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[ts(export, export_to = "v3/")]
pub struct BloomFilter(pub Vec<i16>);

/// Manual schema: bounds the items to the `smallint` range — the derive
/// emits only `format: "int16"`, a non-validating annotation in draft-07,
/// so an out-of-range bit position would pass schema validation and fail
/// at the database.
impl schemars::JsonSchema for BloomFilter {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "BloomFilter".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        // KEEP IN SYNC with the doc comment on `BloomFilter` above — it is the
        // canonical text. A derived `JsonSchema` would copy the doc comment
        // automatically; this manual impl can't, so this hand-written
        // paraphrase must be updated alongside it.
        schemars::json_schema!({
            "type": "array",
            "items": {
                "type": "integer",
                "format": "int16",
                "minimum": i16::MIN,
                "maximum": i16::MAX,
            },
            "description": "Bloom-filter match term — the `bf` wire key. Backs the fuzzy-match \
                            `@@` (`eql_v3.matches`) surface on the `_match` domains; the \
                            containment operators `@>`/`<@` survive only as internal blockers \
                            that raise. Signed i16: EQL stores the filter \
                            as PostgreSQL `smallint[]`, and filters sized above 32768 emit \
                            upper-half bit positions as negative signed values.",
        })
    }
}

impl From<String> for Ciphertext {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<String> for KeyHeader {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<String> for EntryCiphertext {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<String> for Hmac256 {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<Vec<String>> for OreBlock256 {
    fn from(value: Vec<String>) -> Self {
        Self(value)
    }
}

impl From<Vec<i16>> for BloomFilter {
    fn from(value: Vec<i16>) -> Self {
        Self(value)
    }
}

impl From<String> for Selector {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<String> for OpeCllw {
    fn from(value: String) -> Self {
        Self(value)
    }
}
