//! EQL v3 dual-format support.
//!
//! protect-ffi historically speaks the EQL v2.3 wire format (`{v: 2, k, i, c,
//! …}`). The `eql_v3` schema generation replaces the single
//! `eql_v2_encrypted` column type with per-capability column domains
//! (`public.eql_v3_text_eq`, `public.eql_v3_integer_ord_ore`,
//! `public.eql_v3_json_search`, …), their term-only query twins
//! (`eql_v3.query_text_eq`, `eql_v3.query_json`, …) — unprefixed, since the
//! `eql_v3` schema already versions them —
//! and a new envelope: scalars are `{v: 3, i, c, <terms>}` with no `k`
//! discriminator; SteVec (encrypted JSONB) documents keep it and add one
//! document key header (`{v: 3, k: "sv", i, h, sv}`).
//!
//! Client 0.42 emits both versions natively. Scalar v2 payloads retain a
//! conversion path for compatibility, but v3 SteVec documents must be
//! re-encrypted because their key-header envelope and selector-bound entry
//! ciphertexts have no mechanical v2 conversion. Decryption accepts BOTH
//! stored formats regardless of the client's `eqlVersion`.

use cipherstash_client::eql::{
    EqlCiphertext, EqlCiphertextV3, EqlOutput, EqlOutputV3, EqlQueryPayload, EqlQueryPayloadV3,
    SteVecPayloadV3, SteVecQueryTerm,
};
use cipherstash_client::schema::{
    column::ColumnType, column::IndexType, column::SteVecMode, ColumnConfig,
};
use cipherstash_client::zerokms::{
    self, Decryptable, EncryptedRecord, RecordWithNonce, RetrieveKeyPayload, WithContext,
};
use eql_bindings::from_v2::{from_v2_query_typed, from_v2_typed, is_v3_payload, TargetDomain};
use eql_bindings::v3::domain_type::PUBLIC_TYPNAME_PREFIX;
use eql_bindings::v3::json::SteVecEntry as EqlV3SteVecEntry;
use eql_bindings::v3::terms::Selector;
use eql_bindings::v3::{DomainPayload, QueryPayload};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::convert::Infallible;
use uuid::Uuid;

use crate::Error;

/// An EQL wire version this crate can emit.
///
/// The version arrives as a raw `u8` from JavaScript (`newClient({
/// eqlVersion })`) and is converted exactly once, at the FFI boundary, by
/// [`validate_eql_version`]. Everything downstream carries this enum, so
/// invalid versions are unrepresentable past that point and every
/// version-dependent branch is an exhaustive `match` the compiler checks
/// when a variant is added.
///
/// The discriminants are the on-the-wire `v` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum EqlVersion {
    V2 = 2,
    V3 = 3,
}

impl EqlVersion {
    /// The wire version emitted when `eqlVersion` is omitted — v2, for
    /// backwards compatibility.
    pub(crate) const DEFAULT: Self = Self::V2;
}

impl TryFrom<u8> for EqlVersion {
    type Error = Error;

    fn try_from(version: u8) -> Result<Self, Error> {
        match version {
            v if v == Self::V2 as u8 => Ok(Self::V2),
            v if v == Self::V3 as u8 => Ok(Self::V3),
            other => Err(Error::InvalidEqlVersion(other)),
        }
    }
}

/// Validate the client-supplied `eqlVersion` option at the JS boundary:
/// only `2` and `3` are EQL wire versions this crate can emit. `None`
/// defaults to v2 for backwards compatibility.
pub(crate) fn validate_eql_version(version: Option<u8>) -> Result<EqlVersion, Error> {
    version.map_or(Ok(EqlVersion::DEFAULT), EqlVersion::try_from)
}

/// The v2 index terms a column's configuration will produce on a stored
/// payload: `hm` from `unique`, `ob` from `ore`, `op` from `ope`, `bf` from
/// `match`, and the `sv` entry vector from `ste_vec`.
#[derive(Debug, Clone, Copy, Default)]
struct ConfiguredTerms {
    hm: bool,
    ob: bool,
    op: bool,
    bf: bool,
    sv: bool,
    /// The orderable-term primitive the `ste_vec` index emits, when `sv`.
    /// `Compat` (the config default) emits CLLW-OPE `op`; the legacy
    /// `Standard` emits CLLW-ORE `oc`. Only `op` is convertible to v3 — see
    /// [`target_domain_for_column`].
    sv_mode: Option<SteVecMode>,
}

impl ConfiguredTerms {
    fn from_indexes(column_config: &ColumnConfig) -> Self {
        let mut terms = Self::default();
        for index in &column_config.indexes {
            match index.index_type {
                IndexType::Unique { .. } => terms.hm = true,
                IndexType::Ore => terms.ob = true,
                IndexType::Ope => terms.op = true,
                IndexType::Match { .. } => terms.bf = true,
                IndexType::SteVec { mode, .. } => {
                    terms.sv = true;
                    terms.sv_mode = Some(mode);
                }
            }
        }
        terms
    }

    fn any(&self) -> bool {
        self.hm || self.ob || self.op || self.bf || self.sv
    }
}

/// The v3 domain family for a `cast_as` type. `None` for [`ColumnType::BigUInt`],
/// which no `cast_as` value maps to (fail closed if it ever appears).
fn v3_family(cast_type: ColumnType) -> Option<&'static str> {
    match cast_type {
        ColumnType::Text => Some("text"),
        ColumnType::SmallInt => Some("smallint"),
        ColumnType::Int => Some("integer"),
        ColumnType::BigInt => Some("bigint"),
        ColumnType::Float => Some("double"),
        ColumnType::Decimal => Some("numeric"),
        ColumnType::Date => Some("date"),
        ColumnType::Timestamp => Some("timestamp"),
        ColumnType::Boolean => Some("boolean"),
        ColumnType::Json => Some("json"),
        ColumnType::BigUInt => None,
    }
}

/// Qualify a bare family/suffix name with the version prefix every
/// public-schema column domain's typname carries (`text_eq` →
/// `eql_v3_text_eq`). Query twins stay unprefixed — eql-bindings strips it
/// back off when it derives `query_<name>` from the stored domain.
fn v3_domain(bare: &str) -> String {
    format!("{PUBLIC_TYPNAME_PREFIX}{bare}")
}

fn no_v3_domain(column: &str, reason: impl Into<String>, hint: impl Into<String>) -> Error {
    Error::NoV3Domain {
        column: column.to_string(),
        reason: reason.into(),
        hint: hint.into(),
    }
}

/// Select the `eql_v3` column domain for a column, prefixed (`eql_v3_text_eq`).
///
/// Every v2 index term is optional on the wire, so eql-bindings requires the
/// caller to name the target domain — this derives it from the column
/// configuration. Candidates are tried richest-first (`search_ore` > `search` >
/// `ord_ore` > `ord_ope` > `match` > `eq` > storage-only), and the winner must then cover
/// every configured CAPABILITY or the column errors ([`Error::NoV3Domain`])
/// rather than silently stripping a term from stored rows:
///
/// - equality (`unique`/`hm`) is covered by a domain carrying `hm`, `ob`, or
///   `op` — the ORE/OPE operators include `=`/`<>`, which is why non-text
///   `unique` + `ore` may select `<family>_ord_ore` and drop `hm` without
///   losing anything;
/// - ordering (`ore`/`ob`, `ope`/`op`) is covered by `ob` or `op`, so
///   `unique` + `ore` + `ope` selects `_ord_ore` (ordering survives via
///   `ob`);
/// - match (`bf`) is covered only by a domain carrying `bf`, so text
///   combinations no single domain spans (`unique` + `match`, `ore` + `match`,
///   …) error instead of dropping a term; `unique` + `ore` + `match` reaches
///   `text_search_ore` and `unique` + `ope` + `match` reaches `text_search`;
/// - text ordering domains require `hm` alongside `ob`/`op`, so ordered text
///   without a `unique` index cannot be represented and errors;
/// - a column whose configured terms would ALL be dropped (bool with any
///   index, ordered-only text) errors rather than silently degrading to
///   storage-only.
pub(crate) fn target_domain_for_column(column_config: &ColumnConfig) -> Result<String, Error> {
    let column = column_config.name.as_str();
    let terms = ConfiguredTerms::from_indexes(column_config);
    let family = v3_family(column_config.cast_type).ok_or_else(|| {
        no_v3_domain(
            column,
            format!(
                "cast type {} has no EQL v3 domain family",
                column_config.cast_type
            ),
            "Use eqlVersion 2 for this column.",
        )
    })?;

    if family == "json" {
        // eql_v3_json_search carries only sv. Upstream config accepts
        // unique/ore/ope alongside ste_vec on a JSON column, so selecting the
        // domain anyway would silently drop those terms — fail closed instead.
        if terms.hm || terms.ob || terms.op || terms.bf {
            return Err(no_v3_domain(
                column,
                "eql_v3_json_search carries only ste_vec terms; the other configured \
                 indexes would be silently dropped",
                "Remove the non-ste_vec indexes from this JSON column or use \
                 eqlVersion 2.",
            ));
        }
        if !terms.sv {
            // eql-bindings 3.0.1 defines a storage-only `eql_v3_json` domain
            // for this shape, but protect-ffi does not emit it yet — keep
            // failing closed rather than silently changing behaviour.
            return Err(no_v3_domain(
                column,
                "an index-less JSON column has no searchable EQL v3 domain",
                "Add a 'ste_vec' index or use eqlVersion 2.",
            ));
        }
        // v3 orders SteVec entries by the CLLW-OPE `op` term under native byte
        // comparison. A `Standard`-mode (legacy v2) ste_vec emits
        // CLLW-ORE `oc`, whose ciphertext bytes do not order bytewise —
        // eql-bindings refuses to convert it rather than silently misorder, and
        // no mechanical conversion exists. Catch it here, where the column name
        // and a fix are in hand, instead of at encrypt time.
        return match terms.sv_mode {
            Some(SteVecMode::Compat) => Ok(v3_domain("json_search")),
            _ => Err(no_v3_domain(
                column,
                "eql_v3_json_search orders ste_vec entries by the CLLW-OPE 'op' term, but a \
                 'standard' mode ste_vec index emits CLLW-ORE 'oc' terms, which cannot \
                 be converted",
                "Set the ste_vec index mode to 'compat' (existing rows must be \
                 re-encrypted) or use eqlVersion 2.",
            )),
        };
    }

    if family == "boolean" {
        return if terms.any() {
            Err(no_v3_domain(
                column,
                "eql_v3.boolean is storage-only but indexes are configured",
                "Remove the indexes or use eqlVersion 2.",
            ))
        } else {
            Ok(v3_domain("boolean"))
        };
    }

    // Scalar families, richest capability first. Text ordering domains carry
    // hm + ob/op; the non-text ordering domains carry only ob/op.
    let is_text = family == "text";
    // cipherstash-config rejects `match` on non-text casts and `ste_vec` on
    // non-json casts upstream (into_column_config), but fail closed here too:
    // without these guards a non-text `match` + `ore` column would select
    // `_ord_ore` and silently drop bf (sv falls through to the fail-closed
    // arm at the bottom on its own).
    if !is_text && terms.bf {
        return Err(no_v3_domain(
            column,
            format!("eql_v3.{family} domains cannot carry a match/bloom-filter term"),
            "Remove the 'match' index (match requires a text cast) or use \
             eqlVersion 2.",
        ));
    }
    // The richest candidate domain and the terms it actually carries. The two
    // search domains differ only in their ordering primitive — `_search_ore`
    // carries `ob`, `_search` carries `op` — so ORE is preferred when both are
    // configured, matching the `_ord_ore` over `_ord_ope` preference below.
    let (suffix, carried) = if is_text && terms.hm && terms.ob && terms.bf {
        (
            "_search_ore",
            ConfiguredTerms {
                hm: true,
                ob: true,
                bf: true,
                ..Default::default()
            },
        )
    } else if is_text && terms.hm && terms.op && terms.bf {
        (
            "_search",
            ConfiguredTerms {
                hm: true,
                op: true,
                bf: true,
                ..Default::default()
            },
        )
    } else if terms.ob && (!is_text || terms.hm) {
        (
            "_ord_ore",
            ConfiguredTerms {
                hm: is_text,
                ob: true,
                ..Default::default()
            },
        )
    } else if terms.op && (!is_text || terms.hm) {
        (
            "_ord_ope",
            ConfiguredTerms {
                hm: is_text,
                op: true,
                ..Default::default()
            },
        )
    } else if is_text && terms.bf {
        (
            "_match",
            ConfiguredTerms {
                bf: true,
                ..Default::default()
            },
        )
    } else if terms.hm {
        (
            "_eq",
            ConfiguredTerms {
                hm: true,
                ..Default::default()
            },
        )
    } else if terms.any() {
        // Configured terms exist but none of the family's domains can carry
        // them (ore/ope-only text, ste_vec on a scalar cast, …). Falling back
        // to storage-only would silently drop every configured capability.
        return Err(no_v3_domain(
            column,
            format!("no eql_v3.{family} domain can carry the configured index terms"),
            "Ordered text requires a 'unique' index alongside 'ore'/'ope' \
             (v3 text ordering domains carry hm + ob/op). Adjust the indexes \
             or use eqlVersion 2.",
        ));
    } else {
        return Ok(v3_domain(family));
    };

    // Fail closed if the candidate would DROP a configured capability.
    // Coverage is per capability, not per term: equality survives through
    // the ORE/OPE operators (so `hm` may drop when `ob`/`op` is carried —
    // the documented non-text `unique` + `ore` case), and ordering survives
    // when `op` drops in favour of `ob`. `bf` and `sv` have no substitute.
    let mut dropped = Vec::new();
    if terms.hm && !(carried.hm || carried.ob || carried.op) {
        dropped.push("hm (unique)");
    }
    if (terms.ob || terms.op) && !(carried.ob || carried.op) {
        if terms.ob {
            dropped.push("ob (ore)");
        }
        if terms.op {
            dropped.push("op (ope)");
        }
    }
    if terms.bf && !carried.bf {
        dropped.push("bf (match)");
    }
    if terms.sv {
        // Scalar domains never carry sv (the config layer rejects ste_vec on
        // non-json casts upstream; fail closed here too).
        dropped.push("sv (ste_vec)");
    }
    if !dropped.is_empty() {
        // Only text combinations can reach this today (non-text bf/sv are
        // guarded above and non-text ordering domains cover hm), but keep
        // the check generic so new arms stay fail-closed by default.
        return Err(no_v3_domain(
            column,
            format!(
                "eql_v3.{family}{suffix} is the closest domain but does not \
                 carry the configured {} term(s); stored rows would lose that \
                 capability",
                dropped.join(", ")
            ),
            "No single eql_v3 domain covers this index combination — for \
             text, 'unique' + 'ore' + 'match' reaches text_search_ore and \
             'unique' + 'ope' + 'match' reaches text_search (the richest \
             domains). Adjust the indexes to fit one domain, split \
             the capabilities across separate columns, or use eqlVersion 2.",
        ));
    }
    Ok(v3_domain(&format!("{family}{suffix}")))
}

/// A stored payload in whichever wire format the client is configured for.
///
/// `#[serde(untagged)]` makes the `V2` variant serialize exactly as the bare
/// [`EqlCiphertext`] did before dual-format support (no `Value` round-trip,
/// so v2 output is byte-identical), while `V3` carries the typed
/// [`DomainPayload`] for the column's target domain. `DomainPayload` is
/// itself untagged and Serialize-only, so the v3 wire output carries exactly
/// the keys and values the shape-erased [`eql_bindings::from_v2::from_v2`]
/// `Value` did (pinned by
/// `v3_typed_output_serializes_identically_to_the_from_v2_value`; only the
/// meaningless JSON key order differs — schema wire order instead of a
/// `Value`'s alphabetical order). The v2 payload is boxed because it is
/// substantially larger than the other variant (clippy's
/// `large_enum_variant`).
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub(crate) enum EncryptedOutput {
    V2(Box<EqlCiphertext>),
    V3(DomainPayload),
}

/// Wrap a Store-mode ciphertext in the client's configured wire format:
/// v2 passes through untouched; v3 converts via
/// [`eql_bindings::from_v2::from_v2_typed`] against the domain selected from
/// the column configuration, keeping the strictly parsed [`DomainPayload`].
pub(crate) fn storage_output(
    ciphertext: EqlCiphertext,
    eql_version: EqlVersion,
    column_config: &ColumnConfig,
) -> Result<EncryptedOutput, Error> {
    match eql_version {
        EqlVersion::V2 => Ok(EncryptedOutput::V2(Box::new(ciphertext))),
        EqlVersion::V3 => {
            let target = v3_target_for_column(column_config)?;
            let v2_value = serde_json::to_value(&ciphertext)?;
            Ok(EncryptedOutput::V3(from_v2_typed(&v2_value, target)?))
        }
    }
}

/// Build the V3 stored output **natively** from `encrypt_eql_v3`'s payload —
/// the runtime replacement for [`storage_output`]'s `from_v2` branch (no
/// conversion). The client already emits the v3 envelope, so this only
/// strict-parses it into the column's typed [`DomainPayload`] (the same strict
/// parse `from_v2_typed` did after converting), keyed on the domain selected
/// from the column configuration.
///
/// (`storage_output`'s v2→v3 branch is retained for `eqlVersion 2` clients and
/// as the tested home of the `from_v2` converter, but the v3 runtime path no
/// longer routes through it.)
pub(crate) fn storage_output_v3(
    ciphertext: EqlCiphertextV3,
    column_config: &ColumnConfig,
) -> Result<EncryptedOutput, Error> {
    let domain = target_domain_for_column(column_config)?;
    let value = serde_json::to_value(&ciphertext)?;
    let payload = DomainPayload::parse(&domain, &value)
        .ok_or_else(|| {
            Error::InvariantViolation(format!(
                "selected v3 domain {domain:?} has no DomainPayload variant"
            ))
        })?
        .map_err(|source| Error::V3NativeParse {
            domain: domain.clone(),
            source,
        })?;
    Ok(EncryptedOutput::V3(payload))
}

/// A query payload in whichever wire format the client is configured for.
/// Same untagged pass-through (and boxing) design as [`EncryptedOutput`].
/// `V3` carries the typed [`QueryPayload`] — a term-only scalar operand
/// (`{v, i, <terms>}`, no `c`) for the column domain's `eql_v3.query_<name>`
/// twin, or the `eql_v3.query_json` containment needle. `V3Selector` carries
/// the bare selector hash for `ste_vec_selector` queries — v3 has no
/// encrypted-selector envelope; the SQL `->`/`->>` operators take the
/// [`Selector`] encoding (a string) as `text`. All variants are
/// `#[serde(untagged)]` Serialize-only, so the wire output is exactly the
/// inner value's (keys in schema wire order rather than alphabetical;
/// meaningless for jsonb).
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub(crate) enum QueryOutput {
    V2(Box<EqlOutput>),
    V3(QueryPayload),
    V3Selector(Selector),
    V3SteVecTerm(cipherstash_client::eql::EncryptedQueryPayloadV3),
}

/// Wrap an encrypt-query result in the client's configured wire format.
///
/// Under v3 every Store-mode result — the scalar full envelope produced for
/// Default queries and the SteVec `sv` document produced for containment —
/// converts through the ONE seam [`from_v2_query_typed`], targeting the
/// column's domain: scalars hoist exactly the domain's required terms into
/// the `{v, i, <terms>}` operand (dropping `c`/`k` — the whole point: query
/// operands must never carry a decryptable ciphertext), and ste_vec columns
/// produce the containment needle (stripping the envelope and per-entry
/// ciphertexts, exactly like the SQL cast eql_v3.to_ste_vec_query). The only
/// Query-mode payload with a v3 meaning is the selector, which flattens to
/// its bare selector hash.
pub(crate) fn query_output(
    output: EqlOutput,
    eql_version: EqlVersion,
    column_config: &ColumnConfig,
) -> Result<QueryOutput, Error> {
    match eql_version {
        EqlVersion::V2 => Ok(QueryOutput::V2(Box::new(output))),
        EqlVersion::V3 => match output {
            EqlOutput::Store(ciphertext) => {
                let v2_value = serde_json::to_value(&ciphertext)?;
                Ok(QueryOutput::V3(from_v2_query_typed(
                    &v2_value,
                    v3_target_for_column(column_config)?,
                )?))
            }
            EqlOutput::Query(EqlQueryPayload::SteVec(payload)) => match payload.term {
                SteVecQueryTerm::Selector { selector } => {
                    Ok(QueryOutput::V3Selector(Selector(selector)))
                }
                // QueryMode(SteVecSelector) is the only ste_vec query op
                // to_query_plaintext leaves in Query mode; hm/oc/containment
                // terms arrive via Store mode.
                _ => Err(Error::InvariantViolation(
                    "ste_vec query encryption produced a non-selector term".to_string(),
                )),
            },
            // Under v3, scalar Default queries run Store mode (the operand
            // needs ALL the column domain's terms, not one RootQueryTerm).
            EqlOutput::Query(EqlQueryPayload::Encrypted(_)) => Err(Error::InvariantViolation(
                "scalar query encryption ran in query mode under eqlVersion 3".to_string(),
            )),
        },
    }
}

/// Build the V3 query output **natively** from `encrypt_eql_v3`'s result — the
/// runtime replacement for [`query_output`]'s `from_v2` branch (no conversion).
///
/// Store-mode results (scalar operands + jsonb containment) project through
/// [`EqlCiphertextV3::into_query_operand`] — dropping the record ciphertext `c`
/// (and, for SteVec, the envelope + per-entry `c`/`a`) — then strict-parse into
/// the column's `query_<name>` / `query_json` [`QueryPayload`]. A jsonb path
/// query arrives Query-mode as the bare selector hash. An exact path/value
/// query also arrives in Query mode as a one-entry SteVec containment needle.
pub(crate) fn query_output_v3(
    output: EqlOutputV3,
    column_config: &ColumnConfig,
) -> Result<QueryOutput, Error> {
    match output {
        EqlOutputV3::Store(ciphertext) => {
            let operand = ciphertext.into_query_operand();
            let domain = v3_query_domain_name(column_config)?;
            let value = serde_json::to_value(&operand)?;
            let payload = QueryPayload::parse(&domain, &value)
                .ok_or_else(|| {
                    Error::InvariantViolation(format!(
                        "query domain {domain:?} has no QueryPayload variant"
                    ))
                })?
                .map_err(|source| Error::V3NativeParse {
                    domain: domain.clone(),
                    source,
                })?;
            Ok(QueryOutput::V3(payload))
        }
        EqlOutputV3::Query(EqlQueryPayloadV3::Selector(selector)) => {
            Ok(QueryOutput::V3Selector(Selector(selector)))
        }
        EqlOutputV3::Query(EqlQueryPayloadV3::SteVec(needle)) => {
            let domain = v3_query_domain_name(column_config)?;
            let value = serde_json::to_value(&needle)?;
            let payload = QueryPayload::parse(&domain, &value)
                .ok_or_else(|| {
                    Error::InvariantViolation(format!(
                        "query domain {domain:?} has no QueryPayload variant"
                    ))
                })?
                .map_err(|source| Error::V3NativeParse {
                    domain: domain.clone(),
                    source,
                })?;
            Ok(QueryOutput::V3(payload))
        }
        // Scalar Default queries run Store mode, but an explicit SteVecTerm
        // ordering query is represented by the client as an ordinary one-term
        // `{v, i, op}` operand for comparison with an extracted JSON entry.
        EqlOutputV3::Query(EqlQueryPayloadV3::Encrypted(term)) => {
            Ok(QueryOutput::V3SteVecTerm(term))
        }
    }
}

/// Decode a stored ciphertext value in EITHER wire format into the record +
/// lock context pair zerokms decrypts.
///
/// Probes the v3 envelope FIRST, then falls back to the typed v2
/// [`EqlCiphertext`] parse (the historical shape). The order matters: a v3
/// SteVec document carries both `v: 3` and `k: "sv"`; probing it first also
/// ensures the key-header envelope takes the selector-aware decryption path.
/// [`is_v3_payload`] requires `v == 3` exactly, so no v2 payload can take the
/// v3 branch. Decrypt is
/// deliberately version-agnostic — it must keep working across data
/// migrations regardless of the client's `eqlVersion` setting.
pub(crate) fn encrypted_record_from_value(
    value: serde_json::Value,
    encryption_context: Vec<zerokms::Context>,
) -> Result<WithContext<'static, DecryptableRecord>, Error> {
    if is_v3_payload(&value) {
        return Ok(WithContext {
            record: v3_root_record(&value)?,
            context: Cow::Owned(encryption_context),
        });
    }
    // Not v3 — a parse failure here reports the v2 shape (the shape the
    // overwhelming majority of stored data still has).
    let ciphertext = EqlCiphertext::deserialize(&value).map_err(Error::Parse)?;
    let legacy = crate::encrypted_record_from_mp_base85(ciphertext, encryption_context)?;
    Ok(WithContext {
        record: DecryptableRecord::Standard(legacy.record),
        context: legacy.context,
    })
}

/// A homogeneous decrypt input for mixed v2/scalar and v3 SteVec batches.
///
/// Classic EQL records derive their nonce from the record IV. Client 0.42's
/// SteVec entries derive it from the stored selector and bind that selector
/// into the AEAD AAD, so preserving the variant through ZeroKMS decryption is
/// required for authentication as well as correctness.
#[derive(Debug)]
pub(crate) enum DecryptableRecord {
    Standard(EncryptedRecord),
    SteVec(RecordWithNonce),
}

#[cfg(test)]
impl DecryptableRecord {
    fn encrypted_record(&self) -> &EncryptedRecord {
        match self {
            Self::Standard(record) => record,
            Self::SteVec(record) => &record.record,
        }
    }
}

impl Decryptable for DecryptableRecord {
    type Error = Infallible;

    fn keyset_id(&self) -> Option<Uuid> {
        match self {
            Self::Standard(record) => record.keyset_id(),
            Self::SteVec(record) => record.keyset_id(),
        }
    }

    fn retrieve_key_payload(&self) -> Result<RetrieveKeyPayload<'_>, Self::Error> {
        match self {
            Self::Standard(record) => record.retrieve_key_payload(),
            Self::SteVec(record) => record.retrieve_key_payload(),
        }
    }

    fn into_encrypted_record(self) -> Result<EncryptedRecord, Self::Error> {
        match self {
            Self::Standard(record) => record.into_encrypted_record(),
            Self::SteVec(record) => record.into_encrypted_record(),
        }
    }

    fn nonce_override(&self) -> Option<[u8; 12]> {
        match self {
            Self::Standard(record) => record.nonce_override(),
            Self::SteVec(record) => record.nonce_override(),
        }
    }

    fn aad_selector(&self) -> Option<[u8; 16]> {
        match self {
            Self::Standard(record) => record.aad_selector(),
            Self::SteVec(record) => record.aad_selector(),
        }
    }
}

/// Extract the record ciphertext from a v3 stored payload.
///
/// Scalars keep the mp_base85 record at the top-level `c`; SteVec documents
/// carry raw AEAD output on the FIRST `sv` entry (`sv[0].c`) plus one
/// document key header (`h`). The root selector supplies the entry nonce and
/// AAD, so all three fields must remain paired through decryption.
///
/// The scalar arm reads `c` directly instead of parsing one of the ~40
/// generated domain structs: decrypt receives a bare ciphertext with no
/// column configuration, so the specific domain cannot be known here, and
/// the only field decryption needs is `c` (already shape-checked by
/// [`is_v3_payload`]). The structured SteVec arm goes through the typed
/// [`SteVecPayloadV3`] so the key header and raw entry ciphertext are decoded
/// by cipherstash-client's canonical wire types before we trust `sv[0]`.
fn v3_root_record(value: &serde_json::Value) -> Result<DecryptableRecord, Error> {
    // EQL's `->` operator grafts the document metadata and key header onto the
    // selected entry. Its top-level `c` is raw entry ciphertext, not the
    // self-contained scalar record format, so this arm must precede scalars.
    if value.get("h").is_some() && value.get("s").is_some() {
        let entry = EqlV3SteVecEntry::deserialize(value).map_err(Error::Parse)?;
        let header = entry.h.ok_or_else(|| {
            Error::InvariantViolation("Missing key header in v3 SteVec entry".to_string())
        })?;
        let key_header = zerokms::KeyHeader::from_mp_base85(&header.0)?;
        let ciphertext = base85::decode(&entry.c.0)
            .map_err(zerokms::DecryptError::from)
            .map_err(Error::from)?;
        let selector = decode_ste_vec_selector(&entry.s.0)?;
        return Ok(DecryptableRecord::SteVec(
            key_header.record_with_selector(ciphertext, selector),
        ));
    }
    if let Some(c) = value.get("c").and_then(serde_json::Value::as_str) {
        return EncryptedRecord::from_mp_base85(c)
            .map(DecryptableRecord::Standard)
            .map_err(Error::from);
    }
    let document = SteVecPayloadV3::deserialize(value).map_err(Error::Parse)?;
    let root = document.ste_vec.first().ok_or_else(|| {
        Error::InvariantViolation("Missing root entry in v3 SteVec payload".to_string())
    })?;
    let selector = decode_ste_vec_selector(&root.selector)?;
    Ok(DecryptableRecord::SteVec(
        document
            .key_header
            .record_with_selector(root.ciphertext.clone(), selector),
    ))
}

fn decode_ste_vec_selector(selector: &str) -> Result<[u8; 16], Error> {
    hex::decode(selector)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(Error::InvalidSteVecSelector)
}

/// True when `value` is a stored EQL payload in either wire format.
///
/// v2 is the strict round-trip through [`EqlCiphertext`]; v3 is the lenient
/// envelope probe [`is_v3_payload`] (`{v: 3, i, c|sv}`). Query payloads —
/// including the v3 containment needle `{sv: […]}` — are not stored payloads
/// and return false.
pub(crate) fn is_encrypted_value(value: &serde_json::Value) -> bool {
    EqlCiphertext::deserialize(value).is_ok() || is_v3_payload(value)
}

/// Resolve the column's v3 domain name against the eql-bindings inventory.
///
/// [`target_domain_for_column`] only ever emits inventory names (pinned by a
/// unit test), so a parse failure here is a protect-ffi bug, not user error.
fn v3_target_for_column(column_config: &ColumnConfig) -> Result<TargetDomain, Error> {
    let domain = target_domain_for_column(column_config)?;
    TargetDomain::parse(&domain).map_err(|e| {
        Error::InvariantViolation(format!(
            "selected v3 domain {domain:?} is not in the eql-bindings inventory: {e}"
        ))
    })
}

/// The `query_<name>` operand domain for a column — the query twin of its
/// stored domain ([`target_domain_for_column`]). `eql_v3_json_search` maps to
/// `query_json`; a scalar `eql_v3_<name>` maps to `query_<name>` by stripping
/// the version prefix. Keys [`QueryPayload::parse`] for the native query path.
fn v3_query_domain_name(column_config: &ColumnConfig) -> Result<String, Error> {
    let stored = target_domain_for_column(column_config)?;
    if stored == v3_domain("json_search") {
        return Ok("query_json".to_string());
    }
    let bare = stored.strip_prefix(PUBLIC_TYPNAME_PREFIX).ok_or_else(|| {
        Error::InvariantViolation(format!(
            "stored domain {stored:?} lacks the {PUBLIC_TYPNAME_PREFIX} prefix"
        ))
    })?;
    Ok(format!("query_{bare}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shared payload builders for the conversion tests. These mirror the
    /// real wire shapes cipherstash-client emits (dummy key material, valid
    /// structure) — no mocking of the conversion path itself.
    mod support {
        use cipherstash_client::eql::{
            EncryptedPayload, EqlCiphertext, Identifier as EqlIdentifier, SteVecEntry,
            SteVecEntryTerm, SteVecPayload, EQL_SCHEMA_VERSION,
        };
        use cipherstash_client::schema::column::{ColumnMode, ColumnType, Index};
        use cipherstash_client::schema::ColumnConfig;
        use cipherstash_client::zerokms::{EncryptedRecord, KeyHeader};

        pub(super) fn dummy_encrypted_record() -> EncryptedRecord {
            EncryptedRecord {
                iv: Default::default(),
                ciphertext: vec![1; 16],
                tag: vec![2; 16],
                descriptor: "users/email".to_string(),
                keyset_id: None,
                decryption_policy: None,
            }
        }

        pub(super) fn dummy_key_header() -> KeyHeader {
            let record = dummy_encrypted_record();
            KeyHeader {
                iv: record.iv,
                tag: record.tag,
                descriptor: "users/profile".to_string(),
                keyset_id: record.keyset_id,
                decryption_policy: record.decryption_policy,
            }
        }

        pub(super) fn scalar_payload(
            hm: Option<&str>,
            bf: Option<Vec<u16>>,
            ob: Option<Vec<&str>>,
        ) -> EqlCiphertext {
            EqlCiphertext::Encrypted(EncryptedPayload {
                version: EQL_SCHEMA_VERSION,
                identifier: EqlIdentifier::new("users", "email"),
                ciphertext: dummy_encrypted_record(),
                hmac_256: hm.map(String::from),
                bloom_filter: bf,
                ore_block_u64_8_256: ob
                    .map(|blocks| blocks.into_iter().map(String::from).collect()),
                ope_cllw: None,
            })
        }

        /// A scalar payload carrying only the `op` (CLLW-OPE) term, as
        /// cipherstash-client 0.38.1 emits for an ope-indexed column.
        pub(super) fn ope_scalar_payload(op: &str) -> EqlCiphertext {
            EqlCiphertext::Encrypted(EncryptedPayload {
                version: EQL_SCHEMA_VERSION,
                identifier: EqlIdentifier::new("users", "email"),
                ciphertext: dummy_encrypted_record(),
                hmac_256: None,
                bloom_filter: None,
                ore_block_u64_8_256: None,
                ope_cllw: Some(op.to_string()),
            })
        }

        pub(super) fn ste_vec_payload() -> EqlCiphertext {
            EqlCiphertext::SteVec(SteVecPayload {
                version: EQL_SCHEMA_VERSION,
                identifier: EqlIdentifier::new("users", "profile"),
                ste_vec: vec![
                    SteVecEntry {
                        selector: "root".into(),
                        ciphertext: dummy_encrypted_record(),
                        is_array: None,
                        term: None,
                    },
                    SteVecEntry {
                        selector: "leaf".into(),
                        ciphertext: dummy_encrypted_record(),
                        is_array: Some(true),
                        // CLLW-OPE: the only sv ordering term v3 can carry.
                        term: Some(SteVecEntryTerm::Ope {
                            ope_cllw: "deadbeef".into(),
                        }),
                    },
                ],
            })
        }

        /// The same document with a CLLW-ORE (`oc`) ordering term, as a
        /// `standard`-mode ste_vec index emits. Unconvertible to v3.
        pub(super) fn ore_ste_vec_payload() -> EqlCiphertext {
            EqlCiphertext::SteVec(SteVecPayload {
                version: EQL_SCHEMA_VERSION,
                identifier: EqlIdentifier::new("users", "profile"),
                ste_vec: vec![SteVecEntry {
                    selector: "leaf".into(),
                    ciphertext: dummy_encrypted_record(),
                    is_array: Some(true),
                    term: Some(SteVecEntryTerm::OreCllw {
                        ore_cllw_8: "deadbeef".into(),
                    }),
                }],
            })
        }

        pub(super) fn column(cast_type: ColumnType, indexes: Vec<Index>) -> ColumnConfig {
            ColumnConfig {
                name: "test_column".to_string(),
                cast_type,
                indexes,
                in_place: false,
                mode: ColumnMode::Encrypted,
            }
        }
    }

    mod validate_eql_version {
        use super::*;

        #[test]
        fn discriminants_are_the_wire_versions() {
            // The enum discriminants double as the JS-facing `eqlVersion`
            // values and the on-the-wire `v` — they must never drift.
            assert_eq!(EqlVersion::V2 as u8, 2);
            assert_eq!(EqlVersion::V3 as u8, 3);
        }

        #[test]
        fn defaults_to_v2_when_absent() {
            assert_eq!(validate_eql_version(None).unwrap(), EqlVersion::V2);
        }

        #[test]
        fn accepts_v2() {
            assert_eq!(validate_eql_version(Some(2)).unwrap(), EqlVersion::V2);
        }

        #[test]
        fn accepts_v3() {
            assert_eq!(validate_eql_version(Some(3)).unwrap(), EqlVersion::V3);
        }

        #[test]
        fn rejects_other_versions() {
            for v in [0u8, 1, 4, 255] {
                let err = validate_eql_version(Some(v)).unwrap_err();
                assert!(
                    err.to_string().contains("eqlVersion"),
                    "error should mention eqlVersion: {err}"
                );
            }
        }
    }

    mod target_domain_for_column {
        use super::*;
        use cipherstash_client::schema::column::{ColumnMode, Index, Tokenizer};
        use eql_bindings::from_v2::TargetDomain;

        fn column(cast_type: ColumnType, indexes: Vec<Index>) -> ColumnConfig {
            ColumnConfig {
                name: "test_column".to_string(),
                cast_type,
                indexes,
                in_place: false,
                mode: ColumnMode::Encrypted,
            }
        }

        fn unique() -> Index {
            Index::new(IndexType::Unique {
                token_filters: vec![],
            })
        }

        fn ore() -> Index {
            Index::new(IndexType::Ore)
        }

        fn ope() -> Index {
            Index::new(IndexType::Ope)
        }

        fn match_index() -> Index {
            Index::new(IndexType::Match {
                tokenizer: Tokenizer::Standard,
                token_filters: vec![],
                k: 6,
                m: 2048,
                include_original: false,
            })
        }

        fn ste_vec() -> Index {
            ste_vec_with_mode(SteVecMode::Compat)
        }

        fn ste_vec_with_mode(mode: SteVecMode) -> Index {
            Index::new(IndexType::SteVec {
                prefix: "t/c".to_string(),
                term_filters: vec![],
                array_index_mode: Default::default(),
                mode,
            })
        }

        /// The selected domain with the `eql_v3_` typname prefix stripped, so
        /// the cases below assert the family/suffix SELECTION and nothing
        /// else. That every name carries the prefix is pinned separately by
        /// [`selected_domains_carry_the_public_typname_prefix`], and that the
        /// prefixed names resolve upstream by
        /// [`every_selected_domain_resolves_in_the_v3_inventory`].
        fn domain(cast_type: ColumnType, indexes: Vec<Index>) -> String {
            let selected = target_domain_for_column(&column(cast_type, indexes)).unwrap();
            selected
                .strip_prefix(PUBLIC_TYPNAME_PREFIX)
                .unwrap_or_else(|| {
                    panic!("domain {selected:?} lacks the {PUBLIC_TYPNAME_PREFIX} prefix")
                })
                .to_string()
        }

        fn domain_err(cast_type: ColumnType, indexes: Vec<Index>) -> String {
            target_domain_for_column(&column(cast_type, indexes))
                .unwrap_err()
                .to_string()
        }

        #[test]
        fn text_without_indexes_is_storage_only() {
            assert_eq!(domain(ColumnType::Text, vec![]), "text");
        }

        #[test]
        fn text_unique_is_eq() {
            assert_eq!(domain(ColumnType::Text, vec![unique()]), "text_eq");
        }

        #[test]
        fn text_match_is_match() {
            assert_eq!(domain(ColumnType::Text, vec![match_index()]), "text_match");
        }

        #[test]
        fn text_unique_and_ore_is_ord_ore() {
            assert_eq!(
                domain(ColumnType::Text, vec![unique(), ore()]),
                "text_ord_ore"
            );
        }

        #[test]
        fn text_unique_and_ope_is_ord_ope() {
            assert_eq!(
                domain(ColumnType::Text, vec![unique(), ope()]),
                "text_ord_ope"
            );
        }

        #[test]
        fn text_unique_ore_match_is_search_ore() {
            // The ORE search domain is the `_ore`-suffixed one; the bare
            // `text_search` carries the OPE `op` term instead.
            assert_eq!(
                domain(ColumnType::Text, vec![unique(), ore(), match_index()]),
                "text_search_ore"
            );
        }

        #[test]
        fn text_unique_ope_match_is_search() {
            assert_eq!(
                domain(ColumnType::Text, vec![unique(), ope(), match_index()]),
                "text_search"
            );
        }

        #[test]
        fn text_unique_ore_ope_match_prefers_search_ore() {
            // Both ordering terms configured: ORE wins, mirroring the
            // `_ord_ore` over `_ord_ope` preference. Dropping `op` is allowed
            // because the ordering capability survives through `ob`.
            assert_eq!(
                domain(
                    ColumnType::Text,
                    vec![unique(), ore(), ope(), match_index()]
                ),
                "text_search_ore"
            );
        }

        #[test]
        fn text_unique_ore_and_ope_is_ord_ore() {
            // text_ord_ore carries hm + ob. The op term is dropped, but the
            // ordering capability survives through ob, so this is an allowed
            // drop (mirrors the non-text ore-over-ope preference).
            assert_eq!(
                domain(ColumnType::Text, vec![unique(), ore(), ope()]),
                "text_ord_ore"
            );
        }

        #[test]
        fn text_unique_and_match_is_an_error() {
            // The closest domain, text_match, carries only bf — selecting it
            // would permanently strip the configured hm term from stored
            // rows. Fail closed instead of silently dropping equality.
            let err = domain_err(ColumnType::Text, vec![unique(), match_index()]);
            assert!(err.contains("test_column"), "names the column: {err}");
            assert!(err.contains("hm"), "names the dropped term: {err}");
            assert!(err.contains("eqlVersion 2"), "offers a way out: {err}");
        }

        #[test]
        fn text_ore_and_match_without_unique_is_an_error() {
            // text_match carries only bf; the configured ordering capability
            // (ob) would be silently dropped.
            let err = domain_err(ColumnType::Text, vec![match_index(), ore()]);
            assert!(err.contains("test_column"), "names the column: {err}");
            assert!(err.contains("ob"), "names the dropped term: {err}");
        }

        #[test]
        fn text_ore_without_unique_is_an_error() {
            // eql_v3.text_ord_ore requires hm + ob; an ore-only text column
            // yields no hm, and falling back to storage-only would silently
            // drop the configured ordering capability.
            let err = domain_err(ColumnType::Text, vec![ore()]);
            assert!(err.contains("test_column"), "names the column: {err}");
            assert!(err.contains("unique"), "hints at adding unique: {err}");
        }

        #[test]
        fn text_ope_without_unique_is_an_error() {
            let err = domain_err(ColumnType::Text, vec![ope()]);
            assert!(err.contains("unique"), "hints at adding unique: {err}");
        }

        #[test]
        fn int_without_indexes_is_storage_only() {
            assert_eq!(domain(ColumnType::Int, vec![]), "integer");
        }

        #[test]
        fn int_unique_is_eq() {
            assert_eq!(domain(ColumnType::Int, vec![unique()]), "integer_eq");
        }

        #[test]
        fn int_ore_is_ord_ore() {
            assert_eq!(domain(ColumnType::Int, vec![ore()]), "integer_ord_ore");
        }

        #[test]
        fn int_ope_is_ord_ope() {
            assert_eq!(domain(ColumnType::Int, vec![ope()]), "integer_ord_ope");
        }

        #[test]
        fn int_unique_and_ore_prefers_ord_ore_over_eq() {
            // integer_ord_ore requires only ob; hm is dropped but equality
            // remains available via the ORE operators (= <>).
            assert_eq!(
                domain(ColumnType::Int, vec![unique(), ore()]),
                "integer_ord_ore"
            );
        }

        #[test]
        fn int_unique_and_ope_prefers_ord_ope_over_eq() {
            assert_eq!(
                domain(ColumnType::Int, vec![unique(), ope()]),
                "integer_ord_ope"
            );
        }

        #[test]
        fn int_ore_and_ope_prefers_ord_ore() {
            assert_eq!(
                domain(ColumnType::Int, vec![ore(), ope()]),
                "integer_ord_ore"
            );
        }

        #[test]
        fn small_int_maps_to_smallint_family() {
            assert_eq!(
                domain(ColumnType::SmallInt, vec![ore()]),
                "smallint_ord_ore"
            );
        }

        #[test]
        fn big_int_maps_to_bigint_family() {
            assert_eq!(domain(ColumnType::BigInt, vec![unique()]), "bigint_eq");
        }

        #[test]
        fn big_int_without_indexes_is_storage_only() {
            assert_eq!(domain(ColumnType::BigInt, vec![]), "bigint");
        }

        #[test]
        fn big_int_ore_is_ord_ore() {
            assert_eq!(domain(ColumnType::BigInt, vec![ore()]), "bigint_ord_ore");
        }

        #[test]
        fn big_int_unique_and_ore_prefers_ord_ore_over_eq() {
            // Same non-text rule as integer: bigint_ord_ore carries only ob;
            // hm drops but equality survives via the ORE operators.
            assert_eq!(
                domain(ColumnType::BigInt, vec![unique(), ore()]),
                "bigint_ord_ore"
            );
        }

        #[test]
        fn big_int_ope_is_ord_ope() {
            assert_eq!(domain(ColumnType::BigInt, vec![ope()]), "bigint_ord_ope");
        }

        #[test]
        fn float_maps_to_double_family() {
            assert_eq!(domain(ColumnType::Float, vec![ore()]), "double_ord_ore");
        }

        #[test]
        fn decimal_maps_to_numeric_family() {
            assert_eq!(domain(ColumnType::Decimal, vec![ore()]), "numeric_ord_ore");
        }

        #[test]
        fn date_maps_to_date_family() {
            assert_eq!(domain(ColumnType::Date, vec![ore()]), "date_ord_ore");
        }

        #[test]
        fn timestamp_maps_to_timestamp_family() {
            assert_eq!(
                domain(ColumnType::Timestamp, vec![unique()]),
                "timestamp_eq"
            );
        }

        #[test]
        fn boolean_without_indexes_is_storage_only() {
            assert_eq!(domain(ColumnType::Boolean, vec![]), "boolean");
        }

        #[test]
        fn boolean_with_unique_is_an_error() {
            // eql_v3.boolean is storage-only; any index term would be dropped.
            let err = domain_err(ColumnType::Boolean, vec![unique()]);
            assert!(err.contains("test_column"), "names the column: {err}");
            assert!(err.contains("storage-only"), "explains bool: {err}");
        }

        #[test]
        fn boolean_with_ore_is_an_error() {
            let err = domain_err(ColumnType::Boolean, vec![ore()]);
            assert!(err.contains("storage-only"), "explains bool: {err}");
        }

        #[test]
        fn json_with_compat_mode_ste_vec_is_json_search() {
            assert_eq!(domain(ColumnType::Json, vec![ste_vec()]), "json_search");
        }

        #[test]
        fn json_with_standard_mode_ste_vec_is_an_error() {
            // `standard` (the legacy v2 mode) emits CLLW-ORE `oc`
            // sv terms. v3 orders sv entries by the CLLW-OPE `op` term under
            // native byte comparison, and ORE ciphertext bytes do not order
            // that way — converting would silently misorder every entry, so
            // eql-bindings refuses. Fail at config time, not encrypt time.
            let err = domain_err(
                ColumnType::Json,
                vec![ste_vec_with_mode(SteVecMode::Standard)],
            );
            assert!(err.contains("test_column"), "names the column: {err}");
            assert!(err.contains("compat"), "names the fix: {err}");
        }

        #[test]
        fn ste_vec_mode_default_is_compat_so_json_v3_works_unconfigured() {
            // cipherstash-config 0.40.0 flipped this default from `standard`
            // (CLLW-ORE) to `compat` (CLLW-OPE) — the mode v3 requires. A
            // JSON column that names no mode therefore converts. If the
            // default ever flips back, the guard above turns v3 JSON into a
            // config error, so pin it here rather than discover it downstream.
            assert_eq!(SteVecMode::default(), SteVecMode::Compat);
            assert_eq!(
                domain(
                    ColumnType::Json,
                    vec![ste_vec_with_mode(Default::default())]
                ),
                "json_search"
            );
        }

        #[test]
        fn json_without_ste_vec_is_an_error() {
            // v2 stores index-less JSON as an opaque scalar (k: "ct"); v3
            // has no scalar jsonb domain to hold it.
            let err = domain_err(ColumnType::Json, vec![]);
            assert!(err.contains("ste_vec"), "hints at ste_vec: {err}");
        }

        #[test]
        fn json_with_ste_vec_and_unique_is_an_error() {
            // Upstream config accepts unique/ore/ope alongside ste_vec on a
            // JSON column; eql_v3_json_search carries only sv, so selecting it
            // would silently drop the other configured terms. Fail closed.
            let err = domain_err(ColumnType::Json, vec![ste_vec(), unique()]);
            assert!(
                err.contains("ste_vec"),
                "explains the sv-only domain: {err}"
            );
        }

        #[test]
        fn ste_vec_on_a_non_json_cast_is_an_error() {
            // The config layer rejects this before it reaches us; fail
            // closed anyway rather than silently dropping sv.
            let err = domain_err(ColumnType::Int, vec![ste_vec()]);
            assert!(err.contains("test_column"), "names the column: {err}");
        }

        #[test]
        fn match_mixed_with_ore_on_non_text_is_an_error() {
            // Without this guard the _ord_ore arm would match first and
            // silently drop bf (the config layer rejects match on non-text
            // upstream; fail closed anyway).
            let err = domain_err(ColumnType::Int, vec![ore(), match_index()]);
            assert!(err.contains("test_column"), "names the column: {err}");
        }

        #[test]
        fn match_on_non_text_is_an_error() {
            // The config layer rejects this before it reaches us; fail
            // closed anyway rather than silently dropping bf.
            let err = domain_err(ColumnType::Int, vec![match_index()]);
            assert!(err.contains("test_column"), "names the column: {err}");
        }

        #[test]
        fn every_selected_domain_resolves_in_the_v3_inventory() {
            // The names this function emits must always parse against the
            // catalog-generated inventory — a typo here would only surface
            // at encrypt time otherwise.
            let cases: Vec<(ColumnType, Vec<Index>)> = vec![
                (ColumnType::Text, vec![]),
                (ColumnType::Text, vec![unique()]),
                (ColumnType::Text, vec![match_index()]),
                (ColumnType::Text, vec![unique(), ore()]),
                (ColumnType::Text, vec![unique(), ope()]),
                (ColumnType::Text, vec![unique(), ore(), match_index()]),
                (ColumnType::SmallInt, vec![]),
                (ColumnType::SmallInt, vec![unique()]),
                (ColumnType::SmallInt, vec![ore()]),
                (ColumnType::SmallInt, vec![ope()]),
                (ColumnType::Int, vec![ore()]),
                (ColumnType::BigInt, vec![]),
                (ColumnType::BigInt, vec![unique()]),
                (ColumnType::BigInt, vec![ore()]),
                (ColumnType::BigInt, vec![ope()]),
                (ColumnType::Float, vec![ore()]),
                (ColumnType::Decimal, vec![ore()]),
                (ColumnType::Date, vec![ore()]),
                (ColumnType::Timestamp, vec![ore()]),
                (ColumnType::Boolean, vec![]),
                (ColumnType::Json, vec![ste_vec()]),
            ];
            for (cast_type, indexes) in cases {
                // The prefixed name as emitted, NOT the stripped `domain()`
                // helper: it is the qualified typname that must resolve.
                let name = target_domain_for_column(&column(cast_type, indexes)).unwrap();
                assert!(
                    TargetDomain::parse(&name).is_ok(),
                    "domain {name:?} must resolve in the eql-bindings inventory"
                );
            }
        }

        #[test]
        fn selected_domains_carry_the_public_typname_prefix() {
            // Every public-schema column domain is versioned (`eql_v3_text_eq`,
            // `eql_v3_json_search`); the query twins eql-bindings derives from
            // them are not. Storage-only, suffixed and json domains all take it.
            for (cast_type, indexes, expected) in [
                (ColumnType::Text, vec![], "eql_v3_text"),
                (ColumnType::Text, vec![unique()], "eql_v3_text_eq"),
                (ColumnType::Boolean, vec![], "eql_v3_boolean"),
                (ColumnType::Json, vec![ste_vec()], "eql_v3_json_search"),
            ] {
                assert_eq!(
                    target_domain_for_column(&column(cast_type, indexes)).unwrap(),
                    expected
                );
            }
        }
    }

    mod storage_output {
        use super::support::{
            column, ope_scalar_payload, ore_ste_vec_payload, scalar_payload, ste_vec_payload,
        };
        use super::*;
        use cipherstash_client::schema::column::{Index, IndexType, Tokenizer};

        fn text_search_column() -> ColumnConfig {
            column(
                ColumnType::Text,
                vec![
                    Index::new(IndexType::Unique {
                        token_filters: vec![],
                    }),
                    Index::new(IndexType::Ore),
                    Index::new(IndexType::Match {
                        tokenizer: Tokenizer::Standard,
                        token_filters: vec![],
                        k: 6,
                        m: 2048,
                        include_original: false,
                    }),
                ],
            )
        }

        /// A native v3 scalar payload (as `encrypt_eql_v3` emits it) carrying
        /// the same terms as `scalar_payload(Some("aa"), Some([1, 2]),
        /// Some(["bb"]))`. Bloom positions are small and positive, so the signed
        /// `smallint[]` v3 form equals the v2 unsigned form.
        fn native_text_search_scalar() -> cipherstash_client::eql::EqlCiphertextV3 {
            use cipherstash_client::eql::{
                EncryptedPayloadV3, EqlCiphertextV3, Identifier as EqlIdentifier,
                EQL_SCHEMA_VERSION_V3,
            };
            EqlCiphertextV3::Encrypted(EncryptedPayloadV3 {
                version: EQL_SCHEMA_VERSION_V3,
                identifier: EqlIdentifier::new("users", "email"),
                ciphertext: super::support::dummy_encrypted_record(),
                hmac_256: Some("aa".into()),
                bloom_filter: Some(vec![1, 2]),
                ore_block_u64_8_256: Some(vec!["bb".into()]),
                ope_cllw: None,
            })
        }

        #[test]
        fn v3_native_output_matches_the_from_v2_conversion() {
            // The native emit path (storage_output_v3) and the from_v2 path
            // (storage_output V3 branch) must produce the identical typed
            // DomainPayload for the same terms — so retiring from_v2 from the
            // runtime is behaviour-preserving.
            let cfg = text_search_column();
            let native = storage_output_v3(native_text_search_scalar(), &cfg).unwrap();
            let converted = storage_output(
                scalar_payload(Some("aa"), Some(vec![1, 2]), Some(vec!["bb"])),
                EqlVersion::V3,
                &cfg,
            )
            .unwrap();
            assert_eq!(
                serde_json::to_value(&native).unwrap(),
                serde_json::to_value(&converted).unwrap(),
            );
        }

        #[test]
        fn v3_native_output_has_the_v3_scalar_shape() {
            let output =
                storage_output_v3(native_text_search_scalar(), &text_search_column()).unwrap();
            let v = serde_json::to_value(&output).unwrap();
            assert_eq!(v["v"], 3);
            assert!(v.get("k").is_none(), "v3 scalar payloads carry no `k`");
            assert_eq!(v["hm"], "aa");
            assert!(v.get("c").is_some());
        }

        fn json_column() -> ColumnConfig {
            column(
                ColumnType::Json,
                vec![Index::new(IndexType::SteVec {
                    prefix: "users/profile".to_string(),
                    term_filters: vec![],
                    array_index_mode: Default::default(),
                    mode: SteVecMode::Compat,
                })],
            )
        }

        /// A native v3 SteVec document (as `encrypt_eql_v3` emits it) carrying
        /// the same entries as `support::ste_vec_payload()`: root/`hm` and an
        /// array-marked leaf/`op`.
        fn native_ste_vec_document() -> cipherstash_client::eql::EqlCiphertextV3 {
            use cipherstash_client::eql::{
                EqlCiphertextV3, Identifier as EqlIdentifier, SteVecEntryTermV3, SteVecEntryV3,
                SteVecKind, SteVecPayloadV3, EQL_SCHEMA_VERSION_V3,
            };
            EqlCiphertextV3::SteVec(SteVecPayloadV3 {
                version: EQL_SCHEMA_VERSION_V3,
                kind: SteVecKind::SteVec,
                identifier: EqlIdentifier::new("users", "profile"),
                key_header: super::support::dummy_key_header(),
                ste_vec: vec![
                    SteVecEntryV3 {
                        selector: "root".into(),
                        ciphertext: vec![1; 16],
                        is_array: None,
                        term: None,
                    },
                    SteVecEntryV3 {
                        selector: "leaf".into(),
                        ciphertext: vec![2; 16],
                        is_array: Some(true),
                        term: Some(SteVecEntryTermV3::Ope {
                            ope_cllw: "deadbeef".into(),
                        }),
                    },
                ],
            })
        }

        #[test]
        fn v2_ste_vec_document_cannot_be_converted_to_v3() {
            // The v3 key-header envelope and selector-derived entry nonces
            // have no v2 representation. Legacy v2 documents must be
            // decrypted and re-encrypted rather than mechanically converted.
            let cfg = json_column();
            assert!(storage_output(ste_vec_payload(), EqlVersion::V3, &cfg).is_err());
        }

        #[test]
        fn v3_native_ste_vec_output_keeps_the_sv_envelope() {
            // Stored SteVec documents (unlike containment needles) keep the
            // full envelope and per-entry ciphertext/array marker.
            let output = storage_output_v3(native_ste_vec_document(), &json_column()).unwrap();
            let v = serde_json::to_value(&output).unwrap();
            assert_eq!(v["v"], 3);
            assert_eq!(v["k"], "sv", "the document keeps the sv discriminator");
            assert_eq!(v["i"]["t"], "users");
            let sv = v["sv"].as_array().unwrap();
            assert_eq!(sv.len(), 2);
            assert!(v.get("h").is_some(), "the document carries one key header");
            assert!(sv[0].get("c").is_some(), "entries keep their ciphertext");
            assert!(sv[0].get("hm").is_none(), "exact match uses selectors");
            assert_eq!(sv[1]["a"], true, "the array marker is preserved");
            assert_eq!(sv[1]["op"], "deadbeef");
        }

        #[test]
        fn v3_native_parse_failure_is_a_conversion_error() {
            use cipherstash_client::eql::{
                EncryptedPayloadV3, EqlCiphertextV3, Identifier as EqlIdentifier,
                EQL_SCHEMA_VERSION_V3,
            };
            // A payload missing the selected domain's required terms (hm only,
            // but text_search_ore requires hm + ob + bf) must surface as the
            // "EQL v3 conversion failed" error the from_v2 path produced, so
            // the EQL_V3_CONVERSION_FAILED error-code contract holds on the
            // native path too.
            let incomplete = EqlCiphertextV3::Encrypted(EncryptedPayloadV3 {
                version: EQL_SCHEMA_VERSION_V3,
                identifier: EqlIdentifier::new("users", "email"),
                ciphertext: super::support::dummy_encrypted_record(),
                hmac_256: Some("aa".into()),
                bloom_filter: None,
                ore_block_u64_8_256: None,
                ope_cllw: None,
            });
            let err = storage_output_v3(incomplete, &text_search_column())
                .unwrap_err()
                .to_string();
            assert!(
                err.starts_with("EQL v3 conversion failed"),
                "native parse failures must keep the conversion-failed error contract: {err}"
            );
            assert!(
                err.contains("eql_v3_text_search_ore"),
                "the error should name the target domain: {err}"
            );
        }

        #[test]
        fn v2_output_serializes_identically_to_the_bare_ciphertext() {
            let ciphertext = scalar_payload(Some("aa"), Some(vec![1, 2]), Some(vec!["bb"]));
            let expected = serde_json::to_string(&ciphertext).unwrap();

            let output = storage_output(
                scalar_payload(Some("aa"), Some(vec![1, 2]), Some(vec!["bb"])),
                EqlVersion::V2,
                &text_search_column(),
            )
            .unwrap();

            assert_eq!(serde_json::to_string(&output).unwrap(), expected);
        }

        #[test]
        fn v3_typed_output_serializes_identically_to_the_from_v2_value() {
            // EncryptedOutput::V3 carries the typed DomainPayload
            // (from_v2_typed) instead of the shape-erased Value (from_v2).
            // Both are #[serde(untagged)], so the FFI wire output must carry
            // exactly the from_v2 keys and values for scalar domains. SteVec
            // documents are intentionally excluded: v3's key-header envelope
            // cannot be derived from a v2 document. (JSON object key ORDER is the
            // one permitted difference: a Value serializes keys
            // alphabetically, the typed structs in schema wire order
            // `v, i, c, <terms>`. Key order carries no meaning in JSON and
            // none of this crate's consumers observe it.)
            use eql_bindings::from_v2::from_v2;

            let scalar_cfg = text_search_column();
            let scalar_ct = scalar_payload(Some("aa"), Some(vec![1, 2]), Some(vec!["bb"]));
            let scalar_v2 = serde_json::to_value(&scalar_ct).unwrap();
            // Derived, not spelled: the point is that the typed and
            // shape-erased conversions agree on the SAME domain.
            let scalar_target =
                TargetDomain::parse(&target_domain_for_column(&scalar_cfg).unwrap()).unwrap();

            let output = storage_output(scalar_ct, EqlVersion::V3, &scalar_cfg).unwrap();
            assert_eq!(
                serde_json::to_value(&output).unwrap(),
                from_v2(&scalar_v2, scalar_target).unwrap(),
            );
        }

        #[test]
        fn v3_scalar_output_has_v3_envelope_and_required_terms() {
            let output = storage_output(
                scalar_payload(Some("aa"), Some(vec![1, 2]), Some(vec!["bb"])),
                EqlVersion::V3,
                &text_search_column(),
            )
            .unwrap();

            let value = serde_json::to_value(&output).unwrap();
            assert_eq!(value["v"], 3);
            assert!(value.get("k").is_none(), "v3 scalar envelope carries no k");
            assert_eq!(value["i"]["t"], "users");
            assert_eq!(value["i"]["c"], "email");
            assert!(value["c"].is_string(), "ciphertext is copied verbatim");
            assert_eq!(value["hm"], "aa");
            assert_eq!(value["ob"], serde_json::json!(["bb"]));
            assert_eq!(value["bf"], serde_json::json!([1, 2]));
        }

        #[test]
        fn v3_output_drops_terms_the_target_domain_does_not_carry() {
            // unique + ore on int maps to integer_ord_ore, which carries only
            // ob — hm is dropped (equality stays available via ORE).
            let cfg = column(
                ColumnType::Int,
                vec![
                    Index::new(IndexType::Unique {
                        token_filters: vec![],
                    }),
                    Index::new(IndexType::Ore),
                ],
            );
            let output = storage_output(
                scalar_payload(Some("aa"), None, Some(vec!["bb"])),
                EqlVersion::V3,
                &cfg,
            )
            .unwrap();

            let value = serde_json::to_value(&output).unwrap();
            assert_eq!(value["ob"], serde_json::json!(["bb"]));
            assert!(value.get("hm").is_none(), "hm dropped for integer_ord_ore");
        }

        #[test]
        fn v3_bigint_eq_output_carries_hm_only() {
            // A unique-indexed bigint column maps to public.bigint_eq:
            // v, i, c, hm and nothing else (the domain CHECKs in the
            // vendored eql-bindings schemas — EQL release
            // eql-3.0.0-alpha.3 — require exactly the family terms
            // alongside v/i/c).
            let cfg = column(
                ColumnType::BigInt,
                vec![Index::new(IndexType::Unique {
                    token_filters: vec![],
                })],
            );
            let output =
                storage_output(scalar_payload(Some("aa"), None, None), EqlVersion::V3, &cfg)
                    .unwrap();

            let value = serde_json::to_value(&output).unwrap();
            assert_eq!(value["v"], 3);
            assert_eq!(value["hm"], "aa");
            let mut keys: Vec<_> = value.as_object().unwrap().keys().collect();
            keys.sort();
            assert_eq!(keys, ["c", "hm", "i", "v"]);
        }

        #[test]
        fn v3_bigint_ord_ore_output_carries_ob_and_no_hm() {
            // An ore-indexed bigint column maps to eql_v3.bigint_ord_ore:
            // ob is the ordering term; hm must NOT appear (non-text
            // ordering domains carry no hm).
            let cfg = column(ColumnType::BigInt, vec![Index::new(IndexType::Ore)]);
            let output = storage_output(
                scalar_payload(None, None, Some(vec!["bb"])),
                EqlVersion::V3,
                &cfg,
            )
            .unwrap();

            let value = serde_json::to_value(&output).unwrap();
            assert_eq!(value["ob"], serde_json::json!(["bb"]));
            assert!(value.get("hm").is_none(), "no hm on bigint_ord_ore");
            let mut keys: Vec<_> = value.as_object().unwrap().keys().collect();
            keys.sort();
            assert_eq!(keys, ["c", "i", "ob", "v"]);
        }

        #[test]
        fn v3_ope_term_flows_through_to_the_ord_ope_domain() {
            // cipherstash-client 0.38.1 emits the scalar `op` (CLLW-OPE)
            // term, so an ope-indexed column can reach its
            // _ord_ope domain: v, i, c, op and nothing else.
            let cfg = column(ColumnType::Int, vec![Index::new(IndexType::Ope)]);
            let output = storage_output(ope_scalar_payload("cc"), EqlVersion::V3, &cfg).unwrap();

            let value = serde_json::to_value(&output).unwrap();
            assert_eq!(value["v"], 3);
            assert!(value["c"].is_string(), "ciphertext is copied verbatim");
            assert_eq!(value["op"], "cc");
            let mut keys: Vec<_> = value.as_object().unwrap().keys().collect();
            keys.sort();
            assert_eq!(keys, ["c", "i", "op", "v"]);
        }

        #[test]
        fn v3_bloom_filter_upper_half_wraps_to_signed() {
            // v2 emits unsigned bit positions; the v3 smallint[] encoding
            // reinterprets the upper half (32768..=65535) as negative i16.
            let output = storage_output(
                scalar_payload(Some("aa"), Some(vec![7, 40000]), Some(vec!["bb"])),
                EqlVersion::V3,
                &text_search_column(),
            )
            .unwrap();

            let value = serde_json::to_value(&output).unwrap();
            assert_eq!(value["bf"], serde_json::json!([7, 40000u16 as i16]));
        }

        #[test]
        fn v3_ste_vec_output_is_a_ste_vec_document_with_order_preserved() {
            let cfg = column(
                ColumnType::Json,
                vec![Index::new(IndexType::SteVec {
                    prefix: "users/profile".to_string(),
                    term_filters: vec![],
                    array_index_mode: Default::default(),
                    mode: SteVecMode::Compat,
                })],
            );
            let output = storage_output_v3(native_ste_vec_document(), &cfg).unwrap();

            let value = serde_json::to_value(&output).unwrap();
            assert_eq!(value["v"], 3);
            assert_eq!(
                value["k"], "sv",
                "SteVec documents keep the k form discriminator"
            );
            assert!(
                value["h"].is_string(),
                "one key header is stored per document"
            );
            let sv = value["sv"].as_array().unwrap();
            assert_eq!(sv.len(), 2);
            // sv[0] is the decryption root — order must survive parsing.
            assert_eq!(sv[0]["s"], "root");
            assert!(sv[0].get("hm").is_none(), "exact match uses selectors");
            assert!(sv[0]["c"].is_string());
            assert_eq!(sv[1]["s"], "leaf");
            assert_eq!(sv[1]["op"], "deadbeef");
            assert_eq!(sv[1]["a"], true);
        }

        #[test]
        fn v3_ste_vec_conversion_fails_closed_on_an_ore_entry_term() {
            // Defense in depth: target_domain_for_column already rejects a
            // `standard`-mode column, so this payload should be unreachable.
            // If an `oc` entry ever does arrive (a mode change with rows
            // already written under the old mode), conversion must still
            // refuse rather than emit a v3 document ordered by ORE bytes.
            let cfg = column(
                ColumnType::Json,
                vec![Index::new(IndexType::SteVec {
                    prefix: "users/profile".to_string(),
                    term_filters: vec![],
                    array_index_mode: Default::default(),
                    mode: SteVecMode::Compat,
                })],
            );
            let err = storage_output(ore_ste_vec_payload(), EqlVersion::V3, &cfg)
                .unwrap_err()
                .to_string();
            assert!(
                err.starts_with("EQL v3 conversion failed"),
                "carries the conversion-failure prefix: {err}"
            );
            assert!(err.contains("re-encrypt"), "names the remedy: {err}");
        }

        #[test]
        fn v3_conversion_fails_closed_when_a_required_term_is_missing() {
            // text_search_ore requires hm + ob + bf; a payload missing bf must
            // not silently degrade.
            let result = storage_output(
                scalar_payload(Some("aa"), None, Some(vec!["bb"])),
                EqlVersion::V3,
                &text_search_column(),
            );

            let err = result.unwrap_err().to_string();
            assert!(err.contains("bf"), "names the missing term: {err}");
            // Stable prefix: the TS side maps it to EQL_V3_CONVERSION_FAILED.
            assert!(
                err.starts_with("EQL v3 conversion failed"),
                "carries the conversion-failure prefix: {err}"
            );
        }
    }

    mod query_output {
        use super::support::{column, ope_scalar_payload, scalar_payload, ste_vec_payload};
        use super::*;
        use cipherstash_client::eql::{
            EncryptedQueryPayload, EqlOutput, EqlQueryPayload, Identifier as EqlIdentifier,
            RootQueryTerm, SteVecQueryPayload, SteVecQueryTerm, EQL_SCHEMA_VERSION,
        };
        use cipherstash_client::schema::column::{Index, IndexType, Tokenizer};

        fn scalar_query() -> EqlOutput {
            EqlOutput::Query(EqlQueryPayload::Encrypted(EncryptedQueryPayload {
                version: EQL_SCHEMA_VERSION,
                identifier: EqlIdentifier::new("users", "email"),
                term: RootQueryTerm::Hmac {
                    hmac_256: "aa".into(),
                },
            }))
        }

        fn selector_query() -> EqlOutput {
            EqlOutput::Query(EqlQueryPayload::SteVec(SteVecQueryPayload {
                version: EQL_SCHEMA_VERSION,
                identifier: EqlIdentifier::new("users", "profile"),
                term: SteVecQueryTerm::Selector {
                    selector: "deadbeef".into(),
                },
            }))
        }

        fn text_search_column() -> ColumnConfig {
            column(
                ColumnType::Text,
                vec![
                    Index::new(IndexType::Unique {
                        token_filters: vec![],
                    }),
                    Index::new(IndexType::Ore),
                    Index::new(IndexType::Match {
                        tokenizer: Tokenizer::Standard,
                        token_filters: vec![],
                        k: 6,
                        m: 2048,
                        include_original: false,
                    }),
                ],
            )
        }

        fn json_column() -> ColumnConfig {
            column(
                ColumnType::Json,
                vec![Index::new(IndexType::SteVec {
                    prefix: "users/profile".to_string(),
                    term_filters: vec![],
                    array_index_mode: Default::default(),
                    mode: SteVecMode::Compat,
                })],
            )
        }

        fn sorted_keys(value: &serde_json::Value) -> Vec<&String> {
            let mut keys: Vec<_> = value.as_object().unwrap().keys().collect();
            keys.sort();
            keys
        }

        /// A native v3 Store-mode result (as `encrypt_eql_v3` emits for a v3
        /// scalar query) carrying the same terms as `scalar_payload(Some("aa"),
        /// Some([1, 2]), Some(["bb"]))`.
        fn native_scalar_store() -> cipherstash_client::eql::EqlOutputV3 {
            use cipherstash_client::eql::{
                EncryptedPayloadV3, EqlCiphertextV3, EqlOutputV3, Identifier as EqlIdentifier,
                EQL_SCHEMA_VERSION_V3,
            };
            EqlOutputV3::Store(EqlCiphertextV3::Encrypted(EncryptedPayloadV3 {
                version: EQL_SCHEMA_VERSION_V3,
                identifier: EqlIdentifier::new("users", "email"),
                ciphertext: super::support::dummy_encrypted_record(),
                hmac_256: Some("aa".into()),
                bloom_filter: Some(vec![1, 2]),
                ore_block_u64_8_256: Some(vec!["bb".into()]),
                ope_cllw: None,
            }))
        }

        #[test]
        fn query_output_v3_native_matches_the_from_v2_query_conversion() {
            // The native emit path (query_output_v3 via into_query_operand) and
            // the from_v2 path (query_output V3 branch) must produce the
            // identical typed QueryPayload for the same terms — behaviour-
            // preserving when retiring from_v2 from the query runtime.
            let cfg = text_search_column();
            let native = query_output_v3(native_scalar_store(), &cfg).unwrap();
            let converted = query_output(
                EqlOutput::Store(scalar_payload(
                    Some("aa"),
                    Some(vec![1, 2]),
                    Some(vec!["bb"]),
                )),
                EqlVersion::V3,
                &cfg,
            )
            .unwrap();
            assert_eq!(
                serde_json::to_value(&native).unwrap(),
                serde_json::to_value(&converted).unwrap(),
            );
        }

        #[test]
        fn query_output_v3_scalar_operand_carries_no_c_or_k() {
            let v = serde_json::to_value(
                query_output_v3(native_scalar_store(), &text_search_column()).unwrap(),
            )
            .unwrap();
            assert_eq!(v["v"], 3);
            assert!(v.get("c").is_none(), "a query operand must not carry `c`");
            assert!(v.get("k").is_none());
            assert_eq!(v["hm"], "aa");
        }

        #[test]
        fn query_output_v3_selector_becomes_the_bare_v3_selector() {
            use cipherstash_client::eql::{EqlOutputV3, EqlQueryPayloadV3};
            let out = query_output_v3(
                EqlOutputV3::Query(EqlQueryPayloadV3::Selector("deadbeef".into())),
                &json_column(),
            )
            .unwrap();
            // V3Selector(Selector) serializes as the bare selector string (SQL text).
            assert_eq!(
                serde_json::to_value(&out).unwrap(),
                serde_json::json!("deadbeef")
            );
        }

        fn native_ste_vec_query() -> cipherstash_client::eql::EqlOutputV3 {
            use cipherstash_client::eql::{
                EqlOutputV3, EqlQueryPayloadV3, SteVecQueryEntryV3, SteVecQueryPayloadV3,
            };
            EqlOutputV3::Query(EqlQueryPayloadV3::SteVec(SteVecQueryPayloadV3 {
                ste_vec: vec![SteVecQueryEntryV3 {
                    selector: "deadbeef".into(),
                    term: None,
                }],
            }))
        }

        #[test]
        fn query_output_v3_value_selector_is_a_termless_containment_needle() {
            let out = query_output_v3(native_ste_vec_query(), &json_column()).unwrap();

            assert_eq!(
                serde_json::to_value(&out).unwrap(),
                serde_json::json!({"sv": [{"s": "deadbeef"}]})
            );
        }

        #[test]
        fn query_output_v3_ste_vec_needle_rejects_a_scalar_query_domain() {
            let err = query_output_v3(native_ste_vec_query(), &text_search_column()).unwrap_err();
            assert!(matches!(
                err,
                Error::V3NativeParse { ref domain, .. }
                    if domain == "query_text_search_ore"
            ));
        }

        #[test]
        fn query_output_v3_ste_vec_needle_rejects_a_domain_without_a_query_variant() {
            let storage_only = column(ColumnType::Text, vec![]);
            let err = query_output_v3(native_ste_vec_query(), &storage_only).unwrap_err();
            assert!(matches!(&err, Error::InvariantViolation(_)));
            assert!(
                err.to_string().contains("has no QueryPayload variant"),
                "names the missing query variant: {err}"
            );
        }

        #[test]
        fn query_output_v3_ste_vec_ordering_term_keeps_the_one_term_operand() {
            use cipherstash_client::eql::{
                EncryptedQueryPayloadV3, EqlOutputV3, EqlQueryPayloadV3, Identifier,
                EQL_SCHEMA_VERSION_V3,
            };
            let out = query_output_v3(
                EqlOutputV3::Query(EqlQueryPayloadV3::Encrypted(EncryptedQueryPayloadV3 {
                    version: EQL_SCHEMA_VERSION_V3,
                    identifier: Identifier::new("users", "profile"),
                    hmac_256: None,
                    bloom_filter: None,
                    ore_block_u64_8_256: None,
                    ope_cllw: Some("deadbeef".into()),
                })),
                &json_column(),
            )
            .unwrap();

            assert_eq!(
                serde_json::to_value(&out).unwrap(),
                serde_json::json!({
                    "v": 3,
                    "i": {"t": "users", "c": "profile"},
                    "op": "deadbeef"
                })
            );
        }

        /// A native v3 Store-mode SteVec document (as `encrypt_eql_v3` emits
        /// for a v3 containment query) carrying the same entries as
        /// `support::ste_vec_payload()`.
        fn native_ste_vec_store() -> cipherstash_client::eql::EqlOutputV3 {
            use cipherstash_client::eql::{
                EqlCiphertextV3, EqlOutputV3, Identifier as EqlIdentifier, SteVecEntryTermV3,
                SteVecEntryV3, SteVecKind, SteVecPayloadV3, EQL_SCHEMA_VERSION_V3,
            };
            EqlOutputV3::Store(EqlCiphertextV3::SteVec(SteVecPayloadV3 {
                version: EQL_SCHEMA_VERSION_V3,
                kind: SteVecKind::SteVec,
                identifier: EqlIdentifier::new("users", "profile"),
                key_header: super::support::dummy_key_header(),
                ste_vec: vec![
                    SteVecEntryV3 {
                        selector: "root".into(),
                        ciphertext: vec![1; 16],
                        is_array: None,
                        term: None,
                    },
                    SteVecEntryV3 {
                        selector: "leaf".into(),
                        ciphertext: vec![2; 16],
                        is_array: Some(true),
                        term: Some(SteVecEntryTermV3::Ope {
                            ope_cllw: "deadbeef".into(),
                        }),
                    },
                ],
            }))
        }

        #[test]
        fn v2_ste_vec_query_cannot_be_converted_to_v3() {
            let cfg = json_column();
            assert!(
                query_output(EqlOutput::Store(ste_vec_payload()), EqlVersion::V3, &cfg,).is_err()
            );
        }

        #[test]
        fn query_output_v3_native_containment_needle_strips_envelope_c_and_a() {
            let v = serde_json::to_value(
                query_output_v3(native_ste_vec_store(), &json_column()).unwrap(),
            )
            .unwrap();
            // The eql_v3.query_json needle: {sv: [{s, op?}]} — no envelope,
            // no per-entry ciphertext or array marker.
            assert!(v.get("v").is_none(), "needle carries no envelope");
            assert!(v.get("i").is_none(), "needle carries no identifier");
            assert!(v.get("k").is_none(), "needle carries no k");
            let sv = v["sv"].as_array().unwrap();
            assert_eq!(sv.len(), 2);
            assert_eq!(sv[0]["s"], "root");
            assert!(sv[0].get("hm").is_none(), "exact match uses selectors");
            assert!(sv[0].get("c").is_none(), "c is stripped from entries");
            assert_eq!(sv[1]["op"], "deadbeef");
            assert!(sv[1].get("a").is_none(), "a is stripped from entries");
        }

        #[test]
        fn query_output_v3_native_parse_failure_is_a_conversion_error() {
            use cipherstash_client::eql::{
                EncryptedPayloadV3, EqlCiphertextV3, EqlOutputV3, Identifier as EqlIdentifier,
                EQL_SCHEMA_VERSION_V3,
            };
            // Same contract as the storage path: a native operand that fails
            // the query twin's strict parse must map to the
            // EQL_V3_CONVERSION_FAILED error message, not a bare serde error.
            let incomplete = EqlOutputV3::Store(EqlCiphertextV3::Encrypted(EncryptedPayloadV3 {
                version: EQL_SCHEMA_VERSION_V3,
                identifier: EqlIdentifier::new("users", "email"),
                ciphertext: super::support::dummy_encrypted_record(),
                hmac_256: Some("aa".into()),
                bloom_filter: None,
                ore_block_u64_8_256: None,
                ope_cllw: None,
            }));
            let err = query_output_v3(incomplete, &text_search_column())
                .unwrap_err()
                .to_string();
            assert!(
                err.starts_with("EQL v3 conversion failed"),
                "native parse failures must keep the conversion-failed error contract: {err}"
            );
            assert!(
                err.contains("query_text_search_ore"),
                "the error should name the target query domain: {err}"
            );
        }

        #[test]
        fn v2_output_serializes_identically_to_the_bare_eql_output() {
            let expected = serde_json::to_string(&scalar_query()).unwrap();

            let output =
                query_output(scalar_query(), EqlVersion::V2, &text_search_column()).unwrap();

            assert_eq!(serde_json::to_string(&output).unwrap(), expected);
        }

        #[test]
        fn v2_containment_output_passes_through() {
            let expected = serde_json::to_string(&EqlOutput::Store(ste_vec_payload())).unwrap();

            let output = query_output(
                EqlOutput::Store(ste_vec_payload()),
                EqlVersion::V2,
                &json_column(),
            )
            .unwrap();

            assert_eq!(serde_json::to_string(&output).unwrap(), expected);
        }

        #[test]
        fn v3_containment_output_is_a_query_json_needle() {
            let output = query_output_v3(native_ste_vec_store(), &json_column()).unwrap();

            let value = serde_json::to_value(&output).unwrap();
            // The eql_v3.query_json needle: {sv: [{s, op?}]} — no
            // envelope, no per-entry ciphertext or array marker.
            assert!(value.get("v").is_none(), "needle carries no envelope");
            assert!(value.get("i").is_none(), "needle carries no identifier");
            assert!(value.get("k").is_none(), "needle carries no k");
            let sv = value["sv"].as_array().unwrap();
            assert_eq!(sv.len(), 2);
            assert_eq!(sv[0]["s"], "root");
            assert!(sv[0].get("hm").is_none(), "exact match uses selectors");
            assert!(sv[0].get("c").is_none(), "c is stripped from entries");
            assert_eq!(sv[1]["s"], "leaf");
            assert_eq!(sv[1]["op"], "deadbeef");
            assert!(sv[1].get("a").is_none(), "a is stripped from entries");
        }

        #[test]
        fn v3_typed_query_output_serializes_identically_to_the_from_v2_query_value() {
            // The QueryOutput::V3 wire form must be byte-identical to what
            // the shape-erased from_v2_query Value produced — protect-ffi
            // serializes it straight across the FFI boundary. Pinned for the
            // a scalar term-only operand. SteVec documents cannot be
            // mechanically converted because v3 requires a key header.
            use eql_bindings::from_v2::from_v2_query;

            let scalar_ct = scalar_payload(Some("aa"), Some(vec![1, 2]), Some(vec!["bb"]));
            let scalar_v2 = serde_json::to_value(&scalar_ct).unwrap();
            // from_v2_query takes the STORED domain and derives the query twin
            // (`eql_v3_text_search_ore` → `query_text_search_ore`) itself.
            let scalar_target =
                TargetDomain::parse(&target_domain_for_column(&text_search_column()).unwrap())
                    .unwrap();
            let erased = from_v2_query(&scalar_v2, scalar_target).unwrap();

            let output = query_output(
                EqlOutput::Store(scalar_ct),
                EqlVersion::V3,
                &text_search_column(),
            )
            .unwrap();
            let typed = serde_json::to_value(&output).unwrap();

            assert_eq!(typed, erased);
        }

        #[test]
        fn v3_scalar_store_output_is_a_term_only_operand() {
            // A scalar Store envelope hoists to the column domain's query
            // twin (eql_v3.query_text_search): all the domain's terms, the
            // envelope and NO ciphertext.
            let output = query_output(
                EqlOutput::Store(scalar_payload(
                    Some("aa"),
                    Some(vec![1, 2]),
                    Some(vec!["bb"]),
                )),
                EqlVersion::V3,
                &text_search_column(),
            )
            .unwrap();

            let value = serde_json::to_value(&output).unwrap();
            assert_eq!(value["v"], 3);
            assert!(value.get("c").is_none(), "query operands carry no c");
            assert!(value.get("k").is_none(), "query operands carry no k");
            assert_eq!(value["i"]["t"], "users");
            assert_eq!(value["i"]["c"], "email");
            assert_eq!(value["hm"], "aa");
            assert_eq!(value["ob"], serde_json::json!(["bb"]));
            assert_eq!(value["bf"], serde_json::json!([1, 2]));
            assert_eq!(sorted_keys(&value), ["bf", "hm", "i", "ob", "v"]);
        }

        #[test]
        fn v3_text_eq_operand_carries_hm_only() {
            // unique-only text column → eql_v3.query_text_eq: {v, i, hm}.
            let cfg = column(
                ColumnType::Text,
                vec![Index::new(IndexType::Unique {
                    token_filters: vec![],
                })],
            );
            let output = query_output(
                EqlOutput::Store(scalar_payload(Some("aa"), None, None)),
                EqlVersion::V3,
                &cfg,
            )
            .unwrap();

            let value = serde_json::to_value(&output).unwrap();
            assert_eq!(value["hm"], "aa");
            assert_eq!(sorted_keys(&value), ["hm", "i", "v"]);
        }

        #[test]
        fn v3_integer_ord_ore_operand_carries_ob_only() {
            // ore-indexed int column → eql_v3.query_integer_ord_ore: {v, i,
            // ob} (non-text ordering domains carry no hm).
            let cfg = column(ColumnType::Int, vec![Index::new(IndexType::Ore)]);
            let output = query_output(
                EqlOutput::Store(scalar_payload(None, None, Some(vec!["bb"]))),
                EqlVersion::V3,
                &cfg,
            )
            .unwrap();

            let value = serde_json::to_value(&output).unwrap();
            assert_eq!(value["ob"], serde_json::json!(["bb"]));
            assert_eq!(sorted_keys(&value), ["i", "ob", "v"]);
        }

        #[test]
        fn v3_integer_ord_ope_operand_carries_op_only() {
            // ope-indexed int column → eql_v3.query_integer_ord_ope: {v, i,
            // op} (the CLLW-OPE term reaches the query twin too).
            let cfg = column(ColumnType::Int, vec![Index::new(IndexType::Ope)]);
            let output = query_output(
                EqlOutput::Store(ope_scalar_payload("cc")),
                EqlVersion::V3,
                &cfg,
            )
            .unwrap();

            let value = serde_json::to_value(&output).unwrap();
            assert_eq!(value["op"], "cc");
            assert_eq!(sorted_keys(&value), ["i", "op", "v"]);
        }

        #[test]
        fn v3_match_operand_bloom_upper_half_wraps_to_signed() {
            // match-only text column → eql_v3.query_text_match: {v, i, bf},
            // with the same u16→i16 reinterpretation as storage conversion.
            let cfg = column(
                ColumnType::Text,
                vec![Index::new(IndexType::Match {
                    tokenizer: Tokenizer::Standard,
                    token_filters: vec![],
                    k: 6,
                    m: 2048,
                    include_original: false,
                })],
            );
            let output = query_output(
                EqlOutput::Store(scalar_payload(None, Some(vec![7, 40000]), None)),
                EqlVersion::V3,
                &cfg,
            )
            .unwrap();

            let value = serde_json::to_value(&output).unwrap();
            assert_eq!(value["bf"], serde_json::json!([7, 40000u16 as i16]));
            assert_eq!(sorted_keys(&value), ["bf", "i", "v"]);
        }

        #[test]
        fn v3_selector_query_returns_the_bare_selector_string() {
            // v3 has no encrypted-selector envelope: the SQL `->`/`->>`
            // operators take the bare selector hash as text (the same
            // Selector encoding SteVecQuery entries carry in `s`).
            let output = query_output(selector_query(), EqlVersion::V3, &json_column()).unwrap();

            let value = serde_json::to_value(&output).unwrap();
            assert_eq!(value, serde_json::json!("deadbeef"));
        }

        #[test]
        fn v3_scalar_query_mode_payload_is_an_invariant_violation() {
            // Under v3, scalar Default queries run Store mode (the operand
            // needs ALL the column domain's terms), so a v2 Query-mode
            // scalar payload arriving here means the mode inference broke.
            let err =
                query_output(scalar_query(), EqlVersion::V3, &text_search_column()).unwrap_err();

            assert!(matches!(err, Error::InvariantViolation(_)));
            assert!(
                err.to_string()
                    .contains("scalar query encryption ran in query mode"),
                "names the broken invariant: {err}"
            );
        }

        #[test]
        fn v3_store_scalar_on_a_json_column_fails_closed() {
            // A scalar Store envelope for a ste_vec column targets
            // TargetDomain::Json; the conversion rejects the kind mismatch
            // instead of emitting a malformed needle.
            let err = query_output(
                EqlOutput::Store(scalar_payload(Some("aa"), None, None)),
                EqlVersion::V3,
                &json_column(),
            )
            .unwrap_err();

            let msg = err.to_string();
            // Stable prefix: the TS side maps it to EQL_V3_CONVERSION_FAILED.
            assert!(
                msg.starts_with("EQL v3 conversion failed"),
                "carries the conversion-failure prefix: {msg}"
            );
        }
    }

    mod dual_format_decrypt {
        use super::support::{column, dummy_key_header, scalar_payload, ste_vec_payload};
        use super::*;
        use cipherstash_client::schema::column::{Index, IndexType};
        use serde_json::json;

        fn v2_scalar_value() -> serde_json::Value {
            serde_json::to_value(scalar_payload(Some("aa"), None, None)).unwrap()
        }

        fn v2_ste_vec_value() -> serde_json::Value {
            serde_json::to_value(ste_vec_payload()).unwrap()
        }

        fn v3_scalar_value() -> serde_json::Value {
            let cfg = column(
                ColumnType::Text,
                vec![Index::new(IndexType::Unique {
                    token_filters: vec![],
                })],
            );
            let output =
                storage_output(scalar_payload(Some("aa"), None, None), EqlVersion::V3, &cfg)
                    .unwrap();
            serde_json::to_value(&output).unwrap()
        }

        fn v3_ste_vec_value() -> serde_json::Value {
            use cipherstash_client::eql::{
                EqlCiphertextV3, Identifier, SteVecEntryV3, SteVecKind, SteVecPayloadV3,
                EQL_SCHEMA_VERSION_V3,
            };
            let cfg = column(
                ColumnType::Json,
                vec![Index::new(IndexType::SteVec {
                    prefix: "users/profile".to_string(),
                    term_filters: vec![],
                    array_index_mode: Default::default(),
                    mode: SteVecMode::Compat,
                })],
            );
            let output = storage_output_v3(
                EqlCiphertextV3::SteVec(SteVecPayloadV3 {
                    version: EQL_SCHEMA_VERSION_V3,
                    kind: SteVecKind::SteVec,
                    identifier: Identifier::new("users", "profile"),
                    key_header: dummy_key_header(),
                    ste_vec: vec![SteVecEntryV3 {
                        selector: "00000000000000000000000000000000".to_string(),
                        ciphertext: vec![1; 16],
                        is_array: None,
                        term: None,
                    }],
                }),
                &cfg,
            )
            .unwrap();
            serde_json::to_value(&output).unwrap()
        }

        mod encrypted_record_from_value {
            use super::*;

            #[test]
            fn decodes_a_v2_scalar_payload() {
                let record = encrypted_record_from_value(v2_scalar_value(), vec![]).unwrap();
                assert_eq!(record.record.encrypted_record().descriptor, "users/email");
            }

            #[test]
            fn decodes_a_v2_ste_vec_payload_from_the_root_entry() {
                let record = encrypted_record_from_value(v2_ste_vec_value(), vec![]).unwrap();
                assert_eq!(record.record.encrypted_record().descriptor, "users/email");
            }

            #[test]
            fn decodes_a_v3_scalar_payload() {
                let record = encrypted_record_from_value(v3_scalar_value(), vec![]).unwrap();
                assert_eq!(record.record.encrypted_record().descriptor, "users/email");
            }

            #[test]
            fn decodes_a_v3_ste_vec_document_from_sv_0() {
                let record = encrypted_record_from_value(v3_ste_vec_value(), vec![]).unwrap();
                assert_eq!(record.record.encrypted_record().descriptor, "users/profile");
                assert!(matches!(record.record, DecryptableRecord::SteVec(_)));
            }

            #[test]
            fn decodes_a_v3_ste_vec_entry_with_grafted_metadata() {
                let document = v3_ste_vec_value();
                let mut entry = document["sv"][0].clone();
                let object = entry.as_object_mut().unwrap();
                object.insert("v".to_string(), document["v"].clone());
                object.insert("i".to_string(), document["i"].clone());
                object.insert("h".to_string(), document["h"].clone());

                let record = encrypted_record_from_value(entry, vec![]).unwrap();
                assert_eq!(record.record.encrypted_record().descriptor, "users/profile");
                assert!(matches!(record.record, DecryptableRecord::SteVec(_)));
            }

            #[test]
            fn preserves_the_lock_context() {
                let context = vec![zerokms::Context::IdentityClaim("sub".to_string())];
                let record =
                    encrypted_record_from_value(v3_scalar_value(), context.clone()).unwrap();
                assert_eq!(record.context.len(), 1);
            }

            #[test]
            fn rejects_plain_json() {
                let err = encrypted_record_from_value(json!({"random": "data"}), vec![]);
                assert!(err.is_err());
            }

            #[test]
            fn rejects_a_v3_document_with_an_empty_sv() {
                let mut value = v3_ste_vec_value();
                value["sv"] = json!([]);
                let err = encrypted_record_from_value(value, vec![]).unwrap_err();
                // The v3-specific message also pins ROUTING: the error must
                // come from v3_root_record, not the v2 SteVec arm (whose
                // message reads "… in SteVec EQL payload").
                assert!(
                    err.to_string().contains("root entry in v3 SteVec payload"),
                    "mentions the missing root entry via the v3 branch: {err}"
                );
            }

            #[test]
            fn rejects_a_v3_document_with_a_malformed_selector() {
                let mut value = v3_ste_vec_value();
                value["sv"][0]["s"] = json!("deadbeef");
                assert!(matches!(
                    encrypted_record_from_value(value, vec![]).unwrap_err(),
                    Error::InvalidSteVecSelector
                ));

                let mut value = v3_ste_vec_value();
                value["sv"][0]["s"] = json!("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz");
                assert!(matches!(
                    encrypted_record_from_value(value, vec![]).unwrap_err(),
                    Error::InvalidSteVecSelector
                ));
            }
        }

        #[test]
        fn v2_parse_rejects_the_v3_key_header_document() {
            // Client 0.42's v3 SteVec entry ciphertext is raw AEAD output and
            // its key material is stored once in `h`; the v2 parser expects a
            // self-contained encrypted record in every entry.
            assert!(
                EqlCiphertext::deserialize(&v3_ste_vec_value()).is_err(),
                "the v2 parser must not accept a v3 key-header document"
            );
        }

        mod is_encrypted_value {
            use super::*;

            #[test]
            fn accepts_both_wire_formats() {
                for value in [
                    v2_scalar_value(),
                    v2_ste_vec_value(),
                    v3_scalar_value(),
                    v3_ste_vec_value(),
                ] {
                    assert!(is_encrypted_value(&value), "should accept: {value}");
                }
            }

            #[test]
            fn rejects_non_payload_values() {
                for value in [
                    json!({"random": "data"}),
                    json!("plaintext"),
                    json!(42),
                    json!(null),
                    // v2 envelope without the k discriminator
                    json!({"v": 2, "i": {"t": "users", "c": "email"}}),
                    // a v3 containment needle is a QUERY payload, not storage
                    json!({"sv": [{"s": "aa", "hm": "bb"}]}),
                ] {
                    assert!(!is_encrypted_value(&value), "should reject: {value}");
                }
            }
        }
    }
}
