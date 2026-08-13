//! The `from_v2` error enum — hand-rolled `Display`/`Error` (this crate's
//! dependency set is pinned to serde/serde_json/ts-rs/schemars, so no
//! thiserror).

use std::error::Error;
use std::fmt;

/// Why a v2 → v3 conversion was refused. Every variant is fail-closed: the
/// converter never emits a v3 payload it could not validate.
#[derive(Debug)]
pub enum FromV2Error {
    /// The input's envelope version (`v`) is not the v2 wire version `2` —
    /// `found: Some(3)` for an already-converted v3 payload, `None` when `v`
    /// is absent or not an integer (e.g. plaintext JSON).
    UnsupportedVersion {
        /// The integer `v` the input carried, if any.
        found: Option<u64>,
    },
    /// The input's kind discriminator (`k`) is neither `"ct"` nor `"sv"`
    /// (`found: None` when `k` is absent or not a string).
    UnknownKind {
        /// The `k` string the input carried, if any.
        found: Option<String>,
    },
    /// [`TargetDomain::parse`](super::TargetDomain::parse) did not find the
    /// name in the catalog-generated inventory (or it names a SteVec shape —
    /// `jsonb_entry` / `query_json` — that is not a conversion target).
    UnknownDomain {
        /// The name that failed to resolve.
        name: String,
    },
    /// A term key the target scalar domain requires is absent from the input.
    MissingTerm {
        /// The (unqualified) target domain name, e.g. `text_eq`.
        domain: String,
        /// The missing wire key (`hm`/`ob`/`bf`/`op`).
        key: String,
        /// Reserved for structured payloads; scalar payloads use `None`.
        entry: Option<usize>,
    },
    /// A v2 SteVec **document** has no v3 representation: the v3 envelope
    /// wire format stores one key header (`h`) per document with per-entry
    /// ciphertexts encrypted under selector-derived nonces, none of which can
    /// be derived from a v2 payload by JSON transformation — that is
    /// re-encryption. Encrypt the document through a v3-emitting client
    /// (`encrypt_eql_v3`).
    UnconvertibleSteVecDocument,
    /// A v2 SteVec **query** has no v3 exact-match representation. Legacy
    /// SteVec equality needles carry a path selector plus `hm` or `op`; v3
    /// equality requires a value-inclusive selector derived from the original
    /// plaintext. Neither legacy term contains enough information to construct
    /// that selector, so callers must produce the query through a v3-emitting
    /// client.
    UnconvertibleSteVecQuery,
    /// The input's kind contradicts the target: an `sv` payload for a scalar
    /// target, or a `ct` payload for [`TargetDomain::Json`](super::TargetDomain::Json).
    KindMismatch {
        /// The input's `k` discriminator (`ct` or `sv`).
        kind: String,
        /// The requested target (a domain name, or `json`).
        target: String,
    },
    /// A `bf` element is outside both the signed `i16` range and the unsigned
    /// upper half (`32768..=65535`) that reinterprets into it — it cannot be
    /// a PostgreSQL `smallint[]` bit position.
    BloomOutOfRange {
        /// Zero-based index of the offending `bf` element.
        index: usize,
        /// The out-of-range element value.
        value: i64,
    },
    /// [`from_v2_query`](super::from_v2_query) was asked for a storage-only
    /// scalar target. Storage-only domains have no operators or query-operand
    /// twin, so there is no meaningful query payload to produce.
    UnsupportedQueryTarget {
        /// The (unqualified) scalar domain name that was requested.
        domain: String,
    },
    /// The converted payload failed the final strict parse through the target
    /// domain's binding struct (`deny_unknown_fields` + `SchemaVersion`), or
    /// the input was structurally malformed (e.g. a non-array `sv` or `bf`).
    Invalid(serde_json::Error),
}

impl fmt::Display for FromV2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion { found: Some(v) } => {
                write!(f, "unsupported EQL payload version {v} (expected 2)")
            }
            Self::UnsupportedVersion { found: None } => {
                write!(
                    f,
                    "input carries no integer EQL version key `v` (expected 2)"
                )
            }
            Self::UnknownKind { found: Some(k) } => {
                write!(
                    f,
                    "unknown EQL payload kind {k:?} (expected \"ct\" or \"sv\")"
                )
            }
            Self::UnknownKind { found: None } => {
                write!(
                    f,
                    "input carries no kind key `k` (expected \"ct\" or \"sv\")"
                )
            }
            Self::UnknownDomain { name } => {
                write!(f, "unknown target domain {name:?}")
            }
            Self::MissingTerm {
                domain,
                key,
                entry: Some(entry),
            } => {
                write!(
                    f,
                    "sv entry {entry} carries no term key `{key}` required by `{domain}`"
                )
            }
            Self::MissingTerm {
                domain,
                key,
                entry: None,
            } => {
                write!(f, "target domain `{domain}` requires term key `{key}`, absent from the v2 payload")
            }
            Self::UnconvertibleSteVecDocument => {
                write!(
                    f,
                    "a v2 SteVec document cannot be converted to the v3 envelope wire format \
                     (per-document key header + selector-derived entry nonces) — that is \
                     re-encryption, not a JSON transformation; encrypt through encrypt_eql_v3"
                )
            }
            Self::UnconvertibleSteVecQuery => {
                write!(
                    f,
                    "a v2 SteVec query cannot be converted to v3 exact-match semantics: \
                     a value-inclusive selector cannot be derived from a legacy hm/op term; \
                     produce the query through a v3-emitting client"
                )
            }
            Self::KindMismatch { kind, target } => {
                write!(
                    f,
                    "v2 payload kind `{kind}` cannot convert to target `{target}`"
                )
            }
            Self::BloomOutOfRange { index, value } => {
                write!(
                    f,
                    "bf element {index} ({value}) is outside the smallint bit-position range"
                )
            }
            Self::UnsupportedQueryTarget { domain } => {
                write!(f, "storage-only domain `{domain}` has no v3 query operand")
            }
            Self::Invalid(e) => {
                write!(f, "converted payload failed v3 validation: {e}")
            }
        }
    }
}

impl Error for FromV2Error {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Invalid(e) => Some(e),
            _ => None,
        }
    }
}
