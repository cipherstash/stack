//! The `queryOp` wire vocabulary.
//!
//! `queryOp` selects how `encryptQuery` / `encryptQueryBulk` interpret a
//! plaintext — as a JSON path, an exact-match `{path, value}` pair, an ordering
//! operand, or "infer it from the plaintext type". It used to travel as a bare
//! `String` from the options struct all the way to `prepare_query_plaintext`,
//! where a `match` turned it into cipherstash-client's [`QueryOp`].
//!
//! Making it a type moves that rejection to the deserialization boundary, which
//! buys three things:
//!
//! 1. **A bad value cannot exist.** Everything downstream takes
//!    [`QueryOpName`], so there is no "did someone validate this yet?" question
//!    and no second parse to keep in sync.
//! 2. **The failure names the field.** A typo is now reported against `queryOp`
//!    while deserializing the options, not from inside query preparation after
//!    the column and index have already been resolved.
//! 3. **The variants are the documentation.** The enum is the same closed set
//!    as `QueryOpName` in `src/types.ts`, so the two cannot drift silently —
//!    [`tests::the_wire_vocabulary_matches_the_typescript_union`] spells the
//!    union out.
//!
//! # The error message is load-bearing
//!
//! `inferErrorCode` in `src/errors.ts` maps this failure to the public
//! `UNKNOWN_QUERY_OP` error code by matching on the message prefix. That is why
//! [`QueryOpName`] has a hand-written `Deserialize` rather than a derived one:
//! serde's own "unknown variant" message would break the mapping, and the code
//! would quietly become unreachable. [`UNKNOWN_QUERY_OP_PREFIX`] is the shared
//! constant, and a test below pins it.

use std::fmt;

use cipherstash_client::encryption::QueryOp;
use serde::{Deserialize, Deserializer};

/// Prefix `src/errors.ts` matches to infer the `UNKNOWN_QUERY_OP` error code.
/// Changing it is a breaking change to that code — update both sides together.
pub(crate) const UNKNOWN_QUERY_OP_PREFIX: &str = "Unknown query operation:";

/// The `queryOp` values the public API accepts.
///
/// Mirrors `QueryOpName` in `src/types.ts`. Deliberately NOT a re-export of
/// cipherstash-client's [`QueryOp`]: that type is the library's internal
/// vocabulary and may grow variants this binding has no wire spelling for, so
/// the mapping stays explicit in [`QueryOpName::to_query_op`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum QueryOpName {
    /// Infer from the plaintext and index type — see `to_query_plaintext`.
    #[default]
    Default,
    /// A JSON path (`"$.user.email"`) against an `ste_vec` index.
    SteVecSelector,
    /// A `{path, value}` pair for exact match against an `ste_vec` index.
    SteVecValueSelector,
    /// An ordering operand (string or number) against an `ste_vec` index.
    SteVecTerm,
}

impl QueryOpName {
    /// Every accepted value, in the order the error message lists them.
    pub(crate) const ALL: [Self; 4] = [
        Self::Default,
        Self::SteVecSelector,
        Self::SteVecValueSelector,
        Self::SteVecTerm,
    ];

    /// The wire spelling — what a caller writes as `queryOp`.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::SteVecSelector => "ste_vec_selector",
            Self::SteVecValueSelector => "ste_vec_value_selector",
            Self::SteVecTerm => "ste_vec_term",
        }
    }

    fn from_wire(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|op| op.as_str() == value)
    }

    /// Map onto cipherstash-client's [`QueryOp`].
    ///
    /// Infallible by construction: a `QueryOpName` only exists for a value that
    /// already passed the boundary check.
    pub(crate) fn to_query_op(self) -> QueryOp {
        match self {
            Self::Default => QueryOp::Default,
            Self::SteVecSelector => QueryOp::SteVecSelector,
            Self::SteVecValueSelector => QueryOp::SteVecValueSelector,
            Self::SteVecTerm => QueryOp::SteVecTerm,
        }
    }
}

impl fmt::Display for QueryOpName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for QueryOpName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::from_wire(&raw).ok_or_else(|| {
            let accepted = Self::ALL
                .iter()
                .map(|op| format!("'{op}'"))
                .collect::<Vec<_>>()
                .join(", ");
            serde::de::Error::custom(format!(
                "{UNKNOWN_QUERY_OP_PREFIX} '{raw}'. Expected one of: {accepted}."
            ))
        })
    }
}

/// Which `ste_vec` query operation an [`crate::Error::InvalidQueryInput`] is
/// about.
///
/// Every site that raises that error is on an `ste_vec` path — the other index
/// types have no shape for the input to be wrong in — so the name carries the
/// `ste_vec` and the variants do not repeat it.
///
/// Separate from [`QueryOpName`] because it is not the wire vocabulary:
/// [`Self::Default`] names an operation the caller never spelled, inferred from
/// an `ste_vec` index plus the plaintext type. Reusing `QueryOpName` here would
/// put a value in the message that the caller cannot pass back.
///
/// `pub` rather than `pub(crate)` because it is reachable through that public
/// error variant.
#[derive(Debug, Clone, Copy)]
pub enum SteVecQueryOpKind {
    Term,
    ValueSelector,
    /// The inferred default — no wire spelling, hence the parenthetical below.
    Default,
}

impl fmt::Display for SteVecQueryOpKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Term => f.write_str(QueryOpName::SteVecTerm.as_str()),
            Self::ValueSelector => f.write_str(QueryOpName::SteVecValueSelector.as_str()),
            Self::Default => f.write_str("ste_vec (default)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(value: serde_json::Value) -> Result<QueryOpName, serde_json::Error> {
        serde_json::from_value(value)
    }

    #[test]
    fn the_wire_vocabulary_matches_the_typescript_union() {
        // `QueryOpName` in src/types.ts. Spelled out rather than derived from
        // ALL, so adding a variant fails here until the union is updated too —
        // the wasm entry declares that union to its callers.
        let spellings: Vec<&str> = QueryOpName::ALL.iter().map(|op| op.as_str()).collect();
        assert_eq!(
            spellings,
            [
                "default",
                "ste_vec_selector",
                "ste_vec_value_selector",
                "ste_vec_term",
            ]
        );
    }

    #[test]
    fn every_accepted_spelling_round_trips() {
        for op in QueryOpName::ALL {
            let parsed = parse(serde_json::json!(op.as_str())).expect("should deserialize");
            assert_eq!(parsed, op, "round-tripping {op}");
        }
    }

    #[test]
    fn each_name_maps_to_its_library_counterpart() {
        // The one place the two vocabularies are tied together. `QueryOp` has
        // no PartialEq, hence `matches!`.
        assert!(matches!(
            QueryOpName::Default.to_query_op(),
            QueryOp::Default
        ));
        assert!(matches!(
            QueryOpName::SteVecSelector.to_query_op(),
            QueryOp::SteVecSelector
        ));
        assert!(matches!(
            QueryOpName::SteVecValueSelector.to_query_op(),
            QueryOp::SteVecValueSelector
        ));
        assert!(matches!(
            QueryOpName::SteVecTerm.to_query_op(),
            QueryOp::SteVecTerm
        ));
    }

    #[test]
    fn omitting_query_op_means_default() {
        // `#[serde(default)]` on the options structs relies on this, and
        // `queryOp` is optional in the TypeScript declarations.
        assert_eq!(QueryOpName::default(), QueryOpName::Default);
    }

    #[test]
    fn an_unknown_value_keeps_the_prefix_the_error_routing_matches() {
        // `Error::unknown_query_op` matches this prefix to route the failure to
        // the variant carrying UNKNOWN_QUERY_OP — serde's `de::Error::custom`
        // takes a `Display`, so the message is all that survives. If this
        // assertion fails, that code has silently become unreachable.
        //
        // Was `src/errors.ts` doing the match until #146 moved it into Rust.
        let err = parse(serde_json::json!("frobnicate"))
            .expect_err("an unknown op is an error")
            .to_string();
        assert!(err.starts_with(UNKNOWN_QUERY_OP_PREFIX), "got: {err}");
        assert_eq!(UNKNOWN_QUERY_OP_PREFIX, "Unknown query operation:");
    }

    #[test]
    fn an_unknown_value_lists_what_is_accepted() {
        let err = parse(serde_json::json!("ste_vec_selecter"))
            .expect_err("an unknown op is an error")
            .to_string();
        assert!(err.contains("ste_vec_selecter"), "names the input: {err}");
        for op in QueryOpName::ALL {
            assert!(err.contains(op.as_str()), "lists {op}: {err}");
        }
    }

    #[test]
    fn a_non_string_query_op_is_rejected() {
        // The old `String` field rejected these too, but with serde's message.
        // Worth pinning: `queryOp: null` is what `{queryOp: opts.queryOp}` with
        // an undefined `queryOp` becomes on the wasm boundary, and it must not
        // silently read as "default".
        for value in [
            serde_json::json!(null),
            serde_json::json!(7),
            serde_json::json!(["default"]),
        ] {
            assert!(parse(value.clone()).is_err(), "should reject {value}");
        }
    }

    #[test]
    fn ste_vec_query_op_kind_displays_the_wire_spelling_where_one_exists() {
        // Shares `QueryOpName::as_str`, so an error message cannot name an
        // operation using a spelling the caller could not pass back.
        assert_eq!(SteVecQueryOpKind::Term.to_string(), "ste_vec_term");
        assert_eq!(
            SteVecQueryOpKind::ValueSelector.to_string(),
            "ste_vec_value_selector"
        );
        // The exception: no wire spelling, because the caller never wrote it.
        assert_eq!(SteVecQueryOpKind::Default.to_string(), "ste_vec (default)");
    }
}
