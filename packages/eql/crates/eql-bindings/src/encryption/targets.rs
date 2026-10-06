//! EQL types as plan field targets, by name.
//!
//! A Rust caller names an EQL type as a type: `encrypt_as::<TextEq>` runs the
//! plan `TextEq`'s own `EncryptFrom` describes. A binding has no type to
//! name — its plan arrives as data, and a field of that plan names its target
//! as a string, `"TextEq"`. This module is where that string meets the type:
//! a catalog-generated table of every EQL type a plan may name
//! ([`targets`], [`Target`]) and three entry points ([`encrypt`],
//! [`decrypt`], [`query`]) that dispatch on the name and run *the same plan*
//! the typed call runs. Nothing here derives a term or seals a byte itself
//! (ADR-0007: one engine, entered through a plan); the dispatch is generated
//! from `eql-domains::CATALOG` by `eql-codegen` into
//! [`crate::v3::targets`], beside the inventory, so a type cannot be in the
//! catalog and missing from the table.
//!
//! The guest build that holds the EQL types links this module; the build
//! without them has no `eql-bindings` and refuses a target name before
//! reaching here.
//!
//! # Wire format: the target table
//!
//! [`targets`] is what a guest serializes for its `se_targets` export, so a
//! generator (`stashgen`) can ask the engine it embeds which EQL types it
//! holds instead of carrying a copy of the rules. The JSON of one entry, with
//! every field always present:
//!
//! ```json
//! {
//!   "name": "TextEq",
//!   "family": "text",
//!   "suffix": "Eq",
//!   "plaintext": "string",
//!   "sql_domain": "public.eql_v3_text_eq",
//!   "indexes": ["eq"],
//!   "query": "TextEqQuery",
//!   "query_sql_domain": "eql_v3.query_text_eq",
//!   "producible": true,
//!   "reason": null
//! }
//! ```
//!
//! | field | meaning |
//! |---|---|
//! | `name` | The type's name, one across Rust, TypeScript and Go: the catalog struct identifier. The data plan's target form names this. (Go spells the `Json` family's types `JSON`; that rename is the Go generator's.) |
//! | `family` | The catalog family, lower case: `text`, `integer`, `json`, … |
//! | `suffix` | What a query can do, as the plan's table of suffixes spells it: `""` (stored and read only), `Eq`, `Ord`, `OrdOpe`, `OrdOre`, `Match`, `Search`, `SearchOre`; `Search` for the SteVec document. |
//! | `plaintext` | The vitaminc [`ValueKind`] name the type is produced from — the same names a plan field's `"type"` key uses — or `null` while the family's plaintext encoding for the stack-encrypt producer profile is unspecified. |
//! | `sql_domain` | The schema-qualified PostgreSQL domain the stored value inhabits. |
//! | `indexes` | The indexes the type carries, by the engine's `IndexSpec::key()` names: `eq`, `match`, `ore`, `ope`, and `json` for the SteVec document. A query may ask a field typed with this target for exactly these. |
//! | `query` | The query twin's type name (`TextEqQuery`, `SteVecQuery`), or `null` for a storage-only type, which answers no query. |
//! | `query_sql_domain` | The query twin's PostgreSQL domain, `null` likewise. |
//! | `producible` | Whether the engine can produce this type today. [`encrypt`] and [`query`] refuse a type that is not, and a generator should too. |
//! | `reason` | Why not, when `producible` is `false`; `null` when it is. |
//!
//! The table has one row per stored domain in catalog order; query twins are
//! not rows (each row names its own). Adding a field is a wire change for
//! every reader of `se_targets`; renaming or removing one is a breaking one.
//!
//! # What crosses: bytes
//!
//! [`encrypt`] and [`query`] resolve to the EQL value as **JSON bytes** — the
//! bytes PostgreSQL stores or compares — and [`decrypt`] takes them back.
//! The [`Pending`] they return is the engine's own request carrier: the guest
//! zips it with the other fields' pendings so one plan still makes one
//! ZeroKMS request. A query derives no key, so its pending settles without
//! I/O, but it is a `Pending` all the same, for one shape at the call site.
//!
//! # The field's context
//!
//! A plan field's context is a [`Label`]; an EQL value stores an
//! [`Identifier`], table and column. The two are the same context when the
//! label has two segments ([`Identifier::from_label`]): `users/email` is
//! `{"t": "users", "c": "email"}`, sealed under the same AAD, bound to the
//! same ZeroKMS descriptor and deriving the same equality term as the typed
//! `encrypt_as::<TextEq>` call with `Identifier::for_column("users",
//! "email")`. A label of any other length is refused: there is no column to
//! store it in.

use std::fmt;

use serde::{de::DeserializeOwned, Serialize};
use stack_encrypt::kms::MaybeSend;
use stack_encrypt::target::ExpectedContext;
use stack_encrypt::{
    DecryptInto, EncryptFrom, Error, KeysetCipher, Label, NonEmpty, Pending, StackCipher,
};
use vitaminc_aead_value::{FfiValue, ValueKind};

use crate::v3::targets::{decrypt_named, encrypt_named, query_named, TARGETS};
use crate::Identifier;

/// One EQL type a plan may name as a field target: a row of [`targets`].
///
/// The fields are the wire format of the `se_targets` export; the module
/// documentation is their reference. Every value is a `&'static str` or a
/// slice of them because the whole table is a `const` generated from the
/// catalog.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub struct Target {
    /// The type's name across languages: `TextEq`.
    pub name: &'static str,
    /// The catalog family: `text`.
    pub family: &'static str,
    /// The query-capability suffix: `Eq`; empty for a storage-only type.
    pub suffix: &'static str,
    /// The [`ValueKind`] name of the plaintext this type is produced from,
    /// or `None` while the family's encoding is unspecified. See
    /// [`plaintext_kind`](Self::plaintext_kind) for the parsed kind.
    pub plaintext: Option<&'static str>,
    /// The stored value's PostgreSQL domain: `public.eql_v3_text_eq`.
    pub sql_domain: &'static str,
    /// The indexes the type carries, by `IndexSpec::key()` name.
    pub indexes: &'static [&'static str],
    /// The query twin's type name, or `None` for a storage-only type.
    pub query: Option<&'static str>,
    /// The query twin's PostgreSQL domain, or `None` likewise.
    pub query_sql_domain: Option<&'static str>,
    /// Whether the engine produces this type today.
    pub producible: bool,
    /// Why it does not, when it does not.
    pub reason: Option<&'static str>,
}

impl Target {
    /// The plaintext kind, parsed. `None` when the table records none; the
    /// table is generated from names vitaminc freezes, so a recorded name
    /// always parses, and a `None` here means the same as a `None` in
    /// [`plaintext`](Self::plaintext).
    pub fn plaintext_kind(&self) -> Option<ValueKind> {
        self.plaintext.and_then(|name| name.parse().ok())
    }
}

/// Every EQL type a plan may name as a target, in catalog order — the
/// `se_targets` export, as data. See the module documentation for the wire
/// format.
pub fn targets() -> &'static [Target] {
    TARGETS
}

/// The target of this name, or `None` when no EQL type has it. The name is
/// matched exactly: `"TextEq"`, not `"texteq"` or `"text_eq"`.
pub fn target(name: &str) -> Option<&'static Target> {
    TARGETS.iter().find(|target| target.name == name)
}

/// Why a name could not be resolved to a plan, or a value could not be
/// handed to one.
///
/// Every variant is decided before any key is minted or retrieved: these
/// are statements about the name, the context or the value. The encryption
/// itself failing arrives through the returned [`Pending`] as a
/// [`stack_encrypt::Error`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TargetError {
    /// No EQL type has this name.
    #[error("no such EQL type: {name}")]
    Unknown {
        /// The name as it was given.
        name: String,
    },
    /// The type exists, and the engine cannot produce it yet; [`Target::reason`]
    /// says why.
    #[error("the engine cannot produce {name} yet: {reason}")]
    Unproducible {
        /// The type's name.
        name: &'static str,
        /// The table's reason.
        reason: &'static str,
    },
    /// The field's context is not an EQL column: an [`Identifier`] is a
    /// two-segment label, table then column, and this label is not one.
    #[error("{label:?} is not an EQL column identifier: expected two segments, table and column")]
    Context {
        /// The label, rendered.
        label: String,
    },
    /// The value is not of the type's plaintext kind. Nothing is converted:
    /// the stored bytes must be the declared kind's, and a conversion here
    /// would make them something else.
    #[error(
        "{target} is produced from a {expected} plaintext, not {}",
        found.map_or("a value with no kind", ValueKind::name)
    )]
    Plaintext {
        /// The type the value was handed to.
        target: &'static str,
        /// The kind it takes.
        expected: ValueKind,
        /// The kind it was given, or `None` for a null, undefined or
        /// passthrough value, which no kind holds.
        found: Option<ValueKind>,
    },
    /// The stored bytes do not parse as the type: not JSON, not this
    /// domain's shape, or another EQL version.
    #[error("stored value is not a {target}: {source}")]
    Stored {
        /// The type the bytes were read as.
        target: &'static str,
        /// What the parser refused.
        #[source]
        source: serde_json::Error,
    },
}

/// Which cipher [`decrypt`] opens through: the client, which opens a value
/// sealed under any of its keysets, or one keyset, which refuses a value
/// sealed under another ([`stack_encrypt::Error::ForeignKeyset`]) before any
/// key is retrieved. The runtime form of the engine's scope, for a caller
/// who chooses at runtime; a typed caller chooses by naming the cipher.
/// Both references convert into it, so a call site passes either.
pub enum Opener<'a, K> {
    /// Values from any keyset the client holds.
    Client(&'a StackCipher<K>),
    /// Values from this keyset only.
    Keyset(&'a KeysetCipher<'a, K>),
}

// By hand so `K: Debug` is not demanded: neither cipher demands it of its
// own `Debug`.
impl<K> fmt::Debug for Opener<'_, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Opener::Client(cipher) => f.debug_tuple("Client").field(cipher).finish(),
            Opener::Keyset(keyset) => f.debug_tuple("Keyset").field(keyset).finish(),
        }
    }
}

impl<'a, K> From<&'a StackCipher<K>> for Opener<'a, K> {
    fn from(cipher: &'a StackCipher<K>) -> Self {
        Opener::Client(cipher)
    }
}

impl<'a, K> From<&'a KeysetCipher<'a, K>> for Opener<'a, K> {
    fn from(keyset: &'a KeysetCipher<'a, K>) -> Self {
        Opener::Keyset(keyset)
    }
}

impl Identifier {
    /// The column a plan field's context names: a two-segment label, table
    /// then column, as the identifier the value stores and is sealed under.
    /// The same context as the label itself — see the module documentation.
    ///
    /// # Errors
    ///
    /// [`TargetError::Context`] for a label of any other length.
    pub fn from_label(label: &Label) -> Result<NonEmpty<Self>, TargetError> {
        let context = || TargetError::Context {
            label: label.to_string(),
        };
        let mut segments = label.segments();
        let (Some(table), Some(column), None) = (segments.next(), segments.next(), segments.next())
        else {
            return Err(context());
        };
        // A label segment is plain, so never empty; the `Err` arm is the
        // type's, not a case this function can reach.
        Identifier::for_column(table, column).map_err(|_| context())
    }
}

/// Run the named type's own encryption plan for one plan field.
///
/// `context` is the field's label, which must name a column (see
/// [`Identifier::from_label`]); `plaintext` must be of the type's plaintext
/// kind ([`Target::plaintext`]). The result settles to the EQL value's JSON
/// bytes, and merges with other pendings into one ZeroKMS request.
///
/// # Errors
///
/// [`TargetError::Unknown`] for a name no EQL type has,
/// [`TargetError::Unproducible`] for one the engine cannot produce yet,
/// [`TargetError::Context`] for a label that is not a column, and
/// [`TargetError::Plaintext`] for a value of another kind. All decided before
/// any key is minted; the encryption itself fails through the pending.
pub fn encrypt<'a, K: 'static>(
    name: &str,
    keyset: &'a KeysetCipher<'_, K>,
    context: &Label,
    plaintext: FfiValue,
) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
    producible(name)?;
    let column = Identifier::from_label(context)?;
    encrypt_named(name, keyset, column, plaintext)
}

/// Open a stored value of the named type back to its plaintext, checking
/// that it was stored under `context`'s column.
///
/// # Errors
///
/// [`TargetError::Unknown`], [`TargetError::Unproducible`] and
/// [`TargetError::Context`] as for [`encrypt`], and [`TargetError::Stored`]
/// for bytes that are not this type. A stored identifier that differs from
/// `context`, a value sealed under a keyset the opener does not hold, and a
/// failed authentication all fail through the pending.
pub fn decrypt<'a, K: 'static>(
    name: &str,
    opener: impl Into<Opener<'a, K>>,
    context: &Label,
    stored: &[u8],
) -> Result<Pending<'a, FfiValue, K>, TargetError> {
    producible(name)?;
    let column = Identifier::from_label(context)?;
    decrypt_named(name, opener.into(), column, stored)
}

/// Run the named type's query twin for one plaintext: the operand that
/// matches stored values of the type under `context`'s column, as JSON
/// bytes. A query derives no data key, so the pending settles without I/O.
///
/// # Errors
///
/// As [`encrypt`].
pub fn query<'a, K: 'static>(
    name: &str,
    keyset: &'a KeysetCipher<'_, K>,
    context: &Label,
    plaintext: FfiValue,
) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
    producible(name)?;
    let column = Identifier::from_label(context)?;
    query_named(name, keyset, column, plaintext)
}

/// Refuse a name the dispatch has no arm for, as the table explains it.
fn producible(name: &str) -> Result<(), TargetError> {
    match target(name) {
        Some(target) if target.producible => Ok(()),
        _ => Err(refuse(name)),
    }
}

/// The error for a name without a dispatch arm: unproducible when the table
/// has it, unknown otherwise. Called by the generated dispatch's fall-through.
pub(crate) fn refuse(name: &str) -> TargetError {
    match target(name) {
        Some(target) => TargetError::Unproducible {
            name: target.name,
            // A producible type reaching here is a generator bug: the table
            // says yes and the dispatch has no arm. Say so rather than panic.
            reason: target
                .reason
                .unwrap_or("the generated dispatch has no arm for this type"),
        },
        None => TargetError::Unknown {
            name: name.to_owned(),
        },
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for String {}
}

/// A Rust plaintext an EQL type is produced from, read out of and written
/// back into the runtime value. Sealed: the implementations are exactly the
/// plaintext types the catalog's producible families name, and the generated
/// dispatch picks one per type.
pub trait Plaintext: sealed::Sealed + Sized + MaybeSend + 'static {
    /// The kind of value this plaintext is.
    const KIND: ValueKind;
    /// Read the value as this plaintext, refusing any other kind.
    fn from_value(target: &'static str, value: FfiValue) -> Result<Self, TargetError>;
    /// The opened plaintext, as the runtime value.
    fn into_value(self) -> FfiValue;
}

impl Plaintext for String {
    const KIND: ValueKind = ValueKind::String;

    fn from_value(target: &'static str, value: FfiValue) -> Result<Self, TargetError> {
        let refused = |found| TargetError::Plaintext {
            target,
            expected: Self::KIND,
            found,
        };
        match value {
            // The bytes are UTF-8 by `Utf8String`'s construction invariant;
            // checked rather than assumed because this is boundary code. One
            // that fails the check is a string in name only, so it is
            // reported as the bytes it is.
            FfiValue::String(text) => std::str::from_utf8(text.risky_ref())
                .map(str::to_owned)
                .map_err(|_| refused(Some(ValueKind::Bytes))),
            other => Err(refused(other.kind())),
        }
    }

    fn into_value(self) -> FfiValue {
        FfiValue::String(self.into())
    }
}

/// Run a target's own plan over one runtime value and resolve to the EQL
/// value's JSON bytes. The generated dispatch calls this with the type and
/// its plaintext; it is the one place the typed `encrypt_as` is reached from
/// a name.
pub(crate) fn run_target<'a, T, S, K>(
    name: &'static str,
    keyset: &'a KeysetCipher<'_, K>,
    column: NonEmpty<Identifier>,
    plaintext: FfiValue,
) -> Result<Pending<'a, Vec<u8>, K>, TargetError>
where
    T: EncryptFrom<S, Context = NonEmpty<Identifier>> + Serialize,
    S: Plaintext,
    K: 'static,
{
    let plaintext = S::from_value(name, plaintext)?;
    Ok(keyset
        .encrypt_as::<S, T>(&plaintext, column)
        .try_map(|value| serde_json::to_vec(&value).map_err(|error| Error::Other(Box::new(error)))))
}

/// Parse a stored EQL value as the target and describe opening it through
/// the target's own `DecryptInto`, under the column the caller expects.
pub(crate) fn open_target<'a, T, S, K>(
    name: &'static str,
    opener: Opener<'a, K>,
    column: NonEmpty<Identifier>,
    stored: &[u8],
) -> Result<Pending<'a, FfiValue, K>, TargetError>
where
    T: DeserializeOwned + DecryptInto<S, Context = ExpectedContext<Identifier>> + 'static,
    S: Plaintext,
    K: 'static,
{
    let value: T = serde_json::from_slice(stored).map_err(|source| TargetError::Stored {
        target: name,
        source,
    })?;
    let decryption = value.decryption::<K>(column.into()).map(S::into_value);
    Ok(match opener {
        Opener::Client(cipher) => cipher.run_decryption(decryption),
        Opener::Keyset(keyset) => keyset.run_decryption(decryption),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn label(segments: &[&str]) -> Label {
        Label::new(segments).unwrap()
    }

    #[test]
    fn a_two_segment_label_is_the_column_identifier() {
        let column = Identifier::from_label(&label(&["users", "email"])).unwrap();
        assert_eq!(column.clone().into_inner().t, "users");
        assert_eq!(column.into_inner().c, "email");
    }

    #[test]
    fn a_label_of_any_other_length_is_not_a_column() {
        for segments in [&["users"][..], &["tenant", "users", "email"][..]] {
            let error = Identifier::from_label(&label(segments)).unwrap_err();
            assert!(
                matches!(&error, TargetError::Context { label: l } if l == &segments.join("/")),
                "{segments:?}: {error}"
            );
        }
    }

    #[test]
    fn the_table_is_catalog_ordered_and_names_each_type_once() {
        let names: Vec<&str> = targets().iter().map(|t| t.name).collect();
        let mut unique = names.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            names.len(),
            "a name resolves one type: {names:?}"
        );
        assert_eq!(
            target("TextEq").map(|t| t.sql_domain),
            Some("public.eql_v3_text_eq")
        );
        assert_eq!(target("texteq"), None, "names match exactly");
        for t in targets() {
            assert_eq!(
                t.producible,
                t.reason.is_none(),
                "{}: a reason exactly when not producible",
                t.name
            );
            assert_eq!(
                t.plaintext_kind().is_some(),
                t.plaintext.is_some(),
                "{}: a recorded plaintext name is a vitaminc kind",
                t.name
            );
        }
    }

    #[test]
    fn refusals_name_the_type_and_its_reason() {
        assert!(matches!(refuse("Nope"), TargetError::Unknown { name } if name == "Nope"));
        assert!(matches!(
            refuse("TextOrdOre"),
            TargetError::Unproducible { name: "TextOrdOre", reason } if reason.contains("CLLW")
        ));
        assert!(producible("TextEq").is_ok());
    }

    #[test]
    fn a_string_plaintext_is_read_exactly_and_nothing_else_is_converted() {
        let text = String::from_value("TextEq", FfiValue::String("café".into())).unwrap();
        assert_eq!(text, "café");
        assert!(matches!(
            String::from_value("TextEq", FfiValue::UInt64(34)),
            Err(TargetError::Plaintext {
                target: "TextEq",
                expected: ValueKind::String,
                found: Some(ValueKind::UInt64)
            })
        ));
        let error = String::from_value("TextEq", FfiValue::Null).unwrap_err();
        assert!(matches!(error, TargetError::Plaintext { found: None, .. }));
        assert_eq!(
            error.to_string(),
            "TextEq is produced from a string plaintext, not a value with no kind"
        );
        assert!(matches!(
            String::from("x").into_value(),
            FfiValue::String(s) if s.risky_ref() == b"x"
        ));
    }
}
