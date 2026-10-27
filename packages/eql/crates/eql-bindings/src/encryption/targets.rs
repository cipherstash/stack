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
//! [`crate::v4::targets`], beside the v4 family modules, so a type cannot be in the
//! catalog and missing from the table.
//!
//! This module needs the `targets` feature, which also turns on Stack
//! Encrypt's `dynamic` feature. The `stack-encrypt` feature alone gives only
//! the typed EQL v4 types.
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
//!   "sql_domain": "public.eql_v4_text_eq",
//!   "indexes": ["eq"],
//!   "query": "TextEqQuery",
//!   "query_sql_domain": "eql_v4.query_text_eq",
//!   "producible": true,
//!   "reason": null
//! }
//! ```
//!
//! | field | meaning |
//! |---|---|
//! | `name` | The type's name, one across Rust, TypeScript and Go: the catalog struct identifier. The data plan's target form names this. (Go spells the `Json` family's types `JSON`; that rename is the Go generator's.) |
//! | `family` | The catalog family, lower case: `text`, `integer`, `json`, … |
//! | `suffix` | What a query can do, as the plan's table of suffixes spells it: `""` (stored and read only), `Eq`, `Ord`, `OrdOpe`, `OrdOre`, `Match`, `Search`, `SearchOre`; `""` too for a document family's stored type, whose queries are the JSON index's operators. |
//! | `plaintext` | The vitaminc [`ValueKind`] name the type is produced from — the same names a plan field's `"type"` key uses — or `null` while the family's plaintext encoding for the stack-encrypt producer profile is unspecified. |
//! | `sql_domain` | The schema-qualified PostgreSQL domain the stored value inhabits. |
//! | `indexes` | The indexes the type carries, by the engine's `IndexSpec::key()` names: `eq`, `match`, `ore`, `ope`, and `json` for a document family's stored type. A query may ask a field typed with this target for exactly these. |
//! | `query` | The query twin's type name (`TextEqQuery`, `JsonSearchQuery`), or `null` for a storage-only type, which answers no query. |
//! | `query_sql_domain` | The query twin's PostgreSQL domain, `null` likewise. |
//! | `producible` | Whether the engine can produce this type today. [`encrypt`] and [`query`] refuse a type that is not, and a generator should too. |
//! | `reason` | Why not, when `producible` is `false`; `null` when it is. |
//!
//! The engine adds an eleventh key, `operators`, when it lists the table:
//! the operators it answers for the type, computed from the row by its own
//! rules (`stack_encrypt::dynamic::TargetDescriptor`), so this table holds
//! none of them.
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
use stack_encrypt::dynamic::{TargetOptions, ValueFrame, ValueKind};
use stack_encrypt::json::JsonOptions;
use stack_encrypt::kms::MaybeSend;
use stack_encrypt::target::{ExpectedContext, IndexSpec};
use stack_encrypt::{
    Decrypt, DecryptInto, Encrypt, EncryptFrom, Error, KeysetCipher, Label, NonEmpty, Pending,
    StackCipher,
};

use crate::v4::targets::{decrypt_named, encrypt_named, query_named, TARGETS};
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
    /// The stored value's PostgreSQL domain: `public.eql_v4_text_eq`.
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

    /// The PostgreSQL domain of the type's ordering operand at a path, for
    /// a type that stores a JSON document (`JsonSearch`:
    /// `eql_v4.query_json_leaf`); `None` for every other type. Stack
    /// Encrypt binds an ordering at a path as it
    /// (`TargetDescriptor::with_leaf_query_sql_domain`).
    pub fn leaf_query_sql_domain(&self) -> Option<&'static str> {
        use crate::v4::DomainType;
        document(self.name).map(|_| crate::v4::json_tree::JsonTreeLeafQuery::sql_domain_static())
    }

    /// The options this type's match index is built under, for a type that
    /// carries one (`TextMatch`): [`EqlMatch`](super::EqlMatch)'s, the one
    /// match configuration every EQL type's filter is built under. `None`
    /// for a type with no match index. Stack Encrypt answers `matches`
    /// through the type with them, cutting the query's tokens for `verify`
    /// as the stored filter was cut.
    pub fn match_options(&self) -> Option<stack_encrypt::sem::MatchOptions> {
        use stack_encrypt::sem::MatchConfig;
        self.indexes
            .contains(&"match")
            .then(super::EqlMatch::options)
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
    /// The type is produced, and answers no query: a storage-only type has
    /// no query twin, so there is no operand to derive.
    #[error("{name} answers no query: it is a storage-only type")]
    NoQuery {
        /// The type's name.
        name: &'static str,
    },
    /// The type stores a JSON document, which is queried by operator
    /// (`contains`, `eq_at`, an ordering at a path, a read) from named
    /// inputs, not from one plaintext: Stack Encrypt derives those
    /// operands itself (`stack_encrypt::dynamic::query_term`).
    #[error("{name} is queried by a JSON operator, not by one plaintext")]
    DocumentQuery {
        /// The type's name.
        name: &'static str,
    },
    /// A query asked through an index the type does not carry
    /// ([`Target::indexes`]), so it has no term to derive.
    #[error("{name} carries no {index} index, so no query is answered through it")]
    NoIndex {
        /// The type's name.
        name: &'static str,
        /// The index asked for, by its `IndexSpec::key()`.
        index: &'static str,
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
    /// The value is not a JSON document by the engine's rules, for a type
    /// that stores one ([`stack_encrypt::json::parse_text`]). `code` is the
    /// engine's code for what was wrong, never a byte of the value.
    #[error("{target} stores a JSON document, and the value is not one: {source}")]
    Json {
        /// The type the value was handed to.
        target: &'static str,
        /// What was wrong.
        #[source]
        source: stack_encrypt::dynamic::JsonValueError,
    },
    /// Options were given to a type that takes none: a type takes the
    /// options of the index it carries, and only a type that stores a
    /// JSON document carries one with options.
    #[error("{name} takes no options")]
    Options {
        /// The type's name.
        name: &'static str,
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
        Identifier::column_of(label).ok_or_else(|| TargetError::Context {
            label: label.to_string(),
        })
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
    plaintext: ValueFrame,
) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
    encrypt_with(name, None, keyset, context, plaintext)
}

/// [`encrypt`], under the options the plan gives the field
/// ([`TargetOptions`]): a type that stores a JSON document
/// (`JsonSearch`) seals under the JSON index's options, the defaults
/// when `options` is `None`. Every other type takes none.
///
/// # Errors
///
/// As [`encrypt`], [`TargetError::Options`] for options a type does not
/// take, and [`TargetError::Json`] for a value that is not a JSON document
/// by the engine's rules, for a type that stores one.
pub fn encrypt_with<'a, K: 'static>(
    name: &str,
    options: Option<&TargetOptions>,
    keyset: &'a KeysetCipher<'_, K>,
    context: &Label,
    plaintext: ValueFrame,
) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
    producible(name)?;
    let column = Identifier::from_label(context)?;
    if let Some(document) = document(name) {
        let options = match options {
            None => JsonOptions::default(),
            Some(options) => options.json().cloned().ok_or(TargetError::Options {
                name: document.name,
            })?,
        };
        return encrypt_document(document.name, &options, keyset, column, &plaintext);
    }
    if let Some(target) = options.and(target(name)) {
        return Err(TargetError::Options { name: target.name });
    }
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
) -> Result<Pending<'a, ValueFrame, K>, TargetError> {
    producible(name)?;
    let column = Identifier::from_label(context)?;
    if let Some(document) = document(name) {
        return decrypt_document(document.name, opener.into(), column, stored);
    }
    decrypt_named(name, opener.into(), column, stored)
}

/// The stored domain of a document family (`eql-domains`'
/// `DOCUMENT_FAMILIES`), when `name` is one's target: a type the generated
/// dispatch has no arm for, whose plan is the JSON index's, under options.
fn document(name: &str) -> Option<&'static Target> {
    target(name).filter(|target| crate::v4::targets::DOCUMENT_FAMILIES.contains(&target.family))
}

/// Seal one `JsonSearch` value: the document the field's text holds,
/// parsed by the engine's rules, laid out by the JSON index under
/// `options`, under the column. The parsed document is wiped when this
/// returns; the pending has taken what it seals.
fn encrypt_document<'a, K: 'static>(
    name: &'static str,
    options: &JsonOptions,
    keyset: &'a KeysetCipher<'_, K>,
    column: NonEmpty<Identifier>,
    plaintext: &ValueFrame,
) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
    let document =
        stack_encrypt::dynamic::read_json(plaintext).map_err(|source| TargetError::Json {
            target: name,
            source,
        })?;
    Ok(keyset
        .run(
            stack_encrypt::target::Layout::<serde_json::Value>::encryption::<K>(
                &crate::v4::json_tree::JsonTree::new(options.clone()),
            ),
            document.value(),
            column,
        )
        .try_map(|value| serde_json::to_vec(&value).map_err(|error| Error::Other(Box::new(error)))))
}

/// Open one stored `JsonSearch` value to the document's text, checking
/// it was stored under the column.
fn decrypt_document<'a, K: 'static>(
    name: &'static str,
    opener: Opener<'a, K>,
    column: NonEmpty<Identifier>,
    stored: &[u8],
) -> Result<Pending<'a, ValueFrame, K>, TargetError> {
    use crate::v4::json_tree::JsonTreeDocument;
    let value: JsonTreeDocument =
        serde_json::from_slice(stored).map_err(|source| TargetError::Stored {
            target: name,
            source,
        })?;
    let expected: ExpectedContext<Identifier> = column.into();
    Ok(match opener {
        Opener::Client(cipher) => {
            cipher.decrypt_as::<serde_json::Value, JsonTreeDocument>(value, expected)
        }
        Opener::Keyset(keyset) => {
            keyset.decrypt_as::<serde_json::Value, JsonTreeDocument>(value, expected)
        }
    }
    .try_map(|mut document| {
        let frame = stack_encrypt::dynamic::json_frame(&document);
        stack_encrypt::json::wipe_value(&mut document);
        frame
    }))
}

/// Run the named type's query twin for one plaintext: the operand that
/// matches stored values of the type under `context`'s column, as JSON
/// bytes. A query derives no data key, so the pending settles without I/O.
///
/// `index` is the type's index that answers the query's operator, one of
/// [`Target::indexes`]; Stack Encrypt passes the one its
/// `OpSpec::answered_by` picks. Most twins carry every term of their type
/// whatever the index. `TextSearchQuery` carries the index's term alone
/// (EQL v4's search query terms are optional), so `=` and `<` on text too
/// short for a match term are answered, and `matches` on it is refused.
///
/// # Errors
///
/// As [`encrypt`], and [`TargetError::NoIndex`] for an index the type does
/// not carry.
pub fn query<'a, K: 'static>(
    name: &str,
    index: &IndexSpec,
    keyset: &'a KeysetCipher<'_, K>,
    context: &Label,
    plaintext: ValueFrame,
) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
    producible(name)?;
    let Some(target) = target(name) else {
        return Err(refuse(name));
    };
    if let Some(error) = no_query(Some(target)) {
        return Err(error);
    }
    carries(target, index)?;
    if document(name).is_some() {
        return Err(TargetError::DocumentQuery { name: target.name });
    }
    let column = Identifier::from_label(context)?;
    query_named(name, index, keyset, column, plaintext)
}

/// Refuse a query through an index the type does not carry.
fn carries(target: &'static Target, index: &IndexSpec) -> Result<(), TargetError> {
    match target.indexes.iter().find(|key| **key == index.key()) {
        Some(_) => Ok(()),
        None => Err(no_index(target.name, index)),
    }
}

/// The refusal for a query on `name` through an index it does not carry.
/// Also the generated query dispatch's fall-through for a twin built per
/// index.
pub(crate) fn no_index(name: &'static str, index: &IndexSpec) -> TargetError {
    TargetError::NoIndex {
        name,
        index: index.key(),
    }
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
/// The error for a query on a name the query dispatch has no arm for: a
/// producible type with no query twin answers no query; otherwise what
/// [`refuse`] says. Called by the generated query dispatch's fall-through.
pub(crate) fn refuse_query(name: &str) -> TargetError {
    no_query(target(name)).unwrap_or_else(|| refuse(name))
}

/// `NoQuery` for a producible type without a query twin, else `None`: the
/// one case the query dispatch refuses that the others do not.
fn no_query(target: Option<&'static Target>) -> Option<TargetError> {
    match target {
        Some(target) if target.producible && target.query.is_none() => {
            Some(TargetError::NoQuery { name: target.name })
        }
        _ => None,
    }
}

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
    impl Sealed for i16 {}
    impl Sealed for i32 {}
    impl Sealed for i64 {}
    impl Sealed for bool {}
    impl Sealed for f32 {}
    impl Sealed for f64 {}
    impl Sealed for crate::v4::plaintext::Date {}
    impl Sealed for crate::v4::plaintext::Timestamp {}
    impl Sealed for crate::v4::plaintext::Decimal {}
    impl<S: super::Plaintext> Sealed for Option<S> {}
}

/// A Rust plaintext an EQL type is produced from, read out of and written
/// back into the engine's runtime plaintext, a [`ValueFrame`]. Sealed: the
/// implementations are exactly the plaintext types the catalog's producible
/// families name, and the generated dispatch picks one per type.
/// `Zeroize`, because [`from_frame`](Self::from_frame) copies the plaintext
/// out of the frame's `Protected` buffer and the copy is wiped when it is
/// dropped (`run_target` holds it in [`zeroize::Zeroizing`]), as the frame
/// is.
pub trait Plaintext:
    sealed::Sealed + Decrypt + Sized + MaybeSend + zeroize::Zeroize + 'static
{
    /// The kind of value this plaintext is.
    const KIND: ValueKind;

    /// Read the value as this plaintext, refusing any other kind: the frame
    /// is walked into this type's own decrypt sink once its kind is checked,
    /// so nothing is narrowed or widened.
    fn from_frame(target: &'static str, value: &ValueFrame) -> Result<Self, TargetError> {
        let refused = || TargetError::Plaintext {
            target,
            expected: Self::KIND,
            found: value.kind(),
        };
        if value.kind() != Some(Self::KIND) {
            return Err(refused());
        }
        value.visit(Self::sink()).map_err(|_| refused())
    }

    /// The opened plaintext, as the engine's runtime plaintext.
    ///
    /// # Errors
    ///
    /// None for the plaintexts here, every one of which is in the engine's
    /// value model; the `Result` is the frame writer's.
    fn into_frame(self) -> Result<ValueFrame, Error>;
}

/// The frame of a plaintext, or the error a value vitaminc cannot write is.
fn frame_of(value: impl Encrypt) -> Result<ValueFrame, Error> {
    ValueFrame::of(value).map_err(|error| Error::Other(Box::new(error)))
}

impl Plaintext for String {
    const KIND: ValueKind = ValueKind::String;

    /// The frame is written from the opened text, which is wiped when this
    /// returns: the frame writer copies the text into its own `Protected`
    /// buffer, and the opened `String` would otherwise go back to the
    /// allocator with the plaintext still in it.
    fn into_frame(self) -> Result<ValueFrame, Error> {
        let text = zeroize::Zeroizing::new(self);
        frame_of(text.as_str())
    }
}

/// The scalar plaintexts read exactly their own kind: a JSON number is not
/// narrowed or widened into another width, because the stored bytes must be
/// the declared kind's.
macro_rules! scalar_plaintext {
    ($($ty:ident => $variant:ident),+ $(,)?) => {$(
        impl Plaintext for $ty {
            const KIND: ValueKind = ValueKind::$variant;

            fn into_frame(self) -> Result<ValueFrame, Error> {
                frame_of(self)
            }
        }
    )+};
}
scalar_plaintext!(
    i16 => Int16,
    i32 => Int32,
    i64 => Int64,
    bool => Bool,
    f32 => Float32,
    f64 => Float64,
);

/// The date, timestamp and decimal plaintexts read exactly their own kind,
/// and are range checked as they are read: a frame vitaminc's value model
/// admits is always in range, so the check refuses nothing a binding can
/// send. Each wipes itself on drop as well as inside `Zeroizing`.
mod logical {
    use super::*;
    use crate::v4::plaintext::{Date, Decimal, Timestamp};
    scalar_plaintext!(
        Date => Date,
        Timestamp => Timestamp,
        Decimal => Decimal,
    );
}

/// The plaintext of a type whose terms a null has (a storage-only type, or
/// one whose only term is equality's), which may be absent: what the
/// generated dispatch reads such a type's value as, opens it into and
/// queries it with. A null seals as `None`, a typed null of the plaintext's
/// type, as long as a value when the type is fixed width (vitaminc 0.8), and
/// opens as a null; a value seals and opens exactly as the plaintext does,
/// since `Some(v)` walks `v` itself. A null's equality term is the one every
/// null shares (vitaminc-normalize 0.8), which a query of a `None` derives
/// too. Whether a field may hold a null is the plan's to decide (its
/// `"null"`), not the type's.
impl<S: Plaintext> Plaintext for Option<S> {
    const KIND: ValueKind = S::KIND;

    fn from_frame(target: &'static str, value: &ValueFrame) -> Result<Self, TargetError> {
        if value.kind().is_some() {
            return S::from_frame(target, value).map(Some);
        }
        // No kind: a null, which reads as `None`, or something no plaintext
        // is (an `undefined`, a passthrough), refused as `S` refuses it.
        match value.visit(Self::sink()) {
            Ok(None) => Ok(None),
            _ => Err(TargetError::Plaintext {
                target,
                expected: Self::KIND,
                found: None,
            }),
        }
    }

    fn into_frame(self) -> Result<ValueFrame, Error> {
        match self {
            Some(value) => value.into_frame(),
            None => ValueFrame::from_bytes(&[stack_encrypt::dynamic::frame::tags::NULL])
                .map_err(|error| Error::Other(Box::new(error))),
        }
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
    plaintext: ValueFrame,
) -> Result<Pending<'a, Vec<u8>, K>, TargetError>
where
    T: EncryptFrom<S, Context = NonEmpty<Identifier>> + Serialize,
    S: Plaintext,
    K: 'static,
{
    // The copy lives only until `encrypt_as` has cloned what it seals, and
    // is wiped when this returns: the frame kept its bytes in `Protected`,
    // and the copy is held to the same rule.
    let plaintext = zeroize::Zeroizing::new(S::from_frame(name, &plaintext)?);
    Ok(keyset
        .encrypt_as::<S, T>(&plaintext, column)
        .try_map(|value| serde_json::to_vec(&value).map_err(|error| Error::Other(Box::new(error)))))
}

/// Run the plan of `P`, a projection of the query twin `Q` that carries one
/// term, and resolve to `Q`'s JSON bytes: the twin of a type whose query
/// terms are optional, holding only the term `P` derives. The generated
/// query dispatch picks `P` by the index that answers the query's operator.
pub(crate) fn run_projected<'a, P, Q, S, K>(
    name: &'static str,
    keyset: &'a KeysetCipher<'_, K>,
    column: NonEmpty<Identifier>,
    plaintext: ValueFrame,
) -> Result<Pending<'a, Vec<u8>, K>, TargetError>
where
    P: EncryptFrom<S, Context = NonEmpty<Identifier>> + Into<Q>,
    Q: Serialize,
    S: Plaintext,
    K: 'static,
{
    // Wiped when this returns, as in `run_target`.
    let plaintext = zeroize::Zeroizing::new(S::from_frame(name, &plaintext)?);
    Ok(keyset
        .encrypt_as::<S, P>(&plaintext, column)
        .try_map(|value| {
            let query: Q = value.into();
            serde_json::to_vec(&query).map_err(|error| Error::Other(Box::new(error)))
        }))
}

/// Parse a stored EQL value as the target and describe opening it through
/// the target's own `DecryptInto`, under the column the caller expects.
pub(crate) fn open_target<'a, T, S, K>(
    name: &'static str,
    opener: Opener<'a, K>,
    column: NonEmpty<Identifier>,
    stored: &[u8],
) -> Result<Pending<'a, ValueFrame, K>, TargetError>
where
    T: DeserializeOwned + DecryptInto<S, Context = ExpectedContext<Identifier>> + 'static,
    S: Plaintext,
    K: 'static,
{
    let value: T = serde_json::from_slice(stored).map_err(|source| TargetError::Stored {
        target: name,
        source,
    })?;
    // `decrypt_as`, not `run_decryption`: this crate compiles against the
    // crates.io stack-encrypt its manifest names (0.2.0), which has the
    // typed call and not the by-value runner. Same plan, same pending.
    let expected: ExpectedContext<Identifier> = column.into();
    Ok(match opener {
        Opener::Client(cipher) => cipher.decrypt_as::<S, T>(value, expected),
        Opener::Keyset(keyset) => keyset.decrypt_as::<S, T>(value, expected),
    }
    .try_map(S::into_frame))
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
            Some("public.eql_v4_text_eq")
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
    fn a_producible_type_without_a_query_twin_answers_no_query() {
        // `Text` is producible and storage-only, so it has no query twin.
        assert!(matches!(
            no_query(target("Text")),
            Some(TargetError::NoQuery { name: "Text" })
        ));
        assert_eq!(
            refuse_query("Text").to_string(),
            "Text answers no query: it is a storage-only type"
        );
        assert!(
            no_query(target("TextEq")).is_none(),
            "TextEq answers a query"
        );
        assert!(
            no_query(target("Json")).is_none(),
            "an unproducible type without a query twin is refused as unproducible"
        );
        assert!(matches!(
            refuse_query("Json"),
            TargetError::Unproducible { .. }
        ));
        assert!(matches!(refuse_query("Nope"), TargetError::Unknown { .. }));
    }

    #[test]
    fn a_query_through_an_index_the_type_lacks_is_refused() {
        let text_eq = target("TextEq").unwrap();
        assert!(carries(text_eq, &IndexSpec::Equality).is_ok());
        let error = carries(text_eq, &IndexSpec::Ope).unwrap_err();
        assert!(
            matches!(
                error,
                TargetError::NoIndex {
                    name: "TextEq",
                    index: "ope"
                }
            ),
            "{error:?}"
        );
        assert_eq!(
            error.to_string(),
            "TextEq carries no ope index, so no query is answered through it"
        );
    }

    #[test]
    fn refusals_name_the_type_and_its_reason() {
        assert!(matches!(refuse("Nope"), TargetError::Unknown { name } if name == "Nope"));
        assert!(matches!(
            refuse("Json"),
            TargetError::Unproducible { name: "Json", reason } if reason.contains("a JSON value seals as a tree of leaves")
        ));
        assert!(producible("TextEq").is_ok());
        assert!(producible("TextOrdOre").is_ok());
        assert!(producible("DateOrdOre").is_ok());
    }

    fn frame<T: Encrypt>(value: T) -> ValueFrame {
        ValueFrame::of(value).unwrap()
    }

    #[test]
    fn a_string_plaintext_is_read_exactly_and_nothing_else_is_converted() {
        let text = String::from_frame("TextEq", &frame("café")).unwrap();
        assert_eq!(text, "café");
        assert!(matches!(
            String::from_frame("TextEq", &frame(34u64)),
            Err(TargetError::Plaintext {
                target: "TextEq",
                expected: ValueKind::String,
                found: Some(ValueKind::UInt64)
            })
        ));
        let error = String::from_frame("TextEq", &frame(None::<i32>)).unwrap_err();
        assert!(matches!(error, TargetError::Plaintext { found: None, .. }));
        assert_eq!(
            error.to_string(),
            "TextEq is produced from a string plaintext, not a value with no kind"
        );
        assert_eq!(
            String::from("x").into_frame().unwrap().risky_ref(),
            frame("x").risky_ref()
        );
    }

    /// A scalar plaintext reads its own kind and width only, and writes the
    /// frame of the value it holds.
    #[test]
    fn a_scalar_plaintext_is_read_at_its_own_width() {
        let read = i32::from_frame("IntegerEq", &frame(-7i32)).unwrap();
        assert_eq!(read, -7);
        assert!(matches!(
            i32::from_frame("IntegerEq", &frame(-7i64)),
            Err(TargetError::Plaintext {
                found: Some(ValueKind::Int64),
                ..
            })
        ));
        assert_eq!(
            9i64.into_frame().unwrap().risky_ref(),
            frame(9i64).risky_ref()
        );
    }
}
