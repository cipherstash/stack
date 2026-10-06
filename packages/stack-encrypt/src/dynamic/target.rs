//! EQL types as plan field targets: what the host that holds them installs.
//!
//! A data plan field may name an EQL type instead of its outputs
//! (`{"target": "TextEq", "context": [...]}`; see [`record::plan`]). The
//! engine knows no EQL type — `eql-bindings` depends on this crate, so this
//! crate cannot depend on it — and ADR-0007 (amended 2026-10-06) puts the
//! dispatch that resolves the name in the guest build that holds the EQL
//! types. This module is the seam: a [`TargetResolver`] the host installs,
//! which the lowering calls once per target field, and [`NoTargets`], the
//! resolver of a build without EQL types, which refuses every name.
//!
//! The resolver runs the named type's own plan (its `EncryptFrom` /
//! `DecryptInto`) and hands back the engine's [`Pending`], so a target field
//! settles in the same ZeroKMS request as the rest of the record: the
//! lowering zips it in. Nothing here derives a term or seals a byte; the
//! resolver reaches the engine through the typed call, as any Rust caller
//! does.
//!
//! # Wire format
//!
//! [`TargetDescriptor::to_value`] is the entry a guest's `se_targets` export
//! lists for each type; the keys are fixed on [`TargetDescriptor`], in the
//! crate that owns the data grammar, and `eql-bindings` is tested to spell
//! its table the same way.
//!
//! [`record::plan`]: super::record::plan()

use std::fmt;

use vitaminc_aead_value::{FfiValue, ValueKind};

use crate::{KeysetCipher, Label, Pending, StackCipher};

/// One EQL type a plan may name as a target, as the host describes it.
///
/// # Wire format
///
/// [`to_value`](Self::to_value) is the entry a guest's `se_targets` export
/// lists for each type, so a generator can ask the engine it embeds which
/// EQL types it holds. Every key is always present; an absent value is
/// null, never a missing key.
///
/// | key | value |
/// |---|---|
/// | `name` | string: the type's name across languages, `TextEq`; what a plan's `"target"` names |
/// | `family` | string: the catalog family, `text` |
/// | `suffix` | string: the query-capability suffix, `Eq`; empty for a storage-only type |
/// | `plaintext` | string or null: the [`ValueKind`] name the type is produced from — the same names a field's `"type"` key uses — or null while unspecified |
/// | `sql_domain` | string: the stored value's PostgreSQL domain |
/// | `indexes` | list of strings: the indexes the type carries, by `IndexSpec::key()`, plus `json` for a SteVec document |
/// | `query` | string or null: the query twin's type name |
/// | `query_sql_domain` | string or null: the query twin's PostgreSQL domain |
/// | `producible` | bool: whether the engine produces the type today |
/// | `reason` | string or null: why not, when it does not |
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct TargetDescriptor {
    /// The type's name across languages: `TextEq`.
    pub name: String,
    /// The catalog family: `text`.
    pub family: String,
    /// The query-capability suffix: `Eq`; empty for a storage-only type.
    pub suffix: String,
    /// The kind the type is produced from, or `None` while unspecified.
    pub plaintext: Option<ValueKind>,
    /// The stored value's PostgreSQL domain.
    pub sql_domain: String,
    /// The indexes the type carries, by `IndexSpec::key()` name.
    pub indexes: Vec<String>,
    /// The query twin's type name, or `None` for a storage-only type.
    pub query: Option<String>,
    /// The query twin's PostgreSQL domain, or `None` likewise.
    pub query_sql_domain: Option<String>,
    /// Whether the engine produces the type today.
    pub producible: bool,
    /// Why it does not, when it does not.
    pub reason: Option<String>,
}

impl TargetDescriptor {
    /// A descriptor with every field given. The one constructor, so a host
    /// cannot leave a wire field out.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: impl Into<String>,
        family: impl Into<String>,
        suffix: impl Into<String>,
        plaintext: Option<ValueKind>,
        sql_domain: impl Into<String>,
        indexes: Vec<String>,
        query: Option<String>,
        query_sql_domain: Option<String>,
        producible: bool,
        reason: Option<String>,
    ) -> Self {
        Self {
            name: name.into(),
            family: family.into(),
            suffix: suffix.into(),
            plaintext,
            sql_domain: sql_domain.into(),
            indexes,
            query,
            query_sql_domain,
            producible,
            reason,
        }
    }

    /// The descriptor in its wire form: the object a guest's `se_targets`
    /// lists, every key present (see [the type's wire format](Self#wire-format)).
    pub fn to_value(&self) -> FfiValue {
        let text = |s: &str| FfiValue::String(s.into());
        let optional = |s: &Option<String>| s.as_deref().map_or(FfiValue::Null, text);
        FfiValue::Object(vec![
            ("name".to_string(), text(&self.name)),
            ("family".to_string(), text(&self.family)),
            ("suffix".to_string(), text(&self.suffix)),
            (
                "plaintext".to_string(),
                self.plaintext
                    .map_or(FfiValue::Null, |kind| text(kind.name())),
            ),
            ("sql_domain".to_string(), text(&self.sql_domain)),
            (
                "indexes".to_string(),
                FfiValue::Array(self.indexes.iter().map(|k| text(k)).collect()),
            ),
            ("query".to_string(), optional(&self.query)),
            (
                "query_sql_domain".to_string(),
                optional(&self.query_sql_domain),
            ),
            ("producible".to_string(), FfiValue::Bool(self.producible)),
            ("reason".to_string(), optional(&self.reason)),
        ])
    }
}

/// Why a target field could not be resolved or run.
///
/// Every variant but [`Other`](Self::Other) is a statement about the plan,
/// the value or the stored bytes, decided before any key is minted or
/// retrieved; a binding maps them to its malformed-input status. `Other` is
/// the resolver's own failure.
///
/// A resolver writes the `reason` strings, so they are under the rule on
/// [`ErrorPayload`](crate::ErrorPayload) like everything else here: a
/// resolver says what it refused, never a byte of the value or the stored
/// ciphertext it refused.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[non_exhaustive]
pub enum TargetError {
    /// This build holds no EQL types: the plan names one, and only a build
    /// linked with them can run it.
    #[error("this build holds no EQL types; a plan cannot name {name} as a target")]
    #[diagnostic(code(stack_encrypt::target_none))]
    NoTargets {
        /// The name the plan gave.
        name: String,
    },
    /// No EQL type has this name.
    #[error("no such EQL type: {name}")]
    #[diagnostic(code(stack_encrypt::target_unknown))]
    Unknown {
        /// The name the plan gave.
        name: String,
    },
    /// The type exists and the engine cannot produce it yet.
    #[error("the engine cannot produce {name} yet: {reason}")]
    #[diagnostic(code(stack_encrypt::target_unproducible))]
    Unproducible {
        /// The type's name.
        name: String,
        /// The descriptor's reason.
        reason: String,
    },
    /// The type is produced and answers no query: a storage-only EQL type
    /// has no query twin, so a query on a field that names it derives
    /// nothing.
    #[error("{name} answers no query: it is a storage-only type")]
    #[diagnostic(code(stack_encrypt::target_no_query))]
    NoQuery {
        /// The type's name.
        name: String,
    },
    /// The plan extends every field's label by the caller's parts (a tenant,
    /// a region), and an EQL value stores a table and a column only: there
    /// is no column for the extended label. A plan with a target field is
    /// not extended.
    #[error(
        "{name}: an EQL value is stored under a table and a column, so the label {label} \
         cannot be extended by the caller's parts"
    )]
    #[diagnostic(code(stack_encrypt::target_extended))]
    Extended {
        /// The target field's name.
        name: String,
        /// The field's label, before the extension.
        label: String,
    },
    /// The plan takes its context from a field of each record (the
    /// plan-level `"context_field"`), so a field's label is its identity
    /// alone and the table is whatever each record names; an EQL value
    /// stores a table and a column fixed by the declaration. A plan with a
    /// target field has a context of its own.
    #[error(
        "{name}: an EQL value is stored under a table and a column, so a plan that takes \
         its context from its field {context_field} has no table for it"
    )]
    #[diagnostic(code(stack_encrypt::target_context_field))]
    ContextField {
        /// The target field's name.
        name: String,
        /// The field the plan takes its context from.
        context_field: String,
    },
    /// The field's declared `"type"` is not the kind the EQL type is
    /// produced from.
    #[error(
        "{name}: {target} is produced from a {} plaintext, and the field declares {declared}",
        expected.map_or("unspecified", ValueKind::name)
    )]
    #[diagnostic(
        code(stack_encrypt::target_kind),
        help("Declare the field's \"type\" as the kind the EQL type is produced from, or leave it out to take that kind.")
    )]
    Kind {
        /// The field's name.
        name: String,
        /// The EQL type.
        target: String,
        /// The kind the type takes.
        expected: Option<ValueKind>,
        /// The kind the field declared.
        declared: ValueKind,
    },
    /// The field's label is not a column the EQL type can be stored under.
    #[error("{name}: the label {label} is not an EQL column: {reason}")]
    #[diagnostic(code(stack_encrypt::target_column))]
    Column {
        /// The target field's name.
        name: String,
        /// The label.
        label: String,
        /// What the resolver said.
        reason: String,
    },
    /// The value is not of the type's plaintext kind.
    #[error(
        "{name}: {target} is produced from a {} plaintext, not {}",
        expected.map_or("unspecified", ValueKind::name),
        found.map_or("a value with no kind", ValueKind::name)
    )]
    #[diagnostic(code(stack_encrypt::target_plaintext))]
    Plaintext {
        /// The field's name.
        name: String,
        /// The EQL type.
        target: String,
        /// The kind the type takes.
        expected: Option<ValueKind>,
        /// The kind it was given, or `None` for a null, undefined or
        /// passthrough value.
        found: Option<ValueKind>,
    },
    /// The stored bytes are not a value of the type.
    #[error("{name}: the stored value is not a {target}: {reason}")]
    #[diagnostic(code(stack_encrypt::target_stored))]
    Stored {
        /// The field's name.
        name: String,
        /// The EQL type.
        target: String,
        /// What the parser refused.
        reason: String,
    },
    /// The resolver's own failure: a value that did not serialize, an
    /// invariant of the host's that did not hold. Its message is the
    /// resolver's, shown as given, so a resolver writes it under the rule on
    /// [`ErrorPayload`](crate::ErrorPayload).
    #[error(transparent)]
    #[diagnostic(code(stack_encrypt::target_other))]
    Other(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl crate::ErrorPayload for TargetError {
    fn payload(&self) -> serde_json::Map<String, serde_json::Value> {
        use crate::diagnostic::payload;
        let kind = |kind: &Option<ValueKind>| -> serde_json::Value {
            kind.map_or(serde_json::Value::Null, |kind| kind.name().into())
        };
        let mut fields = match self {
            Self::NoTargets { .. }
            | Self::Unknown { .. }
            | Self::NoQuery { .. }
            | Self::Other(_) => serde_json::Map::new(),
            Self::Unproducible { reason, .. } => payload([("reason", reason.as_str().into())]),
            Self::Extended { label, .. } => payload([("label", label.as_str().into())]),
            Self::ContextField { context_field, .. } => {
                payload([("context_field", context_field.as_str().into())])
            }
            Self::Kind {
                target,
                expected,
                declared,
                ..
            } => payload([
                ("target", target.as_str().into()),
                ("expected", kind(expected)),
                ("declared", declared.name().into()),
            ]),
            Self::Column { label, reason, .. } => payload([
                ("label", label.as_str().into()),
                ("reason", reason.as_str().into()),
            ]),
            Self::Plaintext {
                target,
                expected,
                found,
                ..
            } => payload([
                ("target", target.as_str().into()),
                ("expected", kind(expected)),
                ("found", kind(found)),
            ]),
            Self::Stored { target, reason, .. } => payload([
                ("target", target.as_str().into()),
                ("reason", reason.as_str().into()),
            ]),
        };
        // `name` is the target type for the first four, and the field for
        // the rest (the lowering fills it in): keep the two apart.
        match self {
            Self::NoTargets { name }
            | Self::Unknown { name }
            | Self::NoQuery { name }
            | Self::Unproducible { name, .. } => {
                let _ = fields.insert("target".to_owned(), name.as_str().into());
            }
            Self::Extended { name, .. }
            | Self::ContextField { name, .. }
            | Self::Kind { name, .. }
            | Self::Column { name, .. }
            | Self::Plaintext { name, .. }
            | Self::Stored { name, .. } => {
                if !name.is_empty() {
                    let _ = fields.insert("field".to_owned(), name.as_str().into());
                }
            }
            Self::Other(_) => {}
        }
        fields
    }
}

/// The EQL types a build holds, and how to run one.
///
/// A host installs one implementation: the guest build linked with the EQL
/// types implements it over `eql-bindings`' by-name dispatch; the build
/// without them installs [`NoTargets`]. The lowering
/// ([`record::encrypt_with`](super::record::encrypt_with) and its siblings)
/// calls it once per target field, with the field's label and value, and
/// zips the returned [`Pending`] into the record's.
///
/// The three operations take the field's **label** — the plan's context and
/// the field's identity, `users/email` — and never an extension: an EQL
/// value is stored under a table and a column, and
/// [`record::Plan`](super::record::Plan) refuses a plan that both extends and
/// names a target ([`TargetError::Extended`]).
pub trait TargetResolver {
    /// Every EQL type this build knows of, producible or not, in a fixed
    /// order: what `se_targets` lists.
    fn targets(&self) -> Vec<TargetDescriptor>;

    /// The descriptor of a type a plan may run: a name in
    /// [`targets`](Self::targets) whose `producible` is true.
    ///
    /// # Errors
    ///
    /// [`TargetError::NoTargets`] when this build holds none,
    /// [`TargetError::Unknown`] for a name no type has, and
    /// [`TargetError::Unproducible`] with the descriptor's reason.
    fn resolve(&self, name: &str) -> Result<TargetDescriptor, TargetError> {
        let targets = self.targets();
        if targets.is_empty() {
            return Err(TargetError::NoTargets {
                name: name.to_owned(),
            });
        }
        let descriptor = targets
            .into_iter()
            .find(|target| target.name == name)
            .ok_or_else(|| TargetError::Unknown {
                name: name.to_owned(),
            })?;
        if !descriptor.producible {
            return Err(TargetError::Unproducible {
                name: descriptor.name,
                reason: descriptor
                    .reason
                    .unwrap_or_else(|| "no reason recorded".to_owned()),
            });
        }
        Ok(descriptor)
    }

    /// Run the named type's own encryption plan over one value under
    /// `label`, resolving to the EQL value's JSON bytes.
    ///
    /// # Errors
    ///
    /// The refusals of [`resolve`](Self::resolve), [`TargetError::Column`]
    /// for a label that is not a column, and [`TargetError::Plaintext`] for a
    /// value of another kind — all before any key is minted. The encryption
    /// itself fails through the pending.
    fn encrypt<'a, K: 'static>(
        &self,
        name: &str,
        keyset: &'a KeysetCipher<'_, K>,
        label: &Label,
        plaintext: FfiValue,
    ) -> Result<Pending<'a, Vec<u8>, K>, TargetError>;

    /// Open a stored value of the named type back to its plaintext, checking
    /// it was stored under `label`'s column. Opens through the client; the
    /// lowering confines the pending to a keyset when the caller's scope is
    /// one.
    ///
    /// # Errors
    ///
    /// As [`encrypt`](Self::encrypt), with [`TargetError::Stored`] for bytes
    /// that are not the type. A stored identifier that differs from `label`,
    /// and a failed authentication, fail through the pending.
    fn decrypt<'a, K: 'static>(
        &self,
        name: &str,
        cipher: &'a StackCipher<K>,
        label: &Label,
        stored: &[u8],
    ) -> Result<Pending<'a, FfiValue, K>, TargetError>;

    /// Run the named type's query twin over one value: the operand that
    /// matches stored values under `label`'s column, as JSON bytes.
    ///
    /// # Errors
    ///
    /// As [`encrypt`](Self::encrypt).
    fn query<'a, K: 'static>(
        &self,
        name: &str,
        keyset: &'a KeysetCipher<'_, K>,
        label: &Label,
        plaintext: FfiValue,
    ) -> Result<Pending<'a, Vec<u8>, K>, TargetError>;
}

/// The resolver of a build that holds no EQL types: every name is refused
/// with [`TargetError::NoTargets`], so a plan naming a target fails when it
/// is built ([`record::plan`](super::record::plan())), before any value is
/// read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NoTargets;

impl NoTargets {
    fn refuse<T>(name: &str) -> Result<T, TargetError> {
        Err(TargetError::NoTargets {
            name: name.to_owned(),
        })
    }
}

impl TargetResolver for NoTargets {
    fn targets(&self) -> Vec<TargetDescriptor> {
        Vec::new()
    }

    fn encrypt<'a, K: 'static>(
        &self,
        name: &str,
        _: &'a KeysetCipher<'_, K>,
        _: &Label,
        _: FfiValue,
    ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
        Self::refuse(name)
    }

    fn decrypt<'a, K: 'static>(
        &self,
        name: &str,
        _: &'a StackCipher<K>,
        _: &Label,
        _: &[u8],
    ) -> Result<Pending<'a, FfiValue, K>, TargetError> {
        Self::refuse(name)
    }

    fn query<'a, K: 'static>(
        &self,
        name: &str,
        _: &'a KeysetCipher<'_, K>,
        _: &Label,
        _: FfiValue,
    ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
        Self::refuse(name)
    }
}

impl fmt::Display for TargetDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_eq() -> TargetDescriptor {
        TargetDescriptor::new(
            "TextEq",
            "text",
            "Eq",
            Some(ValueKind::String),
            "public.eql_v3_text_eq",
            vec!["eq".to_string()],
            Some("TextEqQuery".to_string()),
            Some("eql_v3.query_text_eq".to_string()),
            true,
            None,
        )
    }

    fn text_ord_ore() -> TargetDescriptor {
        TargetDescriptor::new(
            "TextOrdOre",
            "text",
            "OrdOre",
            Some(ValueKind::String),
            "public.eql_v3_text_ord_ore",
            vec!["eq".to_string(), "ore".to_string()],
            Some("TextOrdOreQuery".to_string()),
            Some("eql_v3.query_text_ord_ore".to_string()),
            false,
            Some("block ORE is not CLLW ORE".to_string()),
        )
    }

    /// A resolver over a fixed list, to test the default `resolve`.
    struct Fixed(Vec<TargetDescriptor>);

    impl TargetResolver for Fixed {
        fn targets(&self) -> Vec<TargetDescriptor> {
            self.0.clone()
        }
        fn encrypt<'a, K: 'static>(
            &self,
            _: &str,
            _: &'a KeysetCipher<'_, K>,
            _: &Label,
            _: FfiValue,
        ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
            unreachable!("not run here")
        }
        fn decrypt<'a, K: 'static>(
            &self,
            _: &str,
            _: &'a StackCipher<K>,
            _: &Label,
            _: &[u8],
        ) -> Result<Pending<'a, FfiValue, K>, TargetError> {
            unreachable!("not run here")
        }
        fn query<'a, K: 'static>(
            &self,
            _: &str,
            _: &'a KeysetCipher<'_, K>,
            _: &Label,
            _: FfiValue,
        ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
            unreachable!("not run here")
        }
    }

    #[test]
    fn the_wire_form_has_every_key_in_order_with_null_for_absent() {
        let FfiValue::Object(entries) = text_eq().to_value() else {
            panic!("an object");
        };
        let keys: Vec<&str> = entries.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            keys,
            [
                "name",
                "family",
                "suffix",
                "plaintext",
                "sql_domain",
                "indexes",
                "query",
                "query_sql_domain",
                "producible",
                "reason"
            ],
            "the se_targets entry's keys, in order"
        );
        assert!(matches!(&entries[3].1, FfiValue::String(s) if s.risky_ref() == b"string"));
        assert!(matches!(&entries[8].1, FfiValue::Bool(true)));
        assert!(
            matches!(&entries[9].1, FfiValue::Null),
            "no reason is null, not absent"
        );
        let mut unspecified = text_eq();
        unspecified.plaintext = None;
        unspecified.query = None;
        let FfiValue::Object(entries) = unspecified.to_value() else {
            panic!("an object");
        };
        assert!(matches!(&entries[3].1, FfiValue::Null));
        assert!(matches!(&entries[6].1, FfiValue::Null));
        assert_eq!(
            entries.len(),
            10,
            "an absent value is null, never a missing key"
        );
    }

    #[test]
    fn resolve_refuses_by_the_table_before_any_name_is_matched() {
        let empty = Fixed(vec![]);
        assert!(
            matches!(empty.resolve("TextEq"), Err(TargetError::NoTargets { name }) if name == "TextEq"),
            "an empty table is a build without EQL types"
        );
        let fixed = Fixed(vec![text_eq(), text_ord_ore()]);
        assert_eq!(fixed.resolve("TextEq").unwrap().name, "TextEq");
        assert!(
            matches!(fixed.resolve("Nope"), Err(TargetError::Unknown { name }) if name == "Nope")
        );
        assert!(matches!(
            fixed.resolve("TextOrdOre"),
            Err(TargetError::Unproducible { name, reason }) if name == "TextOrdOre" && reason.contains("CLLW")
        ));
        assert!(
            matches!(fixed.resolve("texteq"), Err(TargetError::Unknown { .. })),
            "names match exactly"
        );
    }

    /// A descriptor displays as its name alone, producible or not: what a
    /// log line or an error names a type by, with no status attached.
    #[test]
    fn a_descriptor_displays_as_its_name() {
        assert_eq!(text_eq().to_string(), "TextEq");
        assert_eq!(format!("{}", text_ord_ore()), "TextOrdOre");
        assert_eq!(
            format!("targets: {}, {}", text_eq(), text_ord_ore()),
            "targets: TextEq, TextOrdOre"
        );
    }

    #[test]
    fn no_targets_refuses_every_name_with_the_build_reason() {
        let error = NoTargets.resolve("TextEq").unwrap_err();
        assert_eq!(
            error.to_string(),
            "this build holds no EQL types; a plan cannot name TextEq as a target"
        );
        assert!(NoTargets.targets().is_empty());
    }

    #[test]
    fn error_messages_name_the_field_and_the_type() {
        let error = TargetError::Kind {
            name: "email".into(),
            target: "TextEq".into(),
            expected: Some(ValueKind::String),
            declared: ValueKind::UInt64,
        };
        assert_eq!(
            error.to_string(),
            "email: TextEq is produced from a string plaintext, and the field declares uint64"
        );
        let error = TargetError::Plaintext {
            name: "email".into(),
            target: "TextEq".into(),
            expected: Some(ValueKind::String),
            found: None,
        };
        assert_eq!(
            error.to_string(),
            "email: TextEq is produced from a string plaintext, not a value with no kind"
        );
        let error = TargetError::Extended {
            name: "email".into(),
            label: "users/email".into(),
        };
        assert!(error.to_string().contains("cannot be extended"), "{error}");
    }
}
