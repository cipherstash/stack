//! The EQL types as Stack Encrypt's resolver: [`EqlTargets`], and the two
//! conversions it is built from. The module is private, so the type's own
//! documentation is what a reader sees.

use stack_encrypt::dynamic::{self, TargetDescriptor, TargetOptions, TargetResolver, ValueFrame};
use stack_encrypt::target::IndexSpec;
use stack_encrypt::{KeysetCipher, Label, Pending, StackCipher};

use super::targets::{self, decrypt, encrypt_with, query, Target, TargetError};

/// Every EQL type this crate defines, as Stack Encrypt's resolver.
///
/// Stack Encrypt's dynamic interface runs a plan that arrives as data. A
/// field of that plan may name an EQL type, such as `"TextEq"`. Stack
/// Encrypt does not depend on this crate, so a program gives it the EQL
/// types through a [`TargetResolver`]. `EqlTargets` is that resolver. It
/// holds every type in [`targets`](super::targets::targets), and runs a
/// named type through [`encrypt_with`], [`decrypt`] and [`query`].
///
/// Pass `&EqlTargets` wherever the dynamic interface takes a resolver, such
/// as `stack_encrypt::dynamic::record::plan_with`.
///
/// ```
/// use eql_bindings::encryption::EqlTargets;
/// use stack_encrypt::dynamic::TargetResolver;
///
/// let text_eq = EqlTargets.resolve("TextEq")?;
/// assert_eq!(text_eq.sql_domain, "public.eql_v4_text_eq");
/// assert_eq!(text_eq.indexes, ["eq"]);
/// # Ok::<(), stack_encrypt::dynamic::TargetError>(())
/// ```
///
/// The resolver sees a type's name and a field's label. It never sees the
/// field's name, so a refusal leaves the field name empty and the engine
/// fills it in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EqlTargets;

impl TargetResolver for EqlTargets {
    fn targets(&self) -> Vec<TargetDescriptor> {
        targets::targets()
            .iter()
            .map(TargetDescriptor::from)
            .collect()
    }

    fn encrypt<'a, K: 'static>(
        &self,
        name: &str,
        options: Option<&TargetOptions>,
        keyset: &'a KeysetCipher<'_, K>,
        label: &Label,
        plaintext: ValueFrame,
    ) -> Result<Pending<'a, Vec<u8>, K>, dynamic::TargetError> {
        Ok(encrypt_with(name, options, keyset, label, plaintext)?)
    }

    fn decrypt<'a, K: 'static>(
        &self,
        name: &str,
        cipher: &'a StackCipher<K>,
        label: &Label,
        stored: &[u8],
    ) -> Result<Pending<'a, ValueFrame, K>, dynamic::TargetError> {
        Ok(decrypt(name, cipher, label, stored)?)
    }

    fn query<'a, K: 'static>(
        &self,
        name: &str,
        index: &IndexSpec,
        keyset: &'a KeysetCipher<'_, K>,
        label: &Label,
        plaintext: ValueFrame,
    ) -> Result<Pending<'a, Vec<u8>, K>, dynamic::TargetError> {
        Ok(query(name, index, keyset, label, plaintext)?)
    }
}

/// A row of the target table as the engine's descriptor. The two have one
/// wire format.
///
/// The descriptor also carries what the engine needs and the wire does
/// not:
///
/// - the match options, for a type with a match index. The engine answers
///   `matches` through the type only when it knows them;
/// - the three query domains of a type that stores a JSON document. An
///   ordering at a path binds as the leaf operand, `element_match` as the
///   elements operand, and `match` as the predicate operand.
impl From<&Target> for TargetDescriptor {
    fn from(target: &Target) -> Self {
        let mut descriptor = TargetDescriptor::new(
            target.name,
            target.family,
            target.suffix,
            target.plaintext_kind(),
            target.sql_domain,
            target.indexes.iter().map(|key| (*key).to_owned()).collect(),
            target.query.map(str::to_owned),
            target.query_sql_domain.map(str::to_owned),
            target.producible,
            target.reason.map(str::to_owned),
        );
        if let Some(options) = target.match_options() {
            descriptor = descriptor.with_match_options(options);
        }
        if let Some(domain) = target.leaf_query_sql_domain() {
            descriptor = descriptor.with_leaf_query_sql_domain(domain);
        }
        if let Some(domain) = target.elements_query_sql_domain() {
            descriptor = descriptor.with_elements_query_sql_domain(domain);
        }
        if let Some(domain) = target.predicate_query_sql_domain() {
            descriptor = descriptor.with_predicate_query_sql_domain(domain);
        }
        descriptor
    }
}

/// A refusal of this crate as the engine's. The field name is left empty:
/// the engine fills it in, since the resolver never sees it.
///
/// No variant carries a byte of a plaintext or of a stored value. A value
/// that is not a JSON document keeps the engine's code for what was wrong.
/// A stored value that does not parse keeps the parser's kind and position
/// and not its message, because `serde_json` quotes the input it refused,
/// and that input is stored ciphertext.
impl From<TargetError> for dynamic::TargetError {
    fn from(error: TargetError) -> Self {
        match error {
            TargetError::Unknown { name } => Self::Unknown { name },
            TargetError::Unproducible { name, reason } => Self::Unproducible {
                name: name.to_owned(),
                reason: reason.to_owned(),
            },
            TargetError::NoQuery { name } => Self::NoQuery {
                name: name.to_owned(),
            },
            TargetError::Context { label } => Self::Column {
                name: String::new(),
                label,
                reason: "an EQL column is a two-segment label, table and column".to_owned(),
            },
            TargetError::Plaintext {
                target,
                expected,
                found,
            } => Self::Plaintext {
                name: String::new(),
                target: target.to_owned(),
                expected: Some(expected),
                found,
            },
            TargetError::Json { target, source } => Self::Json {
                name: String::new(),
                target: target.to_owned(),
                reason: source.code(),
            },
            TargetError::Stored { target, source } => Self::Stored {
                name: String::new(),
                target: target.to_owned(),
                reason: stack_encrypt::diagnostic::describe_json_error(&source),
            },
            // The engine refuses each of these before it calls the
            // resolver: it derives a document's queries itself, asks a query
            // only through an index the type carries, and refuses options on
            // a type with no JSON index when it builds the plan. Reaching
            // one is the engine's failure, not the caller's input. Each is
            // named, so a variant added later must be placed by hand.
            error @ (TargetError::DocumentQuery { .. }
            | TargetError::NoIndex { .. }
            | TargetError::Options { .. }) => Self::Other(Box::new(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stack_encrypt::dynamic::{record, Op, ValueKind};
    use stack_encrypt::AsProtectedRef as _;

    /// The resolver lists one type for each row of the target table, in
    /// the table's order. The table is generated from the catalog, and
    /// `tests/catalog_parity.rs` holds it to the catalog.
    #[test]
    fn the_resolver_lists_the_target_table() {
        let listed: Vec<String> = EqlTargets.targets().into_iter().map(|t| t.name).collect();
        let table: Vec<&str> = targets::targets().iter().map(|t| t.name).collect();
        assert!(!table.is_empty(), "the catalog has types");
        assert_eq!(listed, table);
    }

    /// Each descriptor has its row's values, and serializes to the row's
    /// wire form with the engine's `operators` key added.
    #[test]
    fn a_descriptor_has_its_rows_values() {
        for (row, descriptor) in targets::targets().iter().zip(EqlTargets.targets()) {
            assert_eq!(descriptor.plaintext, row.plaintext_kind(), "{}", row.name);
            assert_eq!(descriptor.producible, row.producible, "{}", row.name);
            assert_eq!(
                descriptor.match_options.is_some(),
                row.indexes.contains(&"match"),
                "{}: match options exactly where there is a match index",
                row.name
            );
            let mut wire = serde_json::to_value(&descriptor).unwrap();
            let operators = wire.as_object_mut().unwrap().remove("operators");
            assert!(operators.is_some(), "{}", row.name);
            assert_eq!(wire, serde_json::to_value(row).unwrap(), "{}", row.name);
        }
    }

    #[test]
    fn the_resolver_resolves_a_producible_type_and_refuses_the_rest() {
        let text_eq = EqlTargets.resolve("TextEq").unwrap();
        assert_eq!(text_eq.plaintext, Some(ValueKind::String));
        assert_eq!(text_eq.indexes, ["eq"]);
        assert_eq!(text_eq.query.as_deref(), Some("TextEqQuery"));
        assert!(matches!(
            EqlTargets.resolve("Json"),
            Err(dynamic::TargetError::Unproducible { .. })
        ));
        assert!(matches!(
            EqlTargets.resolve("Nope"),
            Err(dynamic::TargetError::Unknown { .. })
        ));
    }

    /// The JSON document names its three query domains, so the engine
    /// offers the orderings at a path, `element_match` and `match`.
    #[test]
    fn a_document_names_the_leaf_element_and_predicate_domains() {
        let document = EqlTargets.resolve("JsonSearch").unwrap();
        assert_eq!(
            document.leaf_query_sql_domain.as_deref(),
            Some("eql_v4.query_json_leaf")
        );
        assert_eq!(
            document.elements_query_sql_domain.as_deref(),
            Some("eql_v4.query_json_elements")
        );
        assert_eq!(
            document.predicate_query_sql_domain.as_deref(),
            Some("eql_v4.query_json_predicate")
        );
        assert!(document.operators().contains(&Op::Match));
        // The operators a field answers: the orderings and `element_match`
        // only where it orders a path, and `match` on every field.
        let field_operators = |ordered: &[&str]| {
            let wire = serde_json::json!({
                "profile": {
                    "context": ["users", "profile"],
                    "type": "json",
                    "null": "sql",
                    "target": {"name": "JsonSearch", "options": {"ordered": ordered}}
                }
            });
            let frame = dynamic::frame::serde::to_vec(&wire).expect("plan frame");
            let plan = record::plan_with(frame.as_protected_ref(), &EqlTargets).expect("plan");
            dynamic::field_operators(&plan, "profile", &EqlTargets)
                .expect("operators")
                .into_iter()
                .map(|(op, _)| op)
                .collect::<Vec<_>>()
        };
        let ordered = field_operators(&["$.contacts[*].relationship"]);
        for present in [Op::ElementMatch, Op::Match] {
            assert!(ordered.contains(&present), "{present:?}: {ordered:?}");
        }
        let unordered = field_operators(&[]);
        assert!(unordered.contains(&Op::Match), "{unordered:?}");
        assert!(!unordered.contains(&Op::ElementMatch), "{unordered:?}");
    }

    #[test]
    fn a_refusal_converts_with_the_field_name_left_to_the_engine() {
        assert!(matches!(
            dynamic::TargetError::from(TargetError::Context {
                label: "tenant/users/email".into()
            }),
            dynamic::TargetError::Column { name, label, .. }
                if name.is_empty() && label == "tenant/users/email"
        ));
        assert!(matches!(
            dynamic::TargetError::from(TargetError::Plaintext {
                target: "TextEq",
                expected: ValueKind::String,
                found: Some(ValueKind::UInt64),
            }),
            dynamic::TargetError::Plaintext {
                target,
                expected: Some(ValueKind::String),
                found: Some(ValueKind::UInt64),
                ..
            } if target == "TextEq"
        ));
        assert!(matches!(
            dynamic::TargetError::from(TargetError::Unknown { name: "Nope".into() }),
            dynamic::TargetError::Unknown { name } if name == "Nope"
        ));
        assert!(matches!(
            dynamic::TargetError::from(TargetError::NoQuery { name: "Text" }),
            dynamic::TargetError::NoQuery { name } if name == "Text"
        ));
        assert!(matches!(
            dynamic::TargetError::from(TargetError::Unproducible {
                name: "Json",
                reason: "not yet",
            }),
            dynamic::TargetError::Unproducible { name, reason }
                if name == "Json" && reason == "not yet"
        ));
        // A value that is not a document keeps the engine's code, and no
        // byte of the value.
        let Err(source) = dynamic::read_json(&ValueFrame::of(r#"{"secret": "#).unwrap()) else {
            panic!("the text is not a JSON document");
        };
        let code = source.code();
        let error = dynamic::TargetError::from(TargetError::Json {
            target: "JsonSearch",
            source,
        });
        assert!(matches!(
            &error,
            dynamic::TargetError::Json { name, target, reason }
                if name.is_empty() && target == "JsonSearch" && *reason == code
        ));
        let shown = format!("{error} {:?}", stack_encrypt::ErrorPayload::payload(&error));
        assert!(!shown.contains("secret"), "{shown}");
        // The engine refuses these three before it calls the resolver, so
        // reaching one is the engine's failure, not the caller's input.
        for refusal in [
            TargetError::NoIndex {
                name: "TextEq",
                index: "ope",
            },
            TargetError::DocumentQuery { name: "JsonSearch" },
            TargetError::Options { name: "TextEq" },
        ] {
            assert!(matches!(
                dynamic::TargetError::from(refusal),
                dynamic::TargetError::Other(_)
            ));
        }
    }

    /// Why `Options` converts to `Other`: the engine refuses options on a
    /// type with no JSON index when it builds the plan, so the resolver is
    /// never asked to encrypt under them.
    #[test]
    fn the_engine_refuses_options_on_a_type_without_a_json_index() {
        let wire = serde_json::json!({
            "email": {
                "context": ["users", "email"],
                "target": {"name": "TextEq", "options": {"ordered": []}}
            }
        });
        let frame = dynamic::frame::serde::to_vec(&wire).expect("plan frame");
        let error = record::plan_with(frame.as_protected_ref(), &EqlTargets).unwrap_err();
        assert_eq!(
            error.reason(),
            Some(dynamic::Reason::TargetOptions),
            "{error:?}"
        );
    }

    /// `serde_json` quotes the value it refused, and a stored EQL value
    /// holds ciphertext and index terms. Only the error's kind and position
    /// cross.
    #[test]
    fn a_stored_value_that_does_not_parse_quotes_none_of_it() {
        let source = serde_json::from_str::<u8>(r#""marker-ciphertext""#).unwrap_err();
        let error = dynamic::TargetError::from(TargetError::Stored {
            target: "TextEq",
            source,
        });
        let dynamic::TargetError::Stored { reason, .. } = &error else {
            panic!("{error:?}");
        };
        assert_eq!(reason, "unexpected data at line 1 column 19");
        let shown = format!("{error} {:?}", stack_encrypt::ErrorPayload::payload(&error));
        assert!(!shown.contains("marker"), "{shown}");
    }
}
