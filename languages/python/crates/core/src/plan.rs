//! A model's plan, checked by the engine when the class is declared.
//!
//! The Python decorator reads the fields and their markers. This module
//! writes them as the plan frame every binding sends, and runs the engine's
//! own reader over it (`record::plan_with`) with the EQL resolver. So the
//! engine sees the same declaration a Rust or Go caller would, and its
//! refusal reaches Python unchanged: its code, message, field and reason.

use miette::Diagnostic as _;
use serde::ser::{Serialize, SerializeMap, SerializeStruct, Serializer};
use stack_encrypt::dynamic::{self, record};
use stack_encrypt::ErrorPayload as _;

use crate::targets;

/// What one plan field stores.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Column<'a> {
    /// A field sealed as the EQL type of this name, such as `TextEq`.
    Eql(&'a str),
    /// A field stored as it is.
    Passthrough,
}

/// The engine's refusal of a plan, in the four fields every SDK error has.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// The engine's diagnostic code, with `::` replaced by `_`:
    /// `stack_encrypt_dynamic_plan`.
    pub code: String,
    /// The engine's message.
    pub message: String,
    /// The plan field at fault, where the engine names one.
    pub field: Option<String>,
    /// The engine's reason token, such as `no_fields`, where it gives one.
    pub reason: Option<String>,
}

/// Check the plan of a model stored in `table`, with `fields` in
/// declaration order. Each field's context is `[table, field]`.
///
/// # Errors
///
/// The engine's refusal, as a [`Refusal`].
pub fn check(table: &str, fields: &[(&str, Column<'_>)]) -> Result<(), Refusal> {
    // A frame of strings and lists of strings always encodes.
    let frame = dynamic::frame::serde::to_vec(&Wire { table, fields })
        .expect("a plan of strings encodes as a frame");
    record::plan_with(&frame, &targets::resolver())
        .map(drop)
        .map_err(|error| refusal(&error))
}

/// An engine diagnostic code as the SDK's `code`: `stack_encrypt::aead`
/// becomes `stack_encrypt_aead`.
pub fn python_code(engine_code: &str) -> String {
    engine_code.replace("::", "_")
}

fn refusal(error: &dynamic::Error) -> Refusal {
    let payload = error.payload();
    let text = |key: &str| payload.get(key).and_then(|v| v.as_str()).map(str::to_owned);
    Refusal {
        code: error.code().map_or_else(
            || "stack_encrypt_dynamic".to_owned(),
            |code| python_code(&code.to_string()),
        ),
        message: error.to_string(),
        field: text("field"),
        // Only the engine's own reason tokens. A resolver's reason, such as
        // the catalog's for an unproducible type, is prose and stays in the
        // message.
        reason: error.reason().map(|reason| reason.as_str().to_owned()),
    }
}

/// The plan frame: `{field: {"context": [table, field], "target": name}}`
/// for an EQL field, `"outputs": ["passthrough"]` for a passthrough field.
struct Wire<'a> {
    table: &'a str,
    fields: &'a [(&'a str, Column<'a>)],
}

impl Serialize for Wire<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.fields.len()))?;
        for (name, column) in self.fields {
            map.serialize_entry(
                name,
                &Spec {
                    context: [self.table, name],
                    column: *column,
                },
            )?;
        }
        map.end()
    }
}

struct Spec<'a> {
    context: [&'a str; 2],
    column: Column<'a>,
}

impl Serialize for Spec<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut spec = serializer.serialize_struct("Spec", 2)?;
        spec.serialize_field("context", &self.context)?;
        match self.column {
            Column::Eql(name) => spec.serialize_field("target", name)?,
            Column::Passthrough => spec.serialize_field("outputs", &["passthrough"])?,
        }
        spec.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plan_of_eql_and_passthrough_fields_is_accepted() {
        let fields = [
            ("email", Column::Eql("TextEq")),
            ("age", Column::Eql("IntegerOrd")),
            ("note", Column::Passthrough),
        ];
        assert_eq!(check("users", &fields), Ok(()));
    }

    #[test]
    fn an_empty_plan_is_refused_with_the_engine_code_and_reason() {
        let refused = check("users", &[]).unwrap_err();
        assert_eq!(refused.code, "stack_encrypt_dynamic_plan");
        assert_eq!(refused.field, None);
        assert_eq!(refused.reason.as_deref(), Some("no_fields"));
    }

    #[test]
    fn an_unknown_eql_type_is_refused_by_the_resolver() {
        let refused = check("users", &[("email", Column::Eql("Nope"))]).unwrap_err();
        assert_eq!(refused.code, "stack_encrypt_target_unknown");
        assert!(refused.message.contains("Nope"), "{refused:?}");
        assert_eq!(refused.reason, None);
    }

    #[test]
    fn an_unproducible_eql_type_is_refused_by_the_resolver() {
        let refused = check("users", &[("doc", Column::Eql("Json"))]).unwrap_err();
        assert_eq!(refused.code, "stack_encrypt_target_unproducible");
    }

    #[test]
    fn engine_codes_replace_the_path_separator() {
        assert_eq!(python_code("stack_encrypt::aead"), "stack_encrypt_aead");
        assert_eq!(
            python_code("stack_kms::load_keyset_forbidden"),
            "stack_kms_load_keyset_forbidden"
        );
    }
}
