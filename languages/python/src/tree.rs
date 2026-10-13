//! The record tree, walked out and rebuilt — ONCE, for the lib and the
//! `parity` bin alike. A copy in each is how the two sides stop agreeing,
//! and the parity test exists to catch exactly that disagreement.
//!
//! The engine's stored record is a `CipherText::Map` per row, and inside it
//! one `Map` per field keyed by output: a target field's EQL JSON rides as a
//! passthrough byte node under `"eql"`, a passthrough field's value under
//! `"passthrough"`, and a ciphertext under `"c"`. The first two are
//! `FfiValue`s in a box and come straight out; the third is a sealed
//! subtree with no byte form this shell knows, so a plan that produces one
//! is refused by name. The tracer's path has no such field — EQL targets
//! and passthroughs only — and the refusal is what keeps that a decision
//! rather than a surprise.
//!
//! Everything here is pure: `FfiValue` in, `FfiValue` out, no Python and no
//! engine call. `engine.rs` converts at its edges; the bin serialises at
//! its.

use std::any::Any;

use stack_encrypt::dynamic::record::{FieldPlan, Plan, EQL_KEY};
use stack_encrypt::dynamic::FfiValue;
use stack_encrypt::{CipherText, StackCipherText};

/// The passthrough output key, as `dynamic::record` spells it. `EQL_KEY` is
/// exported; this one is not, and the module docs fix both as wire format.
pub const PASSTHROUGH_KEY: &str = "passthrough";

/// A refusal while walking a tree. The field is always named; no value is.
#[derive(Debug)]
pub struct TreeError {
    pub field: String,
    pub reason: &'static str,
}

impl std::fmt::Display for TreeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.reason)
    }
}

impl std::error::Error for TreeError {}

fn refuse(field: &str, reason: &'static str) -> TreeError {
    TreeError {
        field: field.to_owned(),
        reason,
    }
}

const NO_COLUMN_FORM: &str = "a field with a bare ciphertext output has no column form in \
     this shell; declare an EQL target or a passthrough";

/// Which output node a field's column value lives under, or a refusal for
/// a field whose node this shell cannot turn into one.
fn column_key(field: &FieldPlan) -> Result<&'static str, TreeError> {
    if field.target().is_some() {
        Ok(EQL_KEY)
    } else if field.has_ciphertext() {
        Err(refuse(field.name(), NO_COLUMN_FORM))
    } else {
        Ok(PASSTHROUGH_KEY)
    }
}

/// The rows of a sealed batch. One row in gives `Map`, a batch gives
/// `Sequence`; callers always send a batch, so `Map` here is a defect.
pub fn rows_of(tree: StackCipherText) -> Result<Vec<Vec<(String, StackCipherText)>>, TreeError> {
    let CipherText::Sequence(rows) = tree else {
        return Err(refuse(
            "<batch>",
            "sealed to something other than a sequence",
        ));
    };
    rows.into_iter()
        .map(|row| match row {
            CipherText::Map(fields) => Ok(fields),
            _ => Err(refuse("<row>", "sealed to something other than a map")),
        })
        .collect()
}

/// One stored row as column values: field name to the `FfiValue` its
/// column takes. A target field's EQL JSON is `Bytes`; a passthrough's
/// value is itself.
pub fn stored_row(
    row: Vec<(String, StackCipherText)>,
    plan: &Plan,
) -> Result<Vec<(String, FfiValue)>, TreeError> {
    let mut out = Vec::with_capacity(row.len());
    for (name, node) in row {
        let CipherText::Map(outputs) = node else {
            return Err(refuse(
                &name,
                "the engine's output for the field is not an output map",
            ));
        };
        let field = plan
            .fields()
            .iter()
            .find(|field| field.name() == name)
            .ok_or_else(|| refuse(&name, "not a field of the plan"))?;
        let key = column_key(field)?;
        let value = passthrough_value(&name, key, outputs)?;
        out.push((name, value));
    }
    Ok(out)
}

/// The `FfiValue` a passthrough node under `key` carries.
fn passthrough_value(
    field: &str,
    key: &str,
    outputs: Vec<(String, StackCipherText)>,
) -> Result<FfiValue, TreeError> {
    let node = outputs
        .into_iter()
        .find(|(candidate, _)| candidate == key)
        .map(|(_, node)| node)
        .ok_or_else(|| refuse(field, "no such output node"))?;
    let CipherText::Passthrough(payload) = node else {
        return Err(refuse(field, "the output node is not a passthrough"));
    };
    let payload: Box<dyn Any + Send> = payload;
    payload
        .downcast::<FfiValue>()
        .map(|value| *value)
        .map_err(|_| refuse(field, "the output node holds no value"))
}

/// Column values back as the engine's row tree, the inverse of
/// [`stored_row`]. A target field's bytes go back under `"eql"`, a
/// passthrough's value under `"passthrough"`, each as the boxed `FfiValue`
/// the engine's own opener downcasts to.
///
/// `values` is looked up by field name, so its order does not matter; the
/// plan's does, and is what the tree follows.
pub fn record_tree(
    mut values: Vec<(String, FfiValue)>,
    plan: &Plan,
) -> Result<StackCipherText, TreeError> {
    let mut row = Vec::with_capacity(plan.fields().len());
    for field in plan.fields() {
        let name = field.name();
        let position = values
            .iter()
            .position(|(candidate, _)| candidate == name)
            .ok_or_else(|| refuse(name, "the record has no such field"))?;
        let (_, value) = values.swap_remove(position);
        let key = column_key(field)?;
        if key == EQL_KEY && !matches!(value, FfiValue::Bytes(_)) {
            return Err(refuse(name, "a stored EQL value is bytes"));
        }
        let payload: Box<dyn Any + Send> = Box::new(value);
        row.push((
            name.to_owned(),
            CipherText::Map(vec![(key.to_owned(), CipherText::Passthrough(payload))]),
        ));
    }
    Ok(CipherText::Map(row))
}
