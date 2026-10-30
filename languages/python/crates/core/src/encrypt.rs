//! `encrypt`: the engine's record encryption under a model's plan, and the
//! walk of its output into one row of column values per model.
//!
//! The extension writes the models into one input frame, a sequence of
//! maps, straight from their attributes. This module runs the engine over
//! it on the shared client, then reads the ciphertext tree the engine
//! returns: per row a map of `field → { output-key → node }`
//! (`stack_encrypt::dynamic::record`, "The stored record is wire format").
//! An EQL field's JSON rides under `"eql"` as bytes; a passthrough field's
//! value rides under `"passthrough"` as the frame it went in as. Both come
//! out as a [`Column`], which the extension turns into the dict's value.

use stack_encrypt::dynamic::record::{self, Plan, EQL_KEY};
use stack_encrypt::dynamic::{self, Output, ValueFrame};
use stack_encrypt::{CipherText, Encrypt, StackCipherText};

use crate::client;
use crate::plan;
use crate::refusal::Refusal;
use crate::targets;
use crate::values::{self, Kind, Scalar};

/// One field of a model's plan, as `encrypt` needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    /// The field, which is the column.
    pub name: String,
    /// The EQL type and its kind, or `None` for a passthrough.
    pub eql: Option<(String, Kind)>,
}

/// A model's plan, built once per `Cipher` and read on every call.
pub struct ModelPlan {
    plan: Plan,
    fields: Vec<Field>,
}

impl ModelPlan {
    /// Build the plan the engine runs for a model stored in `table`.
    ///
    /// # Errors
    ///
    /// The engine's refusal, as [`plan::check`] gives it.
    pub fn new(table: &str, fields: Vec<Field>) -> Result<Self, Refusal> {
        let columns: Vec<(&str, plan::Column<'_>)> = fields
            .iter()
            .map(|field| {
                let column = field
                    .eql
                    .as_ref()
                    .map_or(plan::Column::Passthrough, |(name, _)| {
                        plan::Column::Eql(name)
                    });
                (field.name.as_str(), column)
            })
            .collect();
        let plan = plan::build(table, &columns)?;
        Ok(Self { plan, fields })
    }

    /// The fields, in plan order. The extension writes each model's values
    /// in this order and reads each row's columns back in it.
    pub fn fields(&self) -> &[Field] {
        &self.fields
    }
}

/// One column of an encrypted row.
#[derive(Clone, Debug, PartialEq)]
pub enum Column {
    /// The EQL JSON of a sealed field, as text.
    Eql(String),
    /// The echoed value of a passthrough field.
    Passthrough(Scalar),
}

/// Encrypt `rows` models, written as one frame, under `plan`. Returns one
/// row per model, its columns in [`ModelPlan::fields`] order.
///
/// Builds the shared client on the first call in the process. The caller
/// has released the GIL.
///
/// # Errors
///
/// The client's refusal, or the engine's for the encryption.
pub fn encrypt(
    plan: &ModelPlan,
    source: ValueFrame,
    rows: usize,
) -> Result<Vec<Vec<Column>>, Refusal> {
    let client = client::shared()?;
    let tree = client.block_on(async {
        let keyset = client.keyset();
        let pending = record::encrypt_with(&keyset, source, &plan.plan, &targets::resolver())
            .map_err(|error| plan::refusal(&error))?;
        pending.await.map_err(|error| Refusal::of(&error))
    })?;
    read_rows(plan, tree, rows)
}

fn read_rows(
    plan: &ModelPlan,
    tree: StackCipherText,
    rows: usize,
) -> Result<Vec<Vec<Column>>, Refusal> {
    let CipherText::Sequence(trees) = tree else {
        return Err(engine_fault("the output is not a sequence of rows"));
    };
    if trees.len() != rows {
        return Err(engine_fault(
            "the output has another number of rows than the input",
        ));
    }
    trees.into_iter().map(|row| read_row(plan, row)).collect()
}

fn read_row(plan: &ModelPlan, row: StackCipherText) -> Result<Vec<Column>, Refusal> {
    let CipherText::Map(entries) = row else {
        return Err(engine_fault("a row is not a map of fields"));
    };
    let mut columns = Vec::with_capacity(plan.fields.len());
    for field in &plan.fields {
        let (_, outputs) = entries
            .iter()
            .find(|(name, _)| name == &field.name)
            .ok_or_else(|| engine_fault("a row lacks a declared field"))?;
        let CipherText::Map(outputs) = outputs else {
            return Err(engine_fault("a field is not a map of outputs"));
        };
        let key = if field.eql.is_some() {
            EQL_KEY
        } else {
            Output::Passthrough.key()
        };
        let (_, node) = outputs
            .iter()
            .find(|(output, _)| output == key)
            .ok_or_else(|| engine_fault("a field lacks its output"))?;
        let CipherText::Passthrough(frame) = node else {
            return Err(engine_fault("an output is not a passthrough node"));
        };
        let scalar = values::read(&frame.0).map_err(|refused| Refusal {
            field: Some(field.name.clone()),
            ..refused
        })?;
        columns.push(match (&field.eql, scalar) {
            (Some(_), Scalar::Bytes(json)) => Column::Eql(
                String::from_utf8(json).map_err(|_| engine_fault("an EQL value is not UTF-8"))?,
            ),
            (Some(_), _) => return Err(engine_fault("an EQL value is not bytes")),
            (None, scalar) => Column::Passthrough(scalar),
        });
    }
    Ok(columns)
}

fn engine_fault(what: &str) -> Refusal {
    Refusal {
        code: "stack_encrypt_unknown".to_owned(),
        message: format!(
            "the engine's output does not have the shape the SDK reads: {what}. \
             Report this message as a stackencrypt bug."
        ),
        field: None,
        reason: None,
    }
}

/// A source the engine can read: anything that writes the rows. Re-exported
/// so the extension names one trait.
pub use dynamic::plaintext;

/// Write `source` as the one input frame `encrypt` takes.
///
/// # Errors
///
/// The error the source raised while writing, as the engine's decode error.
pub fn frame_of<P: Encrypt>(source: P) -> Result<ValueFrame, stack_encrypt::DecodeError> {
    ValueFrame::of(source)
}
