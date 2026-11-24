//! A record: a declaration of fields, turned into the engine's [`Plan`] once,
//! and the rows encrypted and decrypted through `dynamic::Planned`.
//!
//! A declaration is the plain object `record(..)` makes:
//! `{ type: "record", name, fields }`, each field
//! `{ type: "sealed", kind: { name }, index: [..], null? }` or
//! `{ type: "passthrough" }`. Each field's context is its field path: the
//! record's name, then the field's name. The plan is built from the
//! declaration with the engine's own types ([`FieldPlan`], [`Output`],
//! [`IndexSpec`], [`NullMode`], [`ValueKind`]), so the engine checks it
//! and its refusals are the engine's. A plan is built once for each
//! declaration and kept for the life of the process.
//!
//! A row crosses as one frame, a map of the record's fields. A value is
//! read as its field's kind by the engine's [`read`] before the engine
//! sees it, because vitaminc reads a JavaScript `bigint` at the narrowest
//! width that holds it.
//!
//! A stored row crosses as one frame too: for each sealed field an object
//! of `ciphertext` and the field's index terms, each as bytes; for a
//! passthrough field its value; for an absent field a null.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex, PoisonError};

use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use stack_encrypt::dynamic::{
    context, read, FieldPlan, NullMode, Output, Plan, Planned, ValueFrame, ValueKind,
};
use stack_encrypt::kms::{DataKeySource, IndexKeySource};
use stack_encrypt::target::IndexSpec;
use stack_encrypt::{
    AsProtectedRef, CipherRef, CipherText, Controlled, DecryptFrom, EncryptInto, KeysetCipher,
    PassthroughFrame, StackCipherText,
};

use crate::error::{Error, RecipherErrorFields};
use crate::frames::{bytes_of, entries, Entry, Map};
use crate::outcome::Outcome;

/// The stored row's name for a field's ciphertext.
const CIPHERTEXT: &str = "ciphertext";

/// Field names the engine reserves at the top of a plan.
const RESERVED: [&str; 2] = ["bind", "context_field"];

/// An index a declaration names, by the SDK's name for it.
fn index_named(name: &str) -> Option<IndexSpec> {
    match name {
        "equality" => Some(IndexSpec::Equality),
        // The match index under its default options, as the engine reads
        // its key in a plan.
        "match" => IndexSpec::parse("match"),
        "ore" => Some(IndexSpec::Ore),
        "ope" => Some(IndexSpec::Ope),
        _ => None,
    }
}

/// The SDK's name for an index, as a stored row spells it.
fn index_name(index: &IndexSpec) -> Option<&'static str> {
    match index {
        IndexSpec::Equality => Some("equality"),
        IndexSpec::Match(_) => Some("match"),
        IndexSpec::Ore => Some("ore"),
        IndexSpec::Ope => Some("ope"),
        IndexSpec::OreBlock | IndexSpec::Json(_) => None,
    }
}

/// A record's plan, built once from its declaration.
pub(crate) struct RecordPlan {
    name: String,
    plan: Plan,
    /// The fields, in declaration order.
    fields: Vec<Field>,
    /// The plan of each sealed field alone, by its name.
    alone: HashMap<String, Arc<RecordPlan>>,
}

/// A field as the rows read it.
#[derive(Clone)]
struct Field {
    name: String,
    kind: Option<ValueKind>,
    indexes: Vec<IndexSpec>,
    passthrough: bool,
}

impl std::fmt::Debug for RecordPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A declaration is not secret, but a plan's debug form is the
        // engine's, which nothing here needs to show.
        f.debug_struct("RecordPlan")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// A declaration, as `record(..)` writes it.
#[derive(Deserialize)]
struct Declaration {
    #[serde(rename = "type")]
    tag: String,
    name: String,
    fields: Fields,
}

/// The fields of a declaration, in the order they are declared.
struct Fields(Vec<(String, FieldDeclaration)>);

impl<'de> Deserialize<'de> for Fields {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct InOrder;
        impl<'de> Visitor<'de> for InOrder {
            type Value = Fields;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an object of field declarations")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Fields, A::Error> {
                let mut fields = Vec::new();
                while let Some(entry) = map.next_entry()? {
                    fields.push(entry);
                }
                Ok(Fields(fields))
            }
        }
        deserializer.deserialize_map(InOrder)
    }
}

/// One field of a declaration.
#[derive(Deserialize)]
struct FieldDeclaration {
    #[serde(rename = "type")]
    tag: String,
    #[serde(default)]
    kind: Option<KindDeclaration>,
    #[serde(default)]
    index: Vec<String>,
    #[serde(default)]
    null: Option<String>,
}

/// A field's kind, as `kinds` spells it.
#[derive(Deserialize)]
struct KindDeclaration {
    name: String,
}

/// The plans built so far, by the declaration's frame bytes. A declaration
/// holds no secret.
static PLANS: LazyLock<Mutex<HashMap<Vec<u8>, Arc<RecordPlan>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

impl RecordPlan {
    /// The plan of the declaration a binding read into `frame`, built the
    /// first time it is seen.
    ///
    /// # Errors
    ///
    /// `recipher::not_a_record`, or a refusal of the declaration naming the
    /// record and, where there is one, the field.
    pub(crate) fn of(frame: &ValueFrame) -> Outcome<Arc<RecordPlan>> {
        let key = frame.risky_ref().to_vec();
        if let Some(plan) = PLANS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key)
        {
            return Ok(Arc::clone(plan));
        }
        let declaration: Declaration =
            stack_encrypt::dynamic::frame::serde::from_slice(frame.risky_ref())
                .map_err(|_| Error::NotARecord)?;
        if declaration.tag != "record" {
            return Err(Error::NotARecord.into());
        }
        let plan = Arc::new(Self::build(declaration.name, declaration.fields.0)?);
        // Another call may have built the same plan meanwhile: the first one
        // kept is the one every call uses.
        let kept = PLANS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(key)
            .or_insert(plan)
            .clone();
        Ok(kept)
    }

    fn build(name: String, declared: Vec<(String, FieldDeclaration)>) -> Outcome<Self> {
        let mut fields = Vec::with_capacity(declared.len());
        let mut plans = Vec::with_capacity(declared.len());
        for (field_name, declaration) in declared {
            let (field, plan) = field_of(&name, field_name, declaration)?;
            fields.push(field);
            plans.push(plan);
        }
        let plan = Plan::new(plans.clone()).map_err(|error| engine_refused(&name, &error))?;
        let mut alone = HashMap::new();
        for (field, field_plan) in fields.iter().zip(plans) {
            if field.passthrough {
                continue;
            }
            let plan =
                Plan::new(vec![field_plan]).map_err(|error| engine_refused(&name, &error))?;
            let _ = alone.insert(
                field.name.clone(),
                Arc::new(Self {
                    name: name.clone(),
                    plan,
                    fields: vec![field.clone()],
                    alone: HashMap::new(),
                }),
            );
        }
        Ok(Self {
            name,
            plan,
            fields,
            alone,
        })
    }

    /// The record's name.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// The names of the fields, in declaration order.
    pub(crate) fn field_names(&self) -> impl Iterator<Item = &str> {
        self.fields.iter().map(|field| field.name.as_str())
    }

    /// The plan of the sealed field `name` alone: the same field path, so
    /// the field's bytes are the bytes it has in a whole row.
    ///
    /// # Errors
    ///
    /// `recipher::no_field` for a name the record does not declare, or that
    /// it passes through.
    pub(crate) fn field(&self, name: &str) -> Outcome<Arc<RecordPlan>> {
        self.alone.get(name).cloned().ok_or_else(|| {
            RecipherErrorFields::from(Error::NoField)
                .in_record(&self.name)
                .at_field(Some(name))
        })
    }
}

/// A field, and the engine's plan of it.
fn field_of(
    record: &str,
    name: String,
    declaration: FieldDeclaration,
) -> Outcome<(Field, FieldPlan)> {
    let at = |error: Error| {
        RecipherErrorFields::from(error)
            .in_record(record)
            .at_field(Some(&name))
    };
    if RESERVED.contains(&name.as_str()) {
        return Err(at(Error::ReservedField));
    }
    let passthrough = match declaration.tag.as_str() {
        "sealed" => false,
        "passthrough" => true,
        _ => return Err(at(Error::Declaration)),
    };
    let kind = match declaration.kind {
        Some(kind) => Some(
            kind.name
                .parse::<ValueKind>()
                .map_err(|_| at(Error::Kind { name: kind.name }))?,
        ),
        None => None,
    };
    let mut indexes = Vec::with_capacity(declaration.index.len());
    for index in declaration.index {
        indexes.push(index_named(&index).ok_or_else(|| at(Error::Index { name: index }))?);
    }
    let null = match declaration.null {
        None => None,
        Some(mode) => Some(
            [NullMode::Sealed, NullMode::Sql]
                .into_iter()
                .find(|known| known.name() == mode)
                .ok_or_else(|| at(Error::Null { mode }))?,
        ),
    };
    let outputs = if passthrough {
        vec![Output::Passthrough]
    } else {
        std::iter::once(Output::Ciphertext)
            .chain(indexes.iter().cloned().map(Output::Term))
            .collect()
    };
    let field_context = field_path(record, &name).ok_or_else(|| at(Error::Context))?;
    let mut plan = FieldPlan::new(name.clone(), field_context, outputs)
        .map_err(|error| engine_refused(record, &error))?;
    if let Some(kind) = kind {
        plan = plan
            .with_type(kind)
            .map_err(|error| engine_refused(record, &error))?;
    }
    if let Some(null) = null {
        plan = plan.with_null(null);
    }
    Ok((
        Field {
            name,
            kind,
            indexes,
            passthrough,
        },
        plan,
    ))
}

/// A field's context: its field path, `[record, field]`, read by the
/// engine's own context reader.
fn field_path(
    record: &str,
    field: &str,
) -> Option<stack_encrypt::NonEmpty<stack_encrypt::ContextPiece<'static>>> {
    let frame = stack_encrypt::dynamic::frame::serde::to_vec(&(record, field)).ok()?;
    context(frame.as_protected_ref()).ok()
}

/// The engine's refusal of a declaration of `record`. When the engine says
/// a context is not a label, the record's name or the field's is at fault.
/// The record's is tried alone to say which: the engine names the field
/// either way.
fn engine_refused(record: &str, error: &stack_encrypt::dynamic::Error) -> RecipherErrorFields {
    let refused = RecipherErrorFields::engine(error).in_record(record);
    if refused.reason() == Some("context_not_label") && !plain_segment(record) {
        return RecipherErrorFields::from(Error::RecordName).in_record(record);
    }
    refused
}

/// Whether `record` is a name the engine takes as the first segment of a
/// field path, asked of the engine with a field it takes.
fn plain_segment(record: &str) -> bool {
    field_path(record, "field")
        .is_some_and(|context| FieldPlan::new("field", context, vec![Output::Ciphertext]).is_ok())
}

/// A row's fields, each read as its field's kind, in the row's order.
///
/// # Errors
///
/// `recipher::not_a_row` for a row that is not an object, and
/// `recipher::field_type` for a value that is not of its field's kind or
/// does not fit it, naming the field.
pub(crate) fn conform_row(plan: &RecordPlan, row: &ValueFrame) -> Outcome<ValueFrame> {
    let not_a_row = || RecipherErrorFields::from(Error::NotARow).in_record(&plan.name);
    let values = entries(row).ok_or_else(not_a_row)?;
    let mut conformed: Vec<(String, ValueFrame)> = Vec::with_capacity(values.len());
    for (name, value) in values {
        let kind = plan
            .fields
            .iter()
            .find(|field| field.name == name)
            .and_then(|field| field.kind);
        let value = match kind {
            // A null is checked by the engine against the field's null mode.
            Some(kind) if value.kind().is_some() => read(kind, &value).map_err(|_| {
                RecipherErrorFields::from(Error::FieldType { kind })
                    .in_record(&plan.name)
                    .at_field(Some(&name))
            })?,
            _ => value,
        };
        conformed.push((name, value));
    }
    let map = Map(conformed
        .iter()
        .map(|(name, value)| (name.as_str(), Entry::Value(value)))
        .collect());
    ValueFrame::of(&map).map_err(|_| not_a_row())
}

/// Seal rows under a record's plan, in one key request however many there
/// are. Each row is a frame from [`conform_row`]; each result a stored row.
///
/// # Errors
///
/// The engine's refusal of a row that does not fit the plan.
pub(crate) async fn seal_rows<K>(
    keyset: &KeysetCipher<'_, K>,
    plan: Arc<RecordPlan>,
    rows: Vec<ValueFrame>,
) -> Outcome<Vec<ValueFrame>>
where
    K: DataKeySource + IndexKeySource + Sync + 'static,
{
    let planned: Vec<_> = rows
        .into_iter()
        .map(|row| Planned::new(&plan.plan, row))
        .collect();
    let stored = planned
        .encrypt_into::<Vec<StackCipherText>, K>(keyset)
        .await
        .map_err(|error| RecipherErrorFields::engine(&error).in_record(&plan.name))?;
    stored
        .into_iter()
        .map(|row| stored_row(&plan, row))
        .collect()
}

/// Open stored rows under a record's plan, in one key request for each
/// keyset they were sealed under. Each stored row is a frame as
/// [`seal_rows`] returns it; each result a row.
///
/// # Errors
///
/// `recipher::not_a_stored_row` for a stored row of another shape, naming
/// the field, and the engine's refusal of one that does not open.
pub(crate) async fn open_rows<'c, K>(
    cipher: impl Into<CipherRef<'c, K>>,
    plan: Arc<RecordPlan>,
    rows: Vec<ValueFrame>,
) -> Outcome<Vec<ValueFrame>>
where
    K: DataKeySource + IndexKeySource + Sync + 'static,
{
    let mut trees = Vec::with_capacity(rows.len());
    for row in &rows {
        trees.push(stored_tree(&plan, row)?);
    }
    let planned: Vec<_> = trees
        .into_iter()
        .map(|tree| Planned::new(&plan.plan, tree))
        .collect();
    Vec::<ValueFrame>::decrypt_from(planned, cipher)
        .await
        .map_err(|error| RecipherErrorFields::engine(&error).in_record(&plan.name))
}

/// The stored row the engine returned, as the frame the SDK hands back.
fn stored_row(plan: &RecordPlan, tree: StackCipherText) -> Outcome<ValueFrame> {
    let CipherText::Map(entries) = tree else {
        return Err(Error::EngineResult {
            what: "a row is not a map of fields",
        }
        .into());
    };
    let mut fields: Vec<(&str, Entry<'_>)> = Vec::with_capacity(plan.fields.len());
    for field in &plan.fields {
        let Some((_, outputs)) = entries.iter().find(|(name, _)| *name == field.name) else {
            // A null stored as SQL `NULL` produces no entry.
            fields.push((field.name.as_str(), Entry::Null));
            continue;
        };
        let CipherText::Map(outputs) = outputs else {
            return Err(Error::EngineResult {
                what: "a field is not a map of outputs",
            }
            .into());
        };
        if field.passthrough {
            let Some((_, CipherText::Passthrough(PassthroughFrame(frame)))) = outputs
                .iter()
                .find(|(key, _)| key == Output::Passthrough.key())
            else {
                return Err(Error::EngineResult {
                    what: "a passthrough field has no passthrough",
                }
                .into());
            };
            fields.push((field.name.as_str(), Entry::Frame(frame)));
            continue;
        }
        let mut stored: Vec<(&str, Entry<'_>)> = Vec::with_capacity(1 + field.indexes.len());
        for (key, node) in outputs {
            match (Output::parse(key), node) {
                (Some(Output::Ciphertext), CipherText::Single(leaf)) => {
                    let bytes = stack_encrypt::Ciphertext::from(leaf.clone()).to_bytes();
                    stored.push((CIPHERTEXT, Entry::Bytes(bytes)));
                }
                (Some(Output::Term(index)), CipherText::Passthrough(PassthroughFrame(term))) => {
                    let name = index_name(&index).ok_or(Error::EngineResult {
                        what: "an index the SDK does not name",
                    })?;
                    stored.push((name, Entry::Frame(term)));
                }
                _ => {
                    return Err(Error::EngineResult {
                        what: "an output of an unexpected shape",
                    }
                    .into())
                }
            }
        }
        fields.push((field.name.as_str(), Entry::Map(Map(stored))));
    }
    ValueFrame::of(&Map(fields)).map_err(|_| {
        Error::EngineResult {
            what: "the stored row could not be written as a frame",
        }
        .into()
    })
}

/// The engine's stored record for a stored row the SDK handed back.
fn stored_tree(plan: &RecordPlan, row: &ValueFrame) -> Outcome<StackCipherText> {
    let misfit = |field: Option<&str>, what: &'static str| {
        RecipherErrorFields::from(Error::NotAStoredRow { what })
            .in_record(&plan.name)
            .at_field(field)
    };
    let stored = entries(row)
        .ok_or_else(|| misfit(None, "a stored row is an object of the record's fields"))?;
    let mut tree = Vec::with_capacity(stored.len());
    for (name, value) in stored {
        let field = plan
            .fields
            .iter()
            .find(|field| field.name == name)
            .ok_or_else(|| misfit(Some(&name), "a field the record does not declare"))?;
        if field.passthrough {
            let node = CipherText::Passthrough(PassthroughFrame(value.risky_ref().to_vec()));
            tree.push((
                name,
                CipherText::Map(vec![(Output::Passthrough.key().to_owned(), node)]),
            ));
            continue;
        }
        if value.kind().is_none() {
            // A null: the field is absent, as SQL `NULL` stores it.
            continue;
        }
        let outputs = entries(&value).ok_or_else(|| {
            misfit(
                Some(&name),
                "a sealed field is an object of its ciphertext and its terms",
            )
        })?;
        let mut nodes = Vec::with_capacity(outputs.len());
        for (key, output) in outputs {
            let bytes = bytes_of(&output)
                .ok_or_else(|| misfit(Some(&name), "an output that is not bytes"))?;
            if key == CIPHERTEXT {
                let ciphertext =
                    stack_encrypt::Ciphertext::from_bytes(&bytes).map_err(|error| {
                        RecipherErrorFields::engine(&error)
                            .in_record(&plan.name)
                            .at_field(Some(&name))
                    })?;
                nodes.push((
                    Output::Ciphertext.key().to_owned(),
                    CipherText::Single(ciphertext.into()),
                ));
                continue;
            }
            let index = field
                .indexes
                .iter()
                .find(|index| index_name(index) == Some(key.as_str()))
                .ok_or_else(|| {
                    misfit(Some(&name), "a term of an index the field does not declare")
                })?;
            let term = vitaminc_aead::to_frame(bytes.as_slice())
                .map_err(|_| misfit(Some(&name), "a term that is not bytes"))?;
            nodes.push((
                index.key().to_owned(),
                CipherText::Passthrough(PassthroughFrame(term.risky_ref().to_vec())),
            ));
        }
        tree.push((name, CipherText::Map(nodes)));
    }
    Ok(CipherText::Map(tree))
}

/// The value of the field `name` in a one-field row, or a null when the
/// row has none (a null stored as SQL `NULL`).
pub(crate) fn field_value(row: &ValueFrame, name: &str) -> Outcome<ValueFrame> {
    let entries = entries(row).ok_or(Error::EngineResult {
        what: "a one-field row is not a map of fields",
    })?;
    match entries.into_iter().find(|(key, _)| key == name) {
        Some((_, value)) => Ok(value),
        None => ValueFrame::of(&Null).map_err(|_| {
            Error::EngineResult {
                what: "a null could not be written",
            }
            .into()
        }),
    }
}

/// A null.
struct Null;

impl stack_encrypt::Encrypt for &Null {
    fn visit<S: stack_encrypt::dynamic::plaintext::Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        sink.scalar(None, stack_encrypt::dynamic::plaintext::Physical::Null)
    }
}

/// A one-field row: `{ name: value }`.
pub(crate) fn one_field_row(name: &str, value: &ValueFrame) -> Outcome<ValueFrame> {
    ValueFrame::of(&Map(vec![(name, Entry::Value(value))])).map_err(|_| {
        Error::EngineResult {
            what: "a one-field row could not be written",
        }
        .into()
    })
}
