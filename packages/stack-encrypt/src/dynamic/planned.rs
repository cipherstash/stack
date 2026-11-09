//! Spike: a data plan paired with a value is an owned target.
//!
//! This module checks one idea before it is written into the API plan and
//! ADR-0007: the dynamic interface does not need the plan builder
//! (`crate::Plan`) between a parsed data plan and the combinators. A
//! [`Planned`] value composes the combinators itself, at run time, from the
//! parsed [`Plan`], and is run by the owned entry points (`encrypt_into`,
//! `decrypt_from`) like any other target.
//!
//! What it shows:
//!
//! - `EncryptTarget` is a declaration about a *type*, with no `self`. A data
//!   plan is a *value*. The plan rides in the plaintext position
//!   (`Planned::new(&plan, value)`), and the composition happens inside the
//!   description's build closure, per call.
//! - Every step is a combinator that exists today, and is the one the
//!   builder calls: `ciphertext`, `indexed`, `Indexes::operations`,
//!   `passthrough`, `under`, `under_by`, `zip`, `map`, `open`.
//!
//! Out of scope for the spike: target fields (EQL types through the
//! resolver), batch rows, rows with absent fields, a caller's context parts,
//! and an expected context on decrypt. Each is plumbing that `encrypt_with`
//! already has and that would move here.
use std::any::type_name;
use std::sync::Arc;

use vitaminc_protected::NonEmpty;
use zeroize::Zeroize;

use super::record::{record_rows, shape_record, Absent, Context, Plan, Rows, Verb};
use super::ValueFrame;
use crate::plan::PlanError;
use crate::plan::{FieldValues, IntoLabel, Slot};
use crate::target::{
    ciphertext, indexed, open, passthrough, AeadContext, Borrowed, CallerContext, DeclaredContext,
    DecryptSource, Decryption, EncryptTarget, Encryption, IndexSpec, Indexes, NoCallerContext,
    Pending,
};
use crate::{Error, Label, StackCipherText};

/// A value under a plan that is data.
pub struct Planned<'p, V> {
    plan: &'p Plan,
    value: V,
}

impl<'p, V> Planned<'p, V> {
    /// `value`, to be encrypted or opened under `plan`.
    pub fn new(plan: &'p Plan, value: V) -> Self {
        Self { plan, value }
    }

    /// The plan.
    pub fn plan(&self) -> &'p Plan {
        self.plan
    }
}

impl<V: Zeroize> Zeroize for Planned<'_, V> {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

// Spike only. A record wipes by dropping its slots: every value the dynamic
// path puts in one (`ValueFrame`, `StackCipherText`, `TermBytes`) wipes on
// drop. The real change would make `FieldValues` hold only such values.
impl Zeroize for FieldValues {
    fn zeroize(&mut self) {
        *self = FieldValues::new();
    }
}

// =============================================================================
// Encrypt side
// =============================================================================

impl<'p> EncryptTarget<Planned<'p, FieldValues>> for StackCipherText {
    // The plan supplies every context part. A caller's scopes and bindings
    // are the API plan's `Scope`/`Bind` work, not this spike's.
    type ContextInput = NoCallerContext;

    fn encryption<'s, K: 'static>(
    ) -> Encryption<'s, Planned<'p, FieldValues>, Self, K, Self::ContextInput>
    where
        Planned<'p, FieldValues>: 's,
    {
        // The plan is only known when the description runs, so the
        // composition happens here, per value. Nothing else about the
        // trait changes: this is still a borrowed description over the
        // plaintext, and `owned_encryption`'s default guards and wipes it.
        Encryption::from_build(
            |source: &Planned<'p, FieldValues>, cipher, _: NoCallerContext| {
                let plan = source.plan;
                let shape = plan.shape();
                let extend = plan.declared_context();
                match compose::<K>(plan) {
                    Ok(fields) => cipher.run(
                        fields.try_map(move |values| {
                            shape_record(values, Vec::new(), &shape, &Absent::new())
                        }),
                        &source.value,
                        extend,
                    ),
                    Err(error) => Pending::failed(cipher, error),
                }
            },
        )
    }
}

/// Where a plan's fields take their base context from.
enum Base {
    /// The plan's own label.
    Label(Label),
    /// A named field of the value.
    Field(Arc<str>),
}

/// The description of a whole record, composed from the parsed plan: each
/// field's verb as its combinator, projected out of the record by name,
/// under the field's label, zipped into one record. This is
/// `Plan::encryption` in `plan/build.rs` and `Plan::lower_without` in
/// `dynamic/record.rs`, merged, with the builder gone from between them.
fn compose<'s, K: 'static>(
    plan: &Plan,
) -> Result<Encryption<'s, FieldValues, FieldValues, K, DeclaredContext>, Error> {
    if plan.fields().iter().any(|field| field.is_target()) {
        // Spike: the resolver's fields are plumbing, not risk.
        return Err(out_of_scope());
    }
    let context_field = plan.context_field().map(str::to_owned);
    let base = match plan.context_source() {
        Context::Label(label) => Base::Label(label.clone()),
        Context::Field(name) => Base::Field(Arc::from(name.as_str())),
    };
    let mut record: Encryption<'s, FieldValues, Vec<(Arc<str>, Slot)>, K, DeclaredContext> =
        Encryption::ready(Ok(Vec::new()));
    for field in plan.fields() {
        let name: Arc<str> = Arc::from(field.name());
        let identity = field.identity().to_owned();
        let verb = field.verb();
        let operation = match verb {
            Verb::Encrypt => lift(
                ciphertext::<ValueFrame, K, Borrowed>().accepting::<CallerContext>(),
                &name,
            ),
            Verb::EncryptIndex => lift(
                indexed::<ValueFrame, K, Borrowed, Vec<IndexSpec>>(field.indexes()),
                &name,
            ),
            Verb::Index => lift(
                Indexes::<ValueFrame>::operations::<K, Borrowed>(&field.indexes()),
                &name,
            ),
            Verb::Passthrough => lift(
                passthrough::<ValueFrame, K, Borrowed, CallerContext>(),
                &name,
            ),
            Verb::Target => return Err(out_of_scope()),
        };
        // A passthrough and the context field carry no label of their own.
        let keys_nothing =
            verb == Verb::Passthrough || context_field.as_deref() == Some(field.name());
        let operation = match &base {
            Base::Label(context) if keys_nothing => {
                operation.under(NonEmpty::from(context.clone()))
            }
            Base::Label(context) => match join(context, &identity) {
                Ok(label) => operation.under(NonEmpty::from(label)),
                Err(source) => Encryption::failed(field_label(field.name(), source)),
            },
            Base::Field(of) => {
                let of = Arc::clone(of);
                let field_name = field.name().to_owned();
                operation.under_by(move |values: &FieldValues| {
                    let context = context_of(values, &of)?;
                    if keys_nothing {
                        Ok(context)
                    } else {
                        join(&context, &identity).map_err(|source| field_label(&field_name, source))
                    }
                })
            }
        };
        record =
            record
                .zip(operation)
                .map(move |(mut slots, slot): (Vec<(Arc<str>, Slot)>, Slot)| {
                    slots.push((name, slot));
                    slots
                });
    }
    Ok(record.map(FieldValues::from_slots))
}

/// A description over one field's value, lifted to read that field out of
/// the record by name and to hold its output in a slot.
fn lift<'s, T, K>(
    operation: Encryption<'s, ValueFrame, T, K, CallerContext>,
    name: &Arc<str>,
) -> Encryption<'s, FieldValues, Slot, K, CallerContext>
where
    T: std::any::Any + Send + 'static,
    K: 'static,
{
    let name = Arc::clone(name);
    operation
        .project_by(move |values: &FieldValues| {
            values
                .get::<ValueFrame>(&name)
                .ok_or_else(|| field_type(&name, type_name::<ValueFrame>()))
        })
        .map(Slot::new)
}

/// The context a record's context field holds.
fn context_of(values: &FieldValues, field: &str) -> Result<Label, Error> {
    values
        .get::<ValueFrame>(field)
        .ok_or_else(|| field_type(field, type_name::<ValueFrame>()))?
        .clone()
        .into_label()
        .map_err(|error| PlanError::ContextLabel(error).into())
}

/// The label a field is sealed under: the context, then its identity.
fn join(context: &Label, identity: &str) -> Result<Label, crate::descriptor::LabelError> {
    Label::new(context.segments().chain([identity]))
}

fn field_label(field: &str, source: crate::descriptor::LabelError) -> Error {
    PlanError::FieldLabel {
        field: field.to_owned(),
        source,
    }
    .into()
}

/// A case the spike leaves to the real change.
fn out_of_scope() -> Error {
    Error::Other("spike: target fields, batches and absent fields are out of scope".into())
}

/// A dynamic-interface refusal as the engine's error, as `dynamic::term` lifts one.
fn engine(error: super::Error) -> Error {
    match error {
        super::Error::Cipher(error) => error,
        other => Error::Other(Box::new(other)),
    }
}

fn field_type(field: &str, expected: &'static str) -> Error {
    PlanError::FieldType {
        field: field.to_owned(),
        expected,
    }
    .into()
}

// =============================================================================
// Decrypt side
// =============================================================================

impl<'p> DecryptSource<FieldValues> for Planned<'p, StackCipherText> {
    // An expected context for a context-field plan is `ExpectedContext`'s
    // job today and `Planned`'s later; not this spike's.
    type ContextInput = NoCallerContext;

    fn decryption<K: 'static>(self, _: NoCallerContext) -> Decryption<FieldValues, K> {
        let plan = self.plan;
        let stored = match record_rows(self.value, plan) {
            Ok(Rows::One(row)) => row,
            // Spike: batches are plumbing.
            Ok(Rows::Batch(_)) => return Decryption::failed(out_of_scope()),
            Err(error) => return Decryption::failed(engine(error)),
        };
        if !stored.targets.is_empty() {
            return Decryption::failed(out_of_scope());
        }
        let mut values = stored.values;
        let extend = plan.declared_context();
        let base = match plan.context_source() {
            Context::Label(label) => label.clone(),
            Context::Field(name) => match context_of(&values, name) {
                Ok(label) => label,
                Err(error) => return Decryption::failed(error),
            },
        };
        let context_field = plan.context_field().map(str::to_owned);
        let mut opened: Decryption<Vec<(Arc<str>, Slot)>, K> = Decryption::ready(Vec::new());
        for field in plan.fields() {
            if !field.opens() || stored.absent.contains(field.name()) {
                continue;
            }
            let name: Arc<str> = Arc::from(field.name());
            let Some(slot) = values.take_slot(field.name()) else {
                return Decryption::failed(
                    PlanError::NotInValue {
                        field: field.name().to_owned(),
                    }
                    .into(),
                );
            };
            let keys_nothing =
                field.verb() == Verb::Passthrough || context_field.as_deref() == Some(field.name());
            let opening: Decryption<Slot, K> = if keys_nothing {
                Decryption::ready(slot)
            } else {
                let label = match join(&base, field.identity()) {
                    Ok(label) => label,
                    Err(source) => return Decryption::failed(field_label(field.name(), source)),
                };
                match slot.downcast::<StackCipherText>() {
                    Ok(ciphertext) => open::<ValueFrame, K>(
                        ciphertext,
                        AeadContext::from(extend.clone().under(NonEmpty::from(label))),
                    )
                    .map(Slot::new),
                    Err(_) => {
                        return Decryption::failed(field_type(
                            field.name(),
                            type_name::<StackCipherText>(),
                        ))
                    }
                }
            };
            opened =
                opened
                    .zip(opening)
                    .map(move |(mut slots, slot): (Vec<(Arc<str>, Slot)>, Slot)| {
                        slots.push((name, slot));
                        slots
                    });
        }
        opened.map(FieldValues::from_slots)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::record::{decrypt, encrypt, plan as parse_plan, source_rows};
    use crate::dynamic::test_frame::{frame_of, Tree};
    use crate::dynamic::Scope;
    use crate::target::{DecryptFrom, EncryptInto};
    use crate::{CipherText, StackCipher};
    use stack_kms::FakeDataKeySource;
    use vitaminc_protected::AsProtectedRef as _;

    fn s(value: &str) -> Tree {
        Tree::String(value.into())
    }
    fn obj(entries: Vec<(&str, Tree)>) -> Tree {
        Tree::Object(
            entries
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        )
    }
    fn strings(items: &[&str]) -> Tree {
        Tree::Array(items.iter().map(|item| s(item)).collect())
    }
    fn label(field: &str) -> Tree {
        strings(&["users", field])
    }
    fn spec(context: Tree, outputs: &[&str]) -> Tree {
        obj(vec![("context", context), ("outputs", strings(outputs))])
    }
    fn typed(context: Tree, outputs: &[&str], ty: &str) -> Tree {
        obj(vec![
            ("context", context),
            ("outputs", strings(outputs)),
            ("type", s(ty)),
        ])
    }

    /// The plan `dynamic::record`'s own tests share: every verb but target.
    fn the_plan() -> Plan {
        let value = obj(vec![
            ("age", typed(label("age"), &["c", "eq", "ore"], "uint32")),
            ("email", spec(label("email"), &["c"])),
            ("nick", typed(label("nick"), &["match"], "string")),
            ("id", spec(label("id"), &["passthrough"])),
        ]);
        parse_plan(frame_of(&value).as_protected_ref().as_deref()).expect("the plan parses")
    }

    fn row(age: u32) -> Tree {
        obj(vec![
            ("age", Tree::UInt32(age)),
            ("email", s("a@x")),
            ("nick", s("al smith")),
            ("id", Tree::UInt64(7)),
        ])
    }

    /// The row as the record `encrypt_with` splits it into.
    fn values_of(row: Tree, plan: &Plan) -> FieldValues {
        match source_rows(row, plan).expect("the row fits the plan") {
            Rows::One(row) => row.values,
            Rows::Batch(_) => panic!("one row"),
        }
    }

    async fn cipher() -> StackCipher<FakeDataKeySource> {
        StackCipher::builder()
            .kms(FakeDataKeySource::new())
            .init()
            .await
            .expect("build cipher")
    }

    fn map(tree: &StackCipherText) -> &[(String, StackCipherText)] {
        match tree {
            CipherText::Map(entries) => entries,
            _ => panic!("expected a map node"),
        }
    }

    fn node<'a>(entries: &'a [(String, StackCipherText)], key: &str) -> &'a StackCipherText {
        &entries
            .iter()
            .find(|(have, _)| have == key)
            .unwrap_or_else(|| panic!("no node {key}"))
            .1
    }

    /// A term's stored bytes: the passthrough node that carries it.
    fn term_bytes(node: &StackCipherText) -> &[u8] {
        match node {
            CipherText::Passthrough(payload) => &payload.0,
            _ => panic!("expected a term node"),
        }
    }

    /// The same declaration, run through today's lowering (`encrypt`, via
    /// the builder) and through `Planned` (combinators alone), writes the
    /// same record shape and the same term bytes, and each side opens the
    /// other's record.
    #[tokio::test]
    async fn planned_writes_what_the_lowering_writes_and_each_opens_the_other() {
        let plan = the_plan();
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();

        let through_builder: StackCipherText = encrypt(&keyset, row(34), &plan)
            .expect("fits")
            .await
            .expect("encrypt");
        let through_planned = Planned::new(&plan, values_of(row(34), &plan))
            .encrypt_into::<StackCipherText, _>(&keyset)
            .await
            .expect("encrypt");

        // Same shape: field names, and each field's output keys, in order.
        let a = map(&through_builder);
        let b = map(&through_planned);
        let keys = |entries: &[(String, StackCipherText)]| -> Vec<(String, Vec<String>)> {
            entries
                .iter()
                .map(|(name, outputs)| {
                    (
                        name.clone(),
                        map(outputs).iter().map(|(k, _)| k.clone()).collect(),
                    )
                })
                .collect()
        };
        assert_eq!(keys(a), keys(b));

        // Same term bytes: a term is deterministic under one index key and
        // one context, so equal bytes mean an equal context and an equal
        // derivation on both paths.
        for (field, key) in [("age", "eq"), ("age", "ore"), ("nick", "match")] {
            let from_a = term_bytes(node(map(node(a, field)), key));
            let from_b = term_bytes(node(map(node(b, field)), key));
            assert_eq!(from_a, from_b, "{field}.{key}");
        }

        // Cross-opening: the AEAD would refuse a record sealed under any
        // other context, so this is the check that the ciphertexts' contexts
        // agree too.
        let opened_by_builder = decrypt(Scope::Client(&cipher), through_planned, &plan, None)
            .expect("fits")
            .await
            .expect("decrypt");
        let opened_by_planned = FieldValues::decrypt_from::<_, FakeDataKeySource>(
            Planned::new(&plan, through_builder),
            &cipher,
        )
        .await
        .expect("decrypt");
        // Both openings give back the row, less the one-way term.
        let by_builder = Tree::from_frame(opened_by_builder.risky_ref()).expect("a value");
        assert_eq!(u32_of(field_of(&by_builder, "age")), 34);
        assert_eq!(text_of(field_of(&by_builder, "email")), "a@x");
        assert_eq!(u64_of(field_of(&by_builder, "id")), 7);
        assert!(
            field_of_opt(&by_builder, "nick").is_none(),
            "a term is one-way"
        );

        let frame = |name: &str| -> Tree {
            let value = opened_by_planned
                .get::<ValueFrame>(name)
                .unwrap_or_else(|| panic!("{name} opened"));
            Tree::from_frame(value.risky_ref()).expect("a value")
        };
        assert_eq!(u32_of(&frame("age")), 34);
        assert_eq!(text_of(&frame("email")), "a@x");
        assert_eq!(u64_of(&frame("id")), 7);
        assert!(
            opened_by_planned.get::<ValueFrame>("nick").is_none(),
            "a term is one-way"
        );
    }

    fn field_of_opt<'a>(tree: &'a Tree, name: &str) -> Option<&'a Tree> {
        match tree {
            Tree::Object(entries) => entries.iter().find(|(k, _)| k == name).map(|(_, v)| v),
            _ => panic!("expected an object"),
        }
    }
    fn field_of<'a>(tree: &'a Tree, name: &str) -> &'a Tree {
        field_of_opt(tree, name).unwrap_or_else(|| panic!("no field {name}"))
    }
    fn u32_of(tree: &Tree) -> u32 {
        match tree {
            Tree::UInt32(v) => *v,
            other => panic!("expected a u32, got {other:?}"),
        }
    }
    fn u64_of(tree: &Tree) -> u64 {
        match tree {
            Tree::UInt64(v) => *v,
            other => panic!("expected a u64, got {other:?}"),
        }
    }
    fn text_of(tree: &Tree) -> &str {
        match tree {
            Tree::String(v) => v,
            other => panic!("expected text, got {other:?}"),
        }
    }

    /// A plan whose context is a field of the row takes the `under_by`
    /// path on encrypt, and reads the stored field back as the base on
    /// decrypt. Both paths agree, and each opens the other.
    #[tokio::test]
    async fn a_context_field_plan_agrees_on_both_paths() {
        let value = obj(vec![
            ("context_field", s("tenant")),
            (
                "tenant",
                typed(strings(&["tenant"]), &["passthrough"], "string"),
            ),
            ("email", typed(strings(&["email"]), &["c", "eq"], "string")),
        ]);
        let plan =
            parse_plan(frame_of(&value).as_protected_ref().as_deref()).expect("the plan parses");
        let row = || obj(vec![("tenant", s("acme")), ("email", s("a@x"))]);
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();

        let through_builder = encrypt(&keyset, row(), &plan)
            .expect("fits")
            .await
            .expect("encrypt");
        let through_planned = Planned::new(&plan, values_of(row(), &plan))
            .encrypt_into::<StackCipherText, _>(&keyset)
            .await
            .expect("encrypt");
        assert_eq!(
            term_bytes(node(map(node(map(&through_builder), "email")), "eq")),
            term_bytes(node(map(node(map(&through_planned), "email")), "eq")),
        );

        let by_builder = decrypt(Scope::Client(&cipher), through_planned, &plan, None)
            .expect("fits")
            .await
            .expect("decrypt");
        let by_builder = Tree::from_frame(by_builder.risky_ref()).expect("a value");
        assert_eq!(text_of(field_of(&by_builder, "email")), "a@x");
        assert_eq!(text_of(field_of(&by_builder, "tenant")), "acme");

        let by_planned = FieldValues::decrypt_from::<_, FakeDataKeySource>(
            Planned::new(&plan, through_builder),
            &cipher,
        )
        .await
        .expect("decrypt");
        let email = by_planned.get::<ValueFrame>("email").expect("email opened");
        assert_eq!(
            text_of(&Tree::from_frame(email.risky_ref()).expect("a value")),
            "a@x"
        );
    }

    /// A collection of planned values is a collection target, through the
    /// existing `Vec<T>: EncryptTarget<Vec<S>>`, with no new code.
    #[tokio::test]
    async fn a_vec_of_planned_values_is_a_collection_target() {
        let plan = the_plan();
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let rows = vec![
            Planned::new(&plan, values_of(row(1), &plan)),
            Planned::new(&plan, values_of(row(2), &plan)),
        ];
        let records = rows
            .encrypt_into::<Vec<StackCipherText>, _>(&keyset)
            .await
            .expect("encrypt");
        assert_eq!(records.len(), 2);
        for record in records {
            let opened = decrypt(Scope::Client(&cipher), record, &plan, None)
                .expect("fits")
                .await
                .expect("decrypt");
            assert!(!opened.is_null());
        }
    }
}
