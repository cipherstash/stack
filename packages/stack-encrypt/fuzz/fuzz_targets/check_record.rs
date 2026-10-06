#![no_main]

//! The stored-record preflight, `dynamic::record::check_record`, against a
//! model of its documented rules.
//!
//! This is the walk a binding's decrypt runs before any key is requested:
//! it decides whether a stored tree fits its plan, and it is the only thing
//! standing between a tree an attacker rewrote and `decrypt_as`, which
//! opens no AEAD for a passthrough and would hand forged plaintext back as
//! a successful decrypt. So the input is not bytes but a *structure*: an
//! `Arbitrary`-derived mirror of a plan value and of a ciphertext tree,
//! drawn from a small name alphabet so field names, output keys and map
//! keys collide often, with passthroughs and duplicate keys anywhere.
//!
//! Two invariants. Neither `plan_with` nor `check_record` may panic on any
//! input. And for a plan that parses, `check_record` accepts the tree
//! exactly when the model does — the rules from the record docs, written
//! independently of the walk: one map, or a sequence of maps; every
//! ciphertext-bearing plan field present exactly once in every row; that
//! field a map with exactly one `"c"`; and under that `"c"` no passthrough
//! and no repeated map key at any depth. A target field (one naming an EQL
//! type) is present exactly once with exactly one `"eql"` node, which is a
//! passthrough carrying bytes.
//!
//! Plans parse under a fixed resolver holding one producible type, `TextEq`
//! over strings, so the target checks in `Plan::new_with` and the `"eql"`
//! node read in `record_row` run under fuzzing; every other target name is
//! refused when the plan is built, as under `NoTargets`.

use std::sync::OnceLock;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use stack_encrypt::dynamic::record::{check_record, plan_with, Plan};
use stack_encrypt::dynamic::{
    FfiValue, Output, TargetDescriptor, TargetError, TargetResolver, ValueKind,
};
use stack_encrypt::{KeysetCipher, Label, Pending, SealedValue, StackCipher, StackCipherText};
use uuid::Uuid;
use vitaminc_protected::Protected;

/// The resolver plans parse under: one producible type, `TextEq` over
/// strings, and nothing that runs — `check_record` never reaches a cipher.
struct Fixed;

impl TargetResolver for Fixed {
    fn targets(&self) -> Vec<TargetDescriptor> {
        vec![TargetDescriptor::new(
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
        )]
    }
    fn encrypt<'a, K: 'static>(
        &self,
        _: &str,
        _: &'a KeysetCipher<'_, K>,
        _: &Label,
        _: FfiValue,
    ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
        unreachable!("check_record runs no cipher")
    }
    fn decrypt<'a, K: 'static>(
        &self,
        _: &str,
        _: &'a StackCipher<K>,
        _: &Label,
        _: &[u8],
    ) -> Result<Pending<'a, FfiValue, K>, TargetError> {
        unreachable!("check_record runs no cipher")
    }
    fn query<'a, K: 'static>(
        &self,
        _: &str,
        _: &'a KeysetCipher<'_, K>,
        _: &Label,
        _: FfiValue,
    ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
        unreachable!("check_record runs no cipher")
    }
}

/// The name alphabet: the plan's field names, the tree's map keys and the
/// output keys all draw from it, so `"c"` is at once an output key and a
/// plausible field name.
#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
enum Name {
    A,
    B,
    C,
    Eq,
    Match,
    Ore,
    Ope,
    /// The stored key of a target field's value, and a plausible field name.
    Eql,
    /// The one target name the fixed resolver produces.
    TextEq,
    Other,
}

impl Name {
    fn as_str(self) -> &'static str {
        match self {
            Name::A => "a",
            Name::B => "b",
            Name::C => "c",
            Name::Eq => "eq",
            Name::Match => "match",
            Name::Ore => "ore",
            Name::Ope => "ope",
            Name::Eql => "eql",
            Name::TextEq => "TextEq",
            Name::Other => "zz",
        }
    }
}

/// A `"context"` value: the shapes `dynamic::context` accepts, plus one it
/// refuses. A plan field's context must be a label (a list of at least two
/// plain segments), optionally extended, so `Label` is what parses most
/// often; the others exercise the parser's refusals.
#[derive(Arbitrary, Debug)]
enum Ctx {
    Label(Name, Name),
    Extended(Name, Name, u32),
    Text(Name),
    I64(i64),
    U32(u32),
    List(Vec<Ctx>),
    Bool(bool),
}

impl Ctx {
    fn into_value(self) -> FfiValue {
        let text = |name: Name| FfiValue::String(name.as_str().into());
        match self {
            Ctx::Label(a, b) => FfiValue::Array(vec![text(a), text(b)]),
            Ctx::Extended(a, b, part) => FfiValue::Array(vec![
                FfiValue::Array(vec![text(a), text(b)]),
                FfiValue::UInt32(part),
            ]),
            Ctx::Text(name) => text(name),
            Ctx::I64(v) => FfiValue::Int64(v),
            Ctx::U32(v) => FfiValue::UInt32(v),
            Ctx::List(items) => FfiValue::Array(items.into_iter().map(Ctx::into_value).collect()),
            Ctx::Bool(v) => FfiValue::Bool(v),
        }
    }
}

/// One entry of a field spec: the three keys the parser knows and one it
/// does not, each with a value that may or may not be the right shape. A
/// `"target"` names an EQL type; `check_record` runs under `NoTargets`, the
/// build without them, so every plan with one is refused when it is built
/// — the parser's path to that refusal is what this exercises.
#[derive(Arbitrary, Debug)]
enum SpecEntry {
    Context(Ctx),
    Outputs(Vec<Name>),
    Target(Name),
    /// A `"type"`: required on an indexed field, so a plan with terms parses
    /// only when one of these names a kind that admits them.
    Type(Kind),
    ContextWrongShape(u32),
    OutputsWrongShape(u32),
    TargetWrongShape(u32),
    Unknown(Ctx),
}

/// A `"type"` value: a few kinds, and a name that is not one.
#[derive(Arbitrary, Debug, Clone, Copy)]
enum Kind {
    UInt32,
    Int64,
    String,
    Bytes,
    Float64,
    Object,
    NotAKind,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::UInt32 => "uint32",
            Kind::Int64 => "int64",
            Kind::String => "string",
            Kind::Bytes => "bytes",
            Kind::Float64 => "float64",
            Kind::Object => "object",
            Kind::NotAKind => "integer",
        }
    }
}

impl SpecEntry {
    fn into_entry(self) -> (String, FfiValue) {
        match self {
            SpecEntry::Context(ctx) => ("context".to_string(), ctx.into_value()),
            SpecEntry::Outputs(names) => (
                "outputs".to_string(),
                FfiValue::Array(
                    names
                        .into_iter()
                        .map(|n| FfiValue::String(n.as_str().into()))
                        .collect(),
                ),
            ),
            SpecEntry::Target(name) => (
                "target".to_string(),
                FfiValue::String(name.as_str().into()),
            ),
            SpecEntry::Type(kind) => ("type".to_string(), FfiValue::String(kind.as_str().into())),
            SpecEntry::ContextWrongShape(v) => ("context".to_string(), FfiValue::UInt32(v)),
            SpecEntry::OutputsWrongShape(v) => ("outputs".to_string(), FfiValue::UInt32(v)),
            SpecEntry::TargetWrongShape(v) => ("target".to_string(), FfiValue::UInt32(v)),
            SpecEntry::Unknown(ctx) => ("bogus".to_string(), ctx.into_value()),
        }
    }
}

/// A plan value as a binding would send it: `{ field: { ...spec } }`.
#[derive(Arbitrary, Debug)]
struct PlanSpec {
    fields: Vec<(Name, Vec<SpecEntry>)>,
}

impl PlanSpec {
    fn into_value(self) -> FfiValue {
        FfiValue::Object(
            self.fields
                .into_iter()
                .map(|(name, entries)| {
                    (
                        name.as_str().to_string(),
                        FfiValue::Object(entries.into_iter().map(SpecEntry::into_entry).collect()),
                    )
                })
                .collect(),
        )
    }
}

/// A stored ciphertext tree, with every `CipherText` variant reachable. A
/// passthrough carries a null or bytes: a target field's `"eql"` node is a
/// passthrough of bytes, and one of anything else is refused.
#[derive(Arbitrary, Debug)]
enum Tree {
    Single,
    None,
    EmptySequence,
    EmptyMap,
    Passthrough,
    PassthroughBytes,
    Sequence(Vec<Tree>),
    Map(Vec<(Name, Tree)>),
}

/// The one leaf every sealed node carries. Structural only, as
/// `check_record` is: nothing here opens it.
fn leaf() -> SealedValue {
    static LEAF: OnceLock<SealedValue> = OnceLock::new();
    LEAF.get_or_init(|| {
        SealedValue::from_parts(Uuid::nil(), [0; 16], vec![0; 48], vec![1; 32])
            .expect("a fixed tag fits the length field")
    })
    .clone()
}

impl Tree {
    fn into_ciphertext(self) -> StackCipherText {
        match self {
            Tree::Single => StackCipherText::Single(leaf()),
            Tree::None => StackCipherText::None(leaf()),
            Tree::EmptySequence => StackCipherText::EmptySequence(leaf()),
            Tree::EmptyMap => StackCipherText::EmptyMap(leaf()),
            Tree::Passthrough => StackCipherText::Passthrough(Box::new(FfiValue::Null)),
            Tree::PassthroughBytes => StackCipherText::Passthrough(Box::new(FfiValue::Bytes(
                Protected::new(b"{}".to_vec()),
            ))),
            Tree::Sequence(items) => {
                StackCipherText::Sequence(items.into_iter().map(Tree::into_ciphertext).collect())
            }
            Tree::Map(entries) => StackCipherText::Map(
                entries
                    .into_iter()
                    .map(|(name, node)| (name.as_str().to_string(), node.into_ciphertext()))
                    .collect(),
            ),
        }
    }

    /// A subtree fit to sit under `"c"`: no passthrough, and no map with a
    /// key given twice, at any depth.
    fn is_clean(&self) -> bool {
        match self {
            Tree::Passthrough | Tree::PassthroughBytes => false,
            Tree::Sequence(items) => items.iter().all(Tree::is_clean),
            Tree::Map(entries) => {
                let unique = entries
                    .iter()
                    .enumerate()
                    .all(|(at, (name, _))| !entries[..at].iter().any(|(prior, _)| prior == name));
                unique && entries.iter().all(|(_, node)| node.is_clean())
            }
            Tree::Single | Tree::None | Tree::EmptySequence | Tree::EmptyMap => true,
        }
    }
}

/// The model: the record rules as documented, not as implemented.
fn model_accepts(tree: &Tree, plan: &Plan) -> bool {
    let rows: Vec<&[(Name, Tree)]> = match tree {
        Tree::Map(entries) => vec![entries],
        Tree::Sequence(items) => {
            let mut rows = Vec::with_capacity(items.len());
            for item in items {
                let Tree::Map(entries) = item else {
                    return false;
                };
                rows.push(entries.as_slice());
            }
            rows
        }
        _ => return false,
    };
    rows.iter().all(|row| {
        plan.fields()
            .iter()
            .filter(|field| field.has_ciphertext() || field.target().is_some())
            .all(|field| {
                // The field exactly once in the row, and its one node
                // exactly once in its output map: a second copy is how a
                // stale ciphertext would be smuggled in beside the current
                // one. A sealed field's node is `"c"` and must be clean; a
                // target field's is `"eql"` and must be a passthrough of
                // bytes — the EQL value, whose ciphertext is inside it.
                let mut named = row
                    .iter()
                    .filter(|(name, _)| name.as_str() == field.name())
                    .map(|(_, node)| node);
                let (Some(Tree::Map(outputs)), None) = (named.next(), named.next()) else {
                    return false;
                };
                let key = if field.target().is_some() {
                    Name::Eql
                } else {
                    Name::C
                };
                let mut nodes = outputs
                    .iter()
                    .filter(|(name, _)| *name == key)
                    .map(|(_, node)| node);
                let (Some(node), None) = (nodes.next(), nodes.next()) else {
                    return false;
                };
                if field.target().is_some() {
                    matches!(node, Tree::PassthroughBytes)
                } else {
                    node.is_clean()
                }
            })
    })
}

#[derive(Arbitrary, Debug)]
struct Case {
    plan: PlanSpec,
    record: Tree,
}

fuzz_target!(|case: Case| {
    // Replaying one input with this set shows what it decoded to and how it
    // was judged: `STACK_ENCRYPT_FUZZ_TRACE=1 cargo +nightly fuzz run
    // check_record <input>`. Off during a campaign.
    let trace = std::env::var_os("STACK_ENCRYPT_FUZZ_TRACE").is_some();
    if trace {
        eprintln!("case: {case:#?}");
    }
    let Case { plan: spec, record } = case;
    // The plan parser is fuzzed for panics only: its rules are a separate
    // model, and a plan that does not parse has no record to check.
    let Ok(plan) = plan_with(spec.into_value(), &Fixed) else {
        if trace {
            eprintln!("verdict: plan refused");
        }
        return;
    };
    // One rule of the parsed plan is asserted here rather than left to the
    // model: every field with a term output declares its type. The parser
    // ends in `Plan::new_with`, which enforces it, so a plan that reaches
    // this point with an untyped indexed field means a parse path was added
    // that does not. A target field's kind is the type's own and it has no
    // outputs of its own, so the rule reads as written over `outputs()`.
    for field in plan.fields() {
        let indexed = field
            .outputs()
            .iter()
            .any(|output| matches!(output, Output::Term(_)));
        assert!(
            !indexed || field.target().is_some() || field.field_type().is_some(),
            "a parsed plan has an indexed field with no type: {:?}",
            field.name()
        );
    }
    let expected = model_accepts(&record, &plan);
    let actual = check_record(record.into_ciphertext(), &plan, None).is_ok();
    if trace {
        eprintln!("verdict: model accepts = {expected}, check_record accepts = {actual}");
    }
    assert_eq!(
        actual, expected,
        "check_record disagrees with the documented rules (model says accepted = {expected})"
    );
});
