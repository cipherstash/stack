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
//! Two invariants. Neither `plan` nor `check_record` may panic on any
//! input. And for a plan that parses, `check_record` accepts the tree
//! exactly when the model does — the rules from the record docs, written
//! independently of the walk: one map, or a sequence of maps; every
//! ciphertext-bearing plan field present exactly once in every row; that
//! field a map with exactly one `"c"`; and under that `"c"` no passthrough
//! and no repeated map key at any depth.

use std::sync::OnceLock;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use stack_encrypt::dynamic::record::{check_record, plan, Plan};
use stack_encrypt::dynamic::FfiValue;
use stack_encrypt::{SealedValue, StackCipherText};
use uuid::Uuid;

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
            Name::Other => "zz",
        }
    }
}

/// A `"context"` value: the shapes `dynamic::context` accepts, plus one it
/// refuses.
#[derive(Arbitrary, Debug)]
enum Ctx {
    Text(Name),
    I64(i64),
    U32(u32),
    List(Vec<Ctx>),
    Bool(bool),
}

impl Ctx {
    fn into_value(self) -> FfiValue {
        match self {
            Ctx::Text(name) => FfiValue::String(name.as_str().into()),
            Ctx::I64(v) => FfiValue::Int64(v),
            Ctx::U32(v) => FfiValue::UInt32(v),
            Ctx::List(items) => FfiValue::Array(items.into_iter().map(Ctx::into_value).collect()),
            Ctx::Bool(v) => FfiValue::Bool(v),
        }
    }
}

/// One entry of a field spec: the two keys the parser knows and one it
/// does not, each with a value that may or may not be the right shape.
#[derive(Arbitrary, Debug)]
enum SpecEntry {
    Context(Ctx),
    Outputs(Vec<Name>),
    ContextWrongShape(u32),
    OutputsWrongShape(u32),
    Unknown(Ctx),
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
            SpecEntry::ContextWrongShape(v) => ("context".to_string(), FfiValue::UInt32(v)),
            SpecEntry::OutputsWrongShape(v) => ("outputs".to_string(), FfiValue::UInt32(v)),
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

/// A stored ciphertext tree, with every `CipherText` variant reachable.
#[derive(Arbitrary, Debug)]
enum Tree {
    Single,
    None,
    EmptySequence,
    EmptyMap,
    Passthrough,
    Sequence(Vec<Tree>),
    Map(Vec<(Name, Tree)>),
}

/// The one leaf every sealed node carries. Structural only, as
/// `check_record` is: nothing here opens it.
fn leaf() -> SealedValue {
    static LEAF: OnceLock<SealedValue> = OnceLock::new();
    LEAF.get_or_init(|| {
        SealedValue::from_parts(Uuid::nil().into(), vec![0; 64], vec![1; 32])
            .expect("a fixed key id fits the length field")
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
            Tree::Passthrough => false,
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
            .filter(|field| field.has_ciphertext())
            .all(|field| {
                // The field exactly once in the row, and `"c"` exactly once
                // in its output map: a second copy is how a stale ciphertext
                // would be smuggled in beside the current one.
                let mut named = row
                    .iter()
                    .filter(|(name, _)| name.as_str() == field.name())
                    .map(|(_, node)| node);
                let (Some(Tree::Map(outputs)), None) = (named.next(), named.next()) else {
                    return false;
                };
                let mut cs = outputs
                    .iter()
                    .filter(|(name, _)| *name == Name::C)
                    .map(|(_, node)| node);
                let (Some(ct), None) = (cs.next(), cs.next()) else {
                    return false;
                };
                ct.is_clean()
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
    let Ok(plan) = plan(spec.into_value()) else {
        if trace {
            eprintln!("verdict: plan refused");
        }
        return;
    };
    let expected = model_accepts(&record, &plan);
    let actual = check_record(record.into_ciphertext(), &plan).is_ok();
    if trace {
        eprintln!("verdict: model accepts = {expected}, check_record accepts = {actual}");
    }
    assert_eq!(
        actual, expected,
        "check_record disagrees with the documented rules (model says accepted = {expected})"
    );
});
