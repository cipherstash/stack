#![no_main]

//! A fields plan built from untrusted names: the context, each field's
//! name, the identity pinned on it and the verb that declares it.
//!
//! A binding builds plans from names its caller supplies (a record's keys,
//! a column list), so `FieldsBuilder::build` is a parser of untrusted text
//! as much as the byte decoders are. Names come either from a small
//! alphabet, so duplicates, shared identities and reserved forms collide
//! often, or as free text.
//!
//! Three invariants. Building and rendering never panic, whatever the
//! names. A plan that builds gives every sealed or indexed field a
//! well-formed label: `<context>/<identity>`, which renders and parses back
//! to itself. And a passthrough field is under no label, so a plan of
//! passthrough fields with distinct names under a plain context builds,
//! whatever text the names are.

use std::collections::HashSet;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use stack_encrypt::plan::{FieldKind, FieldValues};
use stack_encrypt::{Equality, Error, Label, Plan};

/// A name: one of a few that collide or sit on a rule's edge, or free text.
#[derive(Arbitrary, Debug)]
enum Name {
    Email,
    Id,
    /// Begins with a digit: not a plain segment.
    TwoFactor,
    /// A reserved character.
    Parenthesised,
    /// Two segments, not one.
    Slashed,
    Empty,
    Free(String),
}

impl Name {
    fn as_str(&self) -> &str {
        match self {
            Name::Email => "email",
            Name::Id => "id",
            Name::TwoFactor => "2fa_enabled",
            Name::Parenthesised => "created(utc)",
            Name::Slashed => "users/email",
            Name::Empty => "",
            Name::Free(text) => text,
        }
    }
}

#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
enum Verb {
    Encrypt,
    EncryptIndex,
    Index,
    Passthrough,
}

#[derive(Arbitrary, Debug)]
struct Declared {
    verb: Verb,
    name: Name,
    identity: Option<Name>,
}

#[derive(Arbitrary, Debug)]
struct Input {
    context: Name,
    fields: Vec<Declared>,
}

fuzz_target!(|input: Input| {
    let mut builder = Plan::context(input.context.as_str()).fields::<FieldValues, ()>();
    for field in &input.fields {
        let name = field.name.as_str();
        builder = match field.verb {
            Verb::Encrypt => builder.encrypt::<String>(name),
            Verb::EncryptIndex => builder.encrypt_index::<String>(name, Equality),
            Verb::Index => builder.index::<String>(name, Equality),
            Verb::Passthrough => builder.passthrough::<String>(name),
        };
        if let Some(identity) = &field.identity {
            builder = builder.identity(identity.as_str());
        }
    }
    let _ = format!("{builder:?}");

    let context = Label::parse(input.context.as_str());
    let names: HashSet<&str> = input.fields.iter().map(|f| f.name.as_str()).collect();
    let passthrough_only = context.is_ok()
        && names.len() == input.fields.len()
        && input.fields.iter().all(|f| f.verb == Verb::Passthrough);

    match builder.build() {
        Ok(plan) => {
            let context = context.expect("a plan that builds has a plain context");
            assert_eq!(plan.label(), &context);
            assert_eq!(Label::parse(&context.to_string()).as_ref(), Ok(&context));
            assert_eq!(plan.fields().len(), input.fields.len());
            for (built, declared) in plan.fields().zip(&input.fields) {
                assert_eq!(built.name(), declared.name.as_str());
                match built.label() {
                    None => assert_eq!(built.kind(), FieldKind::Passthrough),
                    Some(label) => {
                        assert_ne!(built.kind(), FieldKind::Passthrough);
                        assert_eq!(Label::parse(&label.to_string()).as_ref(), Ok(label));
                        let identity = declared
                            .identity
                            .as_ref()
                            .unwrap_or(&declared.name)
                            .as_str();
                        let mut expected: Vec<&str> = context.segments().collect();
                        expected.push(identity);
                        assert!(label.segments().eq(expected));
                    }
                }
                assert!(plan.field(built.name()).is_ok());
            }
            let _ = format!("{plan:?}");
        }
        Err(Error::Plan(error)) => {
            assert!(
                !passthrough_only,
                "passthrough names are under no label, yet refused: {error}"
            );
            let _ = error.to_string();
        }
        Err(other) => panic!("a plan is refused only with a plan error, got {other:?}"),
    }
});
