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
//! The plan may be built with its context, or without one (the call names
//! it), and a field may be declared as the plan's context field, so a
//! context can also be given twice.
//!
//! Five invariants. Building and rendering never panic, whatever the
//! names. A plan built with its context gives every sealed or indexed field
//! a well-formed label: `<context>/<identity>`, which renders and parses
//! back to itself; a plan without one gives none, and keys each such field
//! under a plain identity segment. A passthrough or context field is under
//! no label, so a plan of passthrough fields with distinct names, under a
//! plain context or none, builds whatever text the names are. And a plan
//! whose context is given twice is refused with `TwoContextSources`.
//! And a built plan checks an empty batch's call context as it would one
//! record's: run with none and no context of its own is `NoContext`, run
//! with one beside its own is `TwoContextSources`, and opened likewise,
//! except that a context field's expected value waits for a record.

use std::collections::HashSet;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use stack_encrypt::plan::{FieldKind, FieldValues, Opens, PlanError, Runs};
use stack_encrypt::{Equality, Error, Label, NoRegistry, Plan};

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
    ContextField,
}

#[derive(Arbitrary, Debug)]
struct Declared {
    verb: Verb,
    name: Name,
    identity: Option<Name>,
}

#[derive(Arbitrary, Debug)]
struct Input {
    /// `None`: a plan built without a context.
    context: Option<Name>,
    fields: Vec<Declared>,
}

fuzz_target!(|input: Input| {
    let mut builder = match &input.context {
        Some(context) => Plan::context(context.as_str()).fields::<FieldValues, NoRegistry>(),
        None => Plan::fields::<FieldValues, NoRegistry>(),
    };
    for field in &input.fields {
        let name = field.name.as_str();
        builder = match field.verb {
            Verb::Encrypt => builder.encrypt::<String>(name),
            Verb::EncryptIndex => builder.encrypt_index::<String>(name, Equality),
            Verb::Index => builder.index::<String>(name, Equality),
            Verb::Passthrough => builder.passthrough::<String>(name),
            Verb::ContextField => builder.context_field::<String>(name),
        };
        if let Some(identity) = &field.identity {
            builder = builder.identity(identity.as_str());
        }
    }
    let _ = format!("{builder:?}");

    let context = input.context.as_ref().map(|c| Label::parse(c.as_str()));
    let context_fields = input
        .fields
        .iter()
        .filter(|f| f.verb == Verb::ContextField)
        .count();
    let sources = usize::from(context.is_some()) + context_fields;
    let names: HashSet<&str> = input.fields.iter().map(|f| f.name.as_str()).collect();
    let passthrough_only = !matches!(context, Some(Err(_)))
        && names.len() == input.fields.len()
        && input.fields.iter().all(|f| f.verb == Verb::Passthrough);

    match builder.build() {
        Ok(plan) => {
            assert!(sources <= 1, "a context given {sources} times built");
            let context = context.map(|c| c.expect("a plan that builds has a plain context"));
            assert_eq!(plan.label(), context.as_ref());
            if let Some(context) = &context {
                assert_eq!(Label::parse(&context.to_string()).as_ref(), Ok(context));
            }
            assert_eq!(
                plan.context_field().is_some(),
                context_fields == 1,
                "the plan names its context field"
            );
            assert_eq!(plan.field_plans().len(), input.fields.len());
            for (built, declared) in plan.field_plans().zip(&input.fields) {
                assert_eq!(built.name(), declared.name.as_str());
                let identity = declared
                    .identity
                    .as_ref()
                    .unwrap_or(&declared.name)
                    .as_str();
                assert_eq!(built.identity(), identity);
                let keys_nothing = matches!(
                    built.kind(),
                    FieldKind::Passthrough | FieldKind::ContextField
                );
                match (built.label(), &context) {
                    (None, Some(_)) => assert!(keys_nothing),
                    (None, None) => {
                        if !keys_nothing {
                            assert_eq!(
                                Label::parse(identity).map(|l| l.segments().count()),
                                Ok(1),
                                "a sealed field is keyed under one plain segment"
                            );
                        }
                    }
                    (Some(_), None) => panic!("a plan without a context labelled a field"),
                    (Some(label), Some(context)) => {
                        assert!(!keys_nothing);
                        assert_eq!(Label::parse(&label.to_string()).as_ref(), Ok(label));
                        let mut expected: Vec<&str> = context.segments().collect();
                        expected.push(identity);
                        assert!(label.segments().eq(expected));
                    }
                }
                assert!(plan.field(built.name()).is_ok());
            }
            let _ = format!("{plan:?}");

            let has_own = context.is_some() || context_fields == 1;
            let call = Label::parse("users").expect("a plain label");
            for call in [None, Some(&call)] {
                let expected = match (has_own, call.is_some()) {
                    (false, false) => Some(PlanError::NoContext),
                    (true, true) => Some(PlanError::TwoContextSources {
                        first: if context_fields == 1 {
                            "a context field"
                        } else {
                            "the plan"
                        },
                        second: "the call",
                    }),
                    _ => None,
                };
                let run = Runs::<Vec<FieldValues>, NoRegistry>::check(&plan, &Vec::new(), call);
                match (&expected, run) {
                    (None, Ok(())) => {}
                    (Some(expected), Err(Error::Plan(error))) => assert_eq!(&error, expected),
                    (expected, run) => panic!("an empty run checked {run:?}, not {expected:?}"),
                }
                let opened = Opens::<Vec<FieldValues>, NoRegistry>::check(&plan, &Vec::new(), call);
                match (&expected, opened) {
                    (_, Ok(())) if context_fields == 1 => {}
                    (None, Ok(())) => {}
                    (Some(expected), Err(Error::Plan(error))) if context_fields == 0 => {
                        assert_eq!(&error, expected)
                    }
                    (expected, opened) => {
                        panic!("an empty opening checked {opened:?}, not {expected:?}")
                    }
                }
            }
        }
        Err(Error::Plan(error)) => {
            assert!(
                !passthrough_only,
                "passthrough names are under no label, yet refused: {error}"
            );
            if sources > 1 && !matches!(context, Some(Err(_))) {
                assert!(
                    matches!(error, PlanError::TwoContextSources { .. }),
                    "a context given twice is refused as that, got {error}"
                );
            }
            let _ = error.to_string();
        }
        Err(other) => panic!("a plan is refused only with a plan error, got {other:?}"),
    }
});
