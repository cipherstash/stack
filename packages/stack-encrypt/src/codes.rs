//! Every error in this crate carries a miette code: one in this crate's
//! namespace, or, for a variant that wraps another crate's error, that
//! error's. The tests here build one of every variant to check it, and pin
//! each error's payload fields.

#[cfg(test)]
mod tests {
    use miette::Diagnostic;
    use uuid::Uuid;

    use crate::diagnostic::is_code_of;
    use crate::sem::{MatchOptions, TermBytesError, TermError};
    use crate::target::IndexSpec;
    use crate::{Descriptor, Error, LabelError, LeafBytesError, PlanError};

    /// One row per variant of an enum, written `pattern => value`. The
    /// patterns are the arms of a match with no wildcard, so a variant with
    /// no row fails to compile, and each value must match its own pattern.
    macro_rules! variants {
        ($($pattern:pat => $value:expr),+ $(,)?) => {{
            let rows = vec![$({
                let value = $value;
                assert!(matches!(value, $pattern), "{value:?} is not {}", stringify!($pattern));
                value
            }),+];
            for row in &rows {
                match row {
                    $($pattern => {})+
                }
            }
            rows
        }};
    }

    fn boxed<E: Diagnostic + 'static>(rows: Vec<E>) -> impl Iterator<Item = Box<dyn Diagnostic>> {
        rows.into_iter()
            .map(|error| Box::new(error) as Box<dyn Diagnostic>)
    }

    /// One of every variant of every error type here.
    fn every_variant() -> Vec<Box<dyn Diagnostic>> {
        let cause = || Box::new(std::io::Error::other("cause"));
        let (a, b) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let field = || "age".to_string();
        let mut errors = Vec::new();
        errors.extend(boxed(variants![
            Error::Kms(_) => Error::Kms(crate::kms::Error::Unexpected("kms".into())),
            Error::Aead => Error::Aead,
            Error::KeyCountMismatch { .. } => Error::KeyCountMismatch {
                expected: 2,
                received: 1,
            },
            Error::DescriptorTooLong { .. } => Error::DescriptorTooLong { len: 513 },
            Error::Config(_) => Error::Config(cause()),
            Error::Term(_) => Error::Term(TermError::EmptyTermText),
            Error::Other(_) => Error::Other(cause()),
            Error::UnsupportedShape => Error::UnsupportedShape,
            Error::ContextMismatch { .. } => Error::ContextMismatch {
                stored: Descriptor::of("users"),
            },
            Error::ResponseShape => Error::ResponseShape,
            Error::KeysetMismatch { .. } => Error::KeysetMismatch { left: a, right: b },
            Error::ForeignKeyset { .. } => Error::ForeignKeyset {
                expected: a,
                found: b,
            },
            Error::NoKeyset => Error::NoKeyset,
            Error::NotOpened => Error::NotOpened,
            Error::Plan(_) => Error::Plan(PlanError::NoContext),
        ]));
        errors.extend(boxed(variants![
            LeafBytesError::UnknownVersion(_) => LeafBytesError::UnknownVersion(9),
            LeafBytesError::Truncated => LeafBytesError::Truncated,
            LeafBytesError::TagTooLong(_) => LeafBytesError::TagTooLong(70_000),
        ]));
        errors.extend(boxed(variants![
            TermError::Prf(_) => TermError::Prf(cause()),
            TermError::Ore(_) => TermError::Ore(cllw_ore::Error),
            TermError::InvalidOptions(_) => TermError::InvalidOptions("k out of range"),
            TermError::EmptyTermText => TermError::EmptyTermText,
            TermError::Bytes(_) => TermError::Bytes(TermBytesError::OddMatchTermsLength(3)),
        ]));
        errors.extend(boxed(variants![
            TermBytesError::WrongEqualityTermLength(_) => {
                TermBytesError::WrongEqualityTermLength(3)
            },
            TermBytesError::OddMatchTermsLength(_) => TermBytesError::OddMatchTermsLength(3),
            TermBytesError::MatchPositionOutOfRange { .. } => {
                TermBytesError::MatchPositionOutOfRange {
                    position: 900,
                    filter_size: 256,
                }
            },
            TermBytesError::MalformedCllwCiphertext(_) => {
                TermBytesError::MalformedCllwCiphertext(3)
            },
        ]));
        errors.extend(boxed(variants![
            LabelError::Empty => LabelError::Empty,
            LabelError::EmptySegment { .. } => LabelError::EmptySegment { index: 0 },
            LabelError::Separator { .. } => LabelError::Separator { index: 0 },
            LabelError::Reserved { .. } => LabelError::Reserved {
                index: 0,
                found: '(',
            },
            LabelError::ReservedPrefix { .. } => LabelError::ReservedPrefix { index: 0 },
            LabelError::NotText => LabelError::NotText,
        ]));
        errors.extend(boxed(variants![
            PlanError::ContextLabel(_) => PlanError::ContextLabel(LabelError::Empty),
            PlanError::FieldLabel { .. } => PlanError::FieldLabel {
                field: field(),
                source: LabelError::Empty,
            },
            PlanError::IdentityWithoutField => PlanError::IdentityWithoutField,
            PlanError::DuplicateField { .. } => PlanError::DuplicateField { field: field() },
            PlanError::SharedIdentity { .. } => PlanError::SharedIdentity {
                identity: "age".into(),
                first: "age".into(),
                second: "years".into(),
            },
            PlanError::PassthroughIndexed { .. } => {
                PlanError::PassthroughIndexed { field: field() }
            },
            PlanError::DuplicateIndex { .. } => PlanError::DuplicateIndex {
                at: field(),
                index: "eq",
            },
            PlanError::EmptyIndexes => PlanError::EmptyIndexes,
            PlanError::NotInPlan { .. } => PlanError::NotInPlan { field: field() },
            PlanError::NotInValue { .. } => PlanError::NotInValue { field: field() },
            PlanError::FieldType { .. } => PlanError::FieldType {
                field: field(),
                expected: "int64",
            },
            PlanError::NoSuchField { .. } => PlanError::NoSuchField { field: field() },
            PlanError::MixedCiphers => PlanError::MixedCiphers,
            PlanError::IndexNotDeclared { .. } => PlanError::IndexNotDeclared {
                field: field(),
                index: "ore",
            },
            PlanError::IndexOptions { .. } => PlanError::IndexOptions {
                field: field(),
                declared: IndexSpec::Match(MatchOptions::default()),
                asked: IndexSpec::Match(MatchOptions {
                    downcase: false,
                    ..MatchOptions::default()
                }),
            },
            PlanError::TwoContextSources { .. } => PlanError::TwoContextSources {
                first: "the plan",
                second: "the call",
            },
            PlanError::NoContext => PlanError::NoContext,
            PlanError::TargetWithVerbs { .. } => PlanError::TargetWithVerbs { field: field() },
        ]));
        #[cfg(feature = "dynamic")]
        errors.extend(dynamic_variants());
        errors
    }

    #[cfg(feature = "dynamic")]
    fn dynamic_variants() -> Vec<Box<dyn Diagnostic>> {
        use crate::dynamic::{Error, Reason, TargetError, ValueKind};
        let name = || "email".to_string();
        let target = || "TextEq".to_string();
        let mut errors = Vec::new();
        errors.extend(boxed(variants![
            Error::Context { .. } => Error::bad_context(Reason::EmptyContext),
            Error::Term { .. } => Error::Term {
                field: Some(name()),
                kind: IndexSpec::Equality,
            },
            Error::Plan { .. } => Error::bad_plan(Reason::NoFields),
            Error::UntypedIndex { .. } => Error::UntypedIndex { field: name() },
            Error::Source { .. } => Error::bad_source(Reason::FieldMissing),
            Error::Record { .. } => Error::bad_record(Reason::NoCiphertextNode),
            Error::Internal => Error::Internal,
            Error::Target(_) => Error::Target(TargetError::NoTargets { name: target() }),
            Error::Cipher(_) => Error::Cipher(crate::Error::Aead),
        ]));
        errors.extend(boxed(variants![
            TargetError::NoTargets { .. } => TargetError::NoTargets { name: target() },
            TargetError::Unknown { .. } => TargetError::Unknown { name: target() },
            TargetError::Unproducible { .. } => TargetError::Unproducible {
                name: target(),
                reason: "block ORE".into(),
            },
            TargetError::NoQuery { .. } => TargetError::NoQuery { name: target() },
            TargetError::Extended { .. } => TargetError::Extended {
                name: name(),
                label: "users/email".into(),
            },
            TargetError::ContextField { .. } => TargetError::ContextField {
                name: name(),
                context_field: "tenant".into(),
            },
            TargetError::Kind { .. } => TargetError::Kind {
                name: name(),
                target: target(),
                expected: Some(ValueKind::String),
                declared: ValueKind::UInt64,
            },
            TargetError::Column { .. } => TargetError::Column {
                name: name(),
                label: "app/users/email".into(),
                reason: "two segments".into(),
            },
            TargetError::Plaintext { .. } => TargetError::Plaintext {
                name: name(),
                target: target(),
                expected: Some(ValueKind::String),
                found: None,
            },
            TargetError::Stored { .. } => TargetError::Stored {
                name: name(),
                target: target(),
                reason: "not JSON".into(),
            },
            TargetError::Other(_) => TargetError::Other(Box::new(std::io::Error::other("boom"))),
        ]));
        errors
    }

    /// Every variant has a code in this crate's namespace and `snake_case`,
    /// save one that carries a stack-kms error, whose code is that error's.
    #[test]
    fn every_variant_has_a_code_of_this_crate() {
        for error in every_variant() {
            let code = error
                .code()
                .unwrap_or_else(|| panic!("{error:?} has no code"))
                .to_string();
            assert!(
                is_code_of("stack_encrypt", &code) || is_code_of("stack_kms", &code),
                "{code}"
            );
        }
    }

    /// A stored context can be customer data: its descriptor stays out of
    /// the message and the payload, which give its length and parts.
    #[test]
    fn a_context_mismatch_does_not_render_the_stored_context() {
        use crate::ErrorPayload;
        let error = Error::ContextMismatch {
            stored: Descriptor::of(("tenant", "marker-tenant")),
        };
        let shown = format!("{error} {:?}", error.payload());
        assert!(!shown.contains("marker-tenant"), "{shown}");
        assert_eq!(error.payload()["stored_parts"], 2);
    }

    /// A PRF backend's error is another library's: it is the source and
    /// never the message.
    #[test]
    fn a_prf_backends_message_is_the_source_only() {
        let error = TermError::Prf(Box::new(std::io::Error::other("marker-cause")));
        assert!(!error.to_string().contains("marker-cause"), "{error}");
        assert!(std::error::Error::source(&error)
            .is_some_and(|source| source.to_string().contains("marker-cause")));
    }

    /// The slots an implementation fills show its message as given: the
    /// implementation answers for it under the rule, and its own report is
    /// the useful one ("unsupported EQL ciphertext producer or version").
    #[test]
    fn an_implementations_own_error_shows_its_message() {
        let error = Error::Other("the implementation's own words".into());
        assert_eq!(error.to_string(), "the implementation's own words");
        assert_eq!(
            error.code().map(|code| code.to_string()).as_deref(),
            Some("stack_encrypt::other")
        );
    }

    #[test]
    fn a_foreign_keyset_carries_both_keysets() {
        use crate::ErrorPayload;
        let (expected, found) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let error = Error::ForeignKeyset { expected, found };
        assert_eq!(error.payload()["expected"], expected.to_string());
        assert_eq!(error.payload()["found"], found.to_string());
        assert!(error.help().is_some());
    }

    /// `Kms` is transparent all the way: a ZeroKMS keyset-not-found reads
    /// as itself, code and help, through the encryption error.
    #[test]
    fn a_kms_error_shows_through() {
        let error = Error::Kms(crate::kms::Error::Unexpected("kms".into()));
        assert_eq!(
            error.code().map(|code| code.to_string()).as_deref(),
            Some("stack_kms::unexpected")
        );
        assert_eq!(error.to_string(), "Unexpected error: kms");
    }

    /// Every error type's structured fields, one variant per arm. A binding
    /// hands these over as they are, so a field that goes missing or changes
    /// name is a break for every caller that reads it.
    fn every_payload() -> Vec<(Box<dyn crate::ErrorPayload>, serde_json::Value)> {
        use serde_json::json;
        let (a, b) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let declared = IndexSpec::Match(MatchOptions::default());
        let asked = IndexSpec::Match(MatchOptions {
            downcase: false,
            ..MatchOptions::default()
        });
        let payloads: Vec<(Box<dyn crate::ErrorPayload>, serde_json::Value)> = vec![
            (
                Box::new(Error::Kms(crate::kms::Error::GenerateKey(
                    crate::kms::GenerateKeyError::InvalidNumberOfKeys {
                        expected: 3,
                        received: 2,
                    },
                ))),
                json!({ "expected": 3, "received": 2 }),
            ),
            (
                Box::new(Error::Term(TermError::Bytes(
                    TermBytesError::WrongEqualityTermLength(31),
                ))),
                json!({ "len": 31 }),
            ),
            (
                Box::new(Error::Plan(PlanError::NoSuchField {
                    field: "age".into(),
                })),
                json!({ "field": "age" }),
            ),
            (
                Box::new(Error::KeyCountMismatch {
                    expected: 2,
                    received: 1,
                }),
                json!({ "expected": 2, "received": 1 }),
            ),
            (
                Box::new(Error::DescriptorTooLong { len: 513 }),
                json!({ "len": 513, "limit": Descriptor::MAX_LEN }),
            ),
            (
                Box::new(Error::ContextMismatch {
                    stored: Descriptor::of(("users", "email")),
                }),
                json!({
                    "stored_len": Descriptor::of(("users", "email")).len(),
                    "stored_parts": 2,
                }),
            ),
            (
                Box::new(Error::KeysetMismatch { left: a, right: b }),
                json!({ "left": a.to_string(), "right": b.to_string() }),
            ),
            (Box::new(Error::Aead), json!({})),
            (
                Box::new(LeafBytesError::UnknownVersion(9)),
                json!({ "version": 9 }),
            ),
            (
                Box::new(LeafBytesError::TagTooLong(70_000)),
                json!({ "len": 70_000 }),
            ),
            (Box::new(LeafBytesError::Truncated), json!({})),
            (
                Box::new(TermError::Bytes(TermBytesError::OddMatchTermsLength(3))),
                json!({ "len": 3 }),
            ),
            (Box::new(TermError::EmptyTermText), json!({})),
            (
                Box::new(TermBytesError::MalformedCllwCiphertext(5)),
                json!({ "len": 5 }),
            ),
            (
                Box::new(TermBytesError::MatchPositionOutOfRange {
                    position: 900,
                    filter_size: 256,
                }),
                json!({ "filter_size": 256 }),
            ),
            (Box::new(LabelError::Empty), json!({})),
            (
                Box::new(LabelError::EmptySegment { index: 1 }),
                json!({ "segment": 1 }),
            ),
            (
                Box::new(LabelError::Reserved {
                    index: 0,
                    found: '(',
                }),
                json!({ "segment": 0, "character": "(" }),
            ),
            (
                Box::new(PlanError::ContextLabel(LabelError::Separator { index: 2 })),
                json!({ "segment": 2 }),
            ),
            (
                Box::new(PlanError::FieldLabel {
                    field: "age".into(),
                    source: LabelError::ReservedPrefix { index: 1 },
                }),
                json!({ "segment": 1, "field": "age" }),
            ),
            (
                Box::new(PlanError::DuplicateField {
                    field: "age".into(),
                }),
                json!({ "field": "age" }),
            ),
            (
                Box::new(PlanError::SharedIdentity {
                    identity: "age".into(),
                    first: "age".into(),
                    second: "years".into(),
                }),
                json!({ "identity": "age", "first": "age", "second": "years" }),
            ),
            (
                Box::new(PlanError::DuplicateIndex {
                    at: "age".into(),
                    index: "eq",
                }),
                json!({ "field": "age", "index": "eq" }),
            ),
            (
                Box::new(PlanError::FieldType {
                    field: "age".into(),
                    expected: "int64",
                }),
                json!({ "field": "age", "expected": "int64" }),
            ),
            (
                Box::new(PlanError::IndexNotDeclared {
                    field: "age".into(),
                    index: "ore",
                }),
                json!({ "field": "age", "index": "ore" }),
            ),
            (
                Box::new(PlanError::IndexOptions {
                    field: "age".into(),
                    declared: declared.clone(),
                    asked: asked.clone(),
                }),
                json!({
                    "field": "age",
                    "index": "match",
                    "declared": format!("{declared:?}"),
                    "asked": format!("{asked:?}"),
                }),
            ),
            (
                Box::new(PlanError::TwoContextSources {
                    first: "the plan",
                    second: "the call",
                }),
                json!({ "first": "the plan", "second": "the call" }),
            ),
            (Box::new(PlanError::NoContext), json!({})),
        ];
        #[cfg(feature = "dynamic")]
        let payloads = payloads.into_iter().chain(dynamic_payloads()).collect();
        payloads
    }

    #[cfg(feature = "dynamic")]
    fn dynamic_payloads() -> Vec<(Box<dyn crate::ErrorPayload>, serde_json::Value)> {
        use crate::dynamic::{Error, Reason, TargetError, ValueKind};
        use serde_json::json;
        let name = || "email".to_string();
        let target = || "TextEq".to_string();
        vec![
            (
                Box::new(Error::Target(TargetError::Unknown { name: target() })),
                json!({ "target": "TextEq" }),
            ),
            (
                Box::new(Error::Cipher(crate::Error::KeyCountMismatch {
                    expected: 2,
                    received: 1,
                })),
                json!({ "expected": 2, "received": 1 }),
            ),
            (
                Box::new(Error::Term {
                    field: Some(name()),
                    kind: IndexSpec::Equality,
                }),
                json!({ "index": "eq", "field": "email" }),
            ),
            (
                Box::new(Error::bad_context(Reason::EmptyContext).in_field("email")),
                json!({ "field": "email", "reason": "empty_context" }),
            ),
            (
                Box::new(Error::bad_record(Reason::NoCiphertextNode)),
                json!({ "reason": "no_ciphertext_node" }),
            ),
            (
                Box::new(Error::UntypedIndex { field: name() }),
                json!({ "field": "email" }),
            ),
            (Box::new(Error::Internal), json!({})),
            (
                Box::new(TargetError::NoTargets { name: target() }),
                json!({ "target": "TextEq" }),
            ),
            (
                Box::new(TargetError::Unproducible {
                    name: target(),
                    reason: "block ORE".into(),
                }),
                json!({ "target": "TextEq", "reason": "block ORE" }),
            ),
            (
                Box::new(TargetError::Extended {
                    name: name(),
                    label: "users/email".into(),
                }),
                json!({ "field": "email", "label": "users/email" }),
            ),
            // Before the lowering names the field, there is none to give.
            (
                Box::new(TargetError::Extended {
                    name: String::new(),
                    label: "users/email".into(),
                }),
                json!({ "label": "users/email" }),
            ),
            (
                Box::new(TargetError::Kind {
                    name: name(),
                    target: target(),
                    expected: Some(ValueKind::String),
                    declared: ValueKind::UInt64,
                }),
                json!({
                    "field": "email",
                    "target": "TextEq",
                    "expected": "string",
                    "declared": "uint64",
                }),
            ),
            (
                Box::new(TargetError::Column {
                    name: name(),
                    label: "app/users/email".into(),
                    reason: "two segments".into(),
                }),
                json!({
                    "field": "email",
                    "label": "app/users/email",
                    "reason": "two segments",
                }),
            ),
            (
                Box::new(TargetError::Plaintext {
                    name: name(),
                    target: target(),
                    expected: Some(ValueKind::String),
                    found: None,
                }),
                json!({
                    "field": "email",
                    "target": "TextEq",
                    "expected": "string",
                    "found": null,
                }),
            ),
            (
                Box::new(TargetError::Stored {
                    name: name(),
                    target: target(),
                    reason: "not JSON".into(),
                }),
                json!({ "field": "email", "target": "TextEq", "reason": "not JSON" }),
            ),
            (
                Box::new(TargetError::Other(Box::new(std::io::Error::other("boom")))),
                json!({}),
            ),
        ]
    }

    #[test]
    fn every_payload_carries_its_fields() {
        for (error, expected) in every_payload() {
            assert_eq!(
                serde_json::Value::Object(error.payload()),
                expected,
                "{error:?}"
            );
        }
    }
}
