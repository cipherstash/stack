//! Every miette code an error from this crate can carry.

/// Every miette code an error from this crate can carry: [`Error`](crate::Error),
/// [`PlanError`](crate::PlanError), [`LabelError`](crate::LabelError),
/// [`LeafBytesError`](crate::LeafBytesError), the term errors in
/// [`sem`](crate::sem), and with the `dynamic` feature the dynamic module's
/// errors. A variant that carries a `stack_kms` or `stack_auth` error carries
/// its code instead.
///
/// A test builds every variant and checks its code is here, so renaming a
/// code means editing this list on purpose. Codes are for crossing a
/// boundary: Rust code that branches on an error matches the variant.
pub const ERROR_CODES: &[&str] = &[
    // `Error`
    "stack_encrypt::aead",
    "stack_encrypt::key_count_mismatch",
    "stack_encrypt::descriptor_too_long",
    "stack_encrypt::config",
    "stack_encrypt::other",
    "stack_encrypt::unsupported_shape",
    "stack_encrypt::context_mismatch",
    "stack_encrypt::response_shape",
    "stack_encrypt::keyset_mismatch",
    "stack_encrypt::foreign_keyset",
    "stack_encrypt::no_keyset",
    "stack_encrypt::not_opened",
    // `LeafBytesError`
    "stack_encrypt::leaf_version",
    "stack_encrypt::leaf_truncated",
    "stack_encrypt::leaf_tag_too_long",
    // `sem::TermError`
    "stack_encrypt::prf_failed",
    "stack_encrypt::ore_failed",
    "stack_encrypt::invalid_match_options",
    "stack_encrypt::empty_term_text",
    // `sem::TermBytesError`
    "stack_encrypt::equality_term_length",
    "stack_encrypt::match_term_length",
    "stack_encrypt::match_position_out_of_range",
    "stack_encrypt::cllw_ciphertext_length",
    // `LabelError`
    "stack_encrypt::label_empty",
    "stack_encrypt::label_empty_segment",
    "stack_encrypt::label_separator",
    "stack_encrypt::label_reserved",
    "stack_encrypt::label_reserved_prefix",
    // `PlanError`
    "stack_encrypt::plan_context_label",
    "stack_encrypt::plan_field_label",
    "stack_encrypt::plan_identity_without_field",
    "stack_encrypt::plan_duplicate_field",
    "stack_encrypt::plan_shared_identity",
    "stack_encrypt::plan_passthrough_indexed",
    "stack_encrypt::plan_duplicate_index",
    "stack_encrypt::plan_empty_indexes",
    "stack_encrypt::plan_field_not_in_plan",
    "stack_encrypt::plan_field_not_in_value",
    "stack_encrypt::plan_field_type",
    "stack_encrypt::plan_no_such_field",
    "stack_encrypt::plan_mixed_ciphers",
    "stack_encrypt::plan_index_not_declared",
    "stack_encrypt::plan_index_options",
    "stack_encrypt::plan_two_context_sources",
    "stack_encrypt::plan_no_context",
    "stack_encrypt::plan_target_with_verbs",
    // `dynamic::Error`
    "stack_encrypt::dynamic_context",
    "stack_encrypt::dynamic_term",
    "stack_encrypt::dynamic_plan",
    "stack_encrypt::dynamic_untyped_index",
    "stack_encrypt::dynamic_source",
    "stack_encrypt::dynamic_record",
    "stack_encrypt::dynamic_internal",
    // `dynamic::TargetError`
    "stack_encrypt::target_none",
    "stack_encrypt::target_unknown",
    "stack_encrypt::target_unproducible",
    "stack_encrypt::target_no_query",
    "stack_encrypt::target_extended",
    "stack_encrypt::target_kind",
    "stack_encrypt::target_column",
    "stack_encrypt::target_plaintext",
    "stack_encrypt::target_stored",
    "stack_encrypt::target_other",
];

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use miette::Diagnostic;
    use uuid::Uuid;

    use super::ERROR_CODES;
    use crate::diagnostic::is_code_of;
    use crate::sem::{MatchOptions, TermBytesError, TermError};
    use crate::target::IndexSpec;
    use crate::{Descriptor, Error, LabelError, LeafBytesError, PlanError};

    /// One of every variant of every error type here. A transparent variant
    /// is built once, to show the code it forwards is listed somewhere.
    fn every_variant() -> Vec<Box<dyn Diagnostic>> {
        let boxed = || Box::new(std::io::Error::other("cause"));
        let (a, b) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let field = || "age".to_string();
        let errors: Vec<Box<dyn Diagnostic>> = vec![
            Box::new(Error::Kms(crate::kms::Error::Unexpected("kms".into()))),
            Box::new(Error::Aead),
            Box::new(Error::KeyCountMismatch {
                expected: 2,
                received: 1,
            }),
            Box::new(Error::DescriptorTooLong { len: 513 }),
            Box::new(Error::Config(boxed())),
            Box::new(Error::Term(TermError::EmptyTermText)),
            Box::new(Error::Other(boxed())),
            Box::new(Error::UnsupportedShape),
            Box::new(Error::ContextMismatch {
                stored: Descriptor::of("users"),
            }),
            Box::new(Error::ResponseShape),
            Box::new(Error::KeysetMismatch { left: a, right: b }),
            Box::new(Error::ForeignKeyset {
                expected: a,
                found: b,
            }),
            Box::new(Error::NoKeyset),
            Box::new(Error::NotOpened),
            Box::new(Error::Plan(PlanError::NoContext)),
            Box::new(LeafBytesError::UnknownVersion(9)),
            Box::new(LeafBytesError::Truncated),
            Box::new(LeafBytesError::TagTooLong(70_000)),
            Box::new(TermError::Prf(boxed())),
            Box::new(TermError::Ore(cllw_ore::Error)),
            Box::new(TermError::InvalidOptions("k out of range")),
            Box::new(TermError::EmptyTermText),
            Box::new(TermError::Bytes(TermBytesError::OddMatchTermsLength(3))),
            Box::new(TermBytesError::WrongEqualityTermLength(3)),
            Box::new(TermBytesError::OddMatchTermsLength(3)),
            Box::new(TermBytesError::MatchPositionOutOfRange {
                position: 900,
                filter_size: 256,
            }),
            Box::new(TermBytesError::MalformedCllwCiphertext(3)),
            Box::new(LabelError::Empty),
            Box::new(LabelError::EmptySegment { index: 0 }),
            Box::new(LabelError::Separator { index: 0 }),
            Box::new(LabelError::Reserved {
                index: 0,
                found: '(',
            }),
            Box::new(LabelError::ReservedPrefix { index: 0 }),
            Box::new(PlanError::ContextLabel(LabelError::Empty)),
            Box::new(PlanError::FieldLabel {
                field: field(),
                source: LabelError::Empty,
            }),
            Box::new(PlanError::IdentityWithoutField),
            Box::new(PlanError::DuplicateField { field: field() }),
            Box::new(PlanError::SharedIdentity {
                identity: "age".into(),
                first: "age".into(),
                second: "years".into(),
            }),
            Box::new(PlanError::PassthroughIndexed { field: field() }),
            Box::new(PlanError::DuplicateIndex {
                at: field(),
                index: "eq",
            }),
            Box::new(PlanError::EmptyIndexes),
            Box::new(PlanError::NotInPlan { field: field() }),
            Box::new(PlanError::NotInValue { field: field() }),
            Box::new(PlanError::FieldType {
                field: field(),
                expected: "int64",
            }),
            Box::new(PlanError::NoSuchField { field: field() }),
            Box::new(PlanError::MixedCiphers),
            Box::new(PlanError::IndexNotDeclared {
                field: field(),
                index: "ore",
            }),
            Box::new(PlanError::IndexOptions {
                field: field(),
                declared: IndexSpec::Match(MatchOptions::default()),
                asked: IndexSpec::Match(MatchOptions {
                    downcase: false,
                    ..MatchOptions::default()
                }),
            }),
            Box::new(PlanError::TwoContextSources {
                first: "the plan",
                second: "the call",
            }),
            Box::new(PlanError::NoContext),
            Box::new(PlanError::TargetWithVerbs { field: field() }),
        ];
        #[cfg(feature = "dynamic")]
        let errors = errors.into_iter().chain(dynamic_variants()).collect();
        errors
    }

    #[cfg(feature = "dynamic")]
    fn dynamic_variants() -> Vec<Box<dyn Diagnostic>> {
        use crate::dynamic::{Error, Reason, TargetError, ValueKind};
        let name = || "email".to_string();
        let target = || "TextEq".to_string();
        vec![
            Box::new(Error::bad_context(Reason::EmptyContext)),
            Box::new(Error::Term {
                field: Some(name()),
                kind: IndexSpec::Equality,
            }),
            Box::new(Error::bad_plan(Reason::NoFields)),
            Box::new(Error::UntypedIndex { field: name() }),
            Box::new(Error::bad_source(Reason::FieldMissing)),
            Box::new(Error::bad_record(Reason::NoCiphertextNode)),
            Box::new(Error::Internal),
            Box::new(Error::Target(TargetError::NoTargets { name: target() })),
            Box::new(Error::Cipher(crate::Error::Aead)),
            Box::new(TargetError::NoTargets { name: target() }),
            Box::new(TargetError::Unknown { name: target() }),
            Box::new(TargetError::Unproducible {
                name: target(),
                reason: "block ORE".into(),
            }),
            Box::new(TargetError::NoQuery { name: target() }),
            Box::new(TargetError::Extended {
                name: name(),
                label: "users/email".into(),
            }),
            Box::new(TargetError::Kind {
                name: name(),
                target: target(),
                expected: Some(ValueKind::String),
                declared: ValueKind::UInt64,
            }),
            Box::new(TargetError::Column {
                name: name(),
                label: "app/users/email".into(),
                reason: "two segments".into(),
            }),
            Box::new(TargetError::Plaintext {
                name: name(),
                target: target(),
                expected: Some(ValueKind::String),
                found: None,
            }),
            Box::new(TargetError::Stored {
                name: name(),
                target: target(),
                reason: "not JSON".into(),
            }),
            Box::new(TargetError::Other(Box::new(std::io::Error::other("boom")))),
        ]
    }

    #[test]
    fn every_variant_has_a_listed_code() {
        let mut seen = BTreeSet::new();
        for error in every_variant() {
            let code = error
                .code()
                .unwrap_or_else(|| panic!("{error:?} has no code"))
                .to_string();
            if code.starts_with("stack_kms::") {
                assert!(crate::kms::ERROR_CODES.contains(&code.as_str()), "{code}");
                continue;
            }
            assert!(is_code_of("stack_encrypt", &code), "{code}");
            assert!(ERROR_CODES.contains(&code.as_str()), "{code} is unlisted");
            seen.insert(code);
        }
        // The dynamic module's codes need its feature to be built.
        let listed: BTreeSet<String> = ERROR_CODES
            .iter()
            .filter(|code| {
                cfg!(feature = "dynamic")
                    || !(code.starts_with("stack_encrypt::dynamic_")
                        || code.starts_with("stack_encrypt::target_"))
            })
            .map(|code| code.to_string())
            .collect();
        assert_eq!(seen, listed, "every listed code is produced");
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
}
