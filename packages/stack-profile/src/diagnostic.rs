//! Inspect error codes, recovery hints, and structured details.
//!
//! [`ProfileError`](crate::ProfileError) provides a readable message through
//! `Display`, a code and optional help through [`miette::Diagnostic`], and
//! structured fields through [`ErrorPayload::payload`]. Use these fields when
//! you need details such as a missing profile's path or a JSON error's line
//! and column. You do not need to parse the message.
//!
//! # Read an error's details
//!
//! Import both traits to access their methods:
//!
//! ```
//! use miette::Diagnostic;
//! use stack_profile::{ErrorPayload, ProfileError};
//!
//! let error = ProfileError::NotFound {
//!     path: "auth.json".into(),
//! };
//!
//! assert_eq!(error.code().unwrap().to_string(), "stack_profile::not_found");
//! assert_eq!(error.payload()["path"], "auth.json");
//! assert!(error.help().is_some());
//! ```
//!
//! In Rust, match error variants to decide how to handle a failure. Codes
//! identify errors when reporting them to another language or service; fields
//! provide the details needed to explain or handle that failure. Payload keys
//! use `snake_case`, and errors without additional details return an empty map.
//!
//! `stack-auth`, `stack-kms`, and `stack-encrypt` use the same trait and
//! re-export it, so you can import it from the crate you already use.
//!
//! # Handle underlying errors with care
//!
//! These crates avoid including sensitive input in diagnostic messages, help,
//! and payloads. Wrapped library errors remain available through
//! [`std::error::Error::source`] for local troubleshooting. Their messages may
//! contain input, credentials, or URLs: inspect them before including them in
//! logs or reports. Do not assume that formatting an entire error chain is
//! safe because its top-level message omits sensitive values.
//!
//! For example, [`describe_json_error`] reports the error kind, line, and
//! column instead of the JSON parser's message, which can quote profile
//! contents containing a token.
//!
//! # Implement an error payload
//!
//! Implement [`ErrorPayload`] for an error that already implements
//! [`miette::Diagnostic`]. Override `payload()` to return its structured
//! details, using the [`payload`] helper to build a map from name/value pairs.
//! Keep the default empty map when there are no useful details.
//!
//! The following policy applies to messages, help, payload fields, and any
//! causes reported through a language binding.
//!
//! ## Allowed details
//!
//! - Keyset IDs and names; counts and lengths; index names and kinds.
//! - Schema field names from a plan or Go struct, rather than field values.
//! - Request kinds and HTTP status codes for ZeroKMS, CipherStash's
//!   key-management service.
//! - Workspace IDs, workspace resource names (CRNs), and regions.
//! - Profile file paths, which identify a store rather than its contents.
//! - The CipherStash token service's OAuth `error_description`, intended for
//!   people to read.
//! - Messages from errors governed by this policy, or fixed library messages
//!   such as those from `url::ParseError`.
//!
//! ## Details to exclude
//!
//! Never include plaintext, key material (data, index, or client keys), access
//! or refresh tokens, ciphertext bytes, search-index bytes, or raw context
//! values. Contexts can contain customer data taken from record fields; report
//! their length and number of parts instead of their contents.
//!
//! Do not forward arbitrary library error messages. Report the operation or
//! error kind instead, and retain the original error through `source()`.
//! Likewise, omit ZeroKMS response bodies because they may echo request data;
//! report the request kind and HTTP status instead.
//!
//! Custom implementations that supply boxed errors, such as
//! `stack_encrypt::Error::Other` or `dynamic::TargetError::Other`, are
//! responsible for their messages: these messages are displayed as supplied.
//! Describe what failed without quoting the value or ciphertext, and do not
//! pass through another library's message.
//!
//! If a new field is not covered by this policy, decide whether it is safe
//! and document that decision here before adding it.

/// Structured error details that callers can read without parsing a message.
///
/// Use [`miette::Diagnostic`] for the code and help, and [`payload`](Self::payload)
/// for fields such as a profile path or a JSON error's position. See the
/// [module documentation](crate::diagnostic) for examples and the policy on error contents.
pub trait ErrorPayload: miette::Diagnostic {
    /// Returns structured details with `snake_case` keys.
    ///
    /// Values must follow this module's policy on error contents. The default
    /// implementation returns an empty map.
    fn payload(&self) -> serde_json::Map<String, serde_json::Value> {
        serde_json::Map::new()
    }
}

/// Builds a payload map from `(name, value)` pairs.
///
/// Use this when implementing [`ErrorPayload::payload`]. Names should use
/// `snake_case`, and values must follow this module's policy on error contents.
pub fn payload<const N: usize>(
    fields: [(&str, serde_json::Value); N],
) -> serde_json::Map<String, serde_json::Value> {
    fields
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect()
}

/// Describes a JSON error by kind, line, and column without quoting input.
///
/// For example: `syntax error at line 1 column 5`. Use this instead of the
/// parser's own message when the input may contain credentials or other
/// sensitive data.
pub fn describe_json_error(error: &serde_json::Error) -> String {
    let kind = match error.classify() {
        serde_json::error::Category::Io => "read error",
        serde_json::error::Category::Syntax => "syntax error",
        serde_json::error::Category::Data => "unexpected data",
        serde_json::error::Category::Eof => "unexpected end of input",
    };
    format!("{kind} at line {} column {}", error.line(), error.column())
}

/// Checks that a code uses the given crate prefix and a `snake_case` name.
///
/// For example, `is_code_of("stack_profile", "stack_profile::not_found")`
/// returns `true`. This checks the format, not whether any error carries the
/// code. Each crate's tests run it on a code from every one of its variants.
///
/// Hidden from the documentation: it exists for those tests, which live in
/// four crates and so need it public, and is not part of the API.
#[doc(hidden)]
pub fn is_code_of(crate_name: &str, code: &str) -> bool {
    let Some(name) = code
        .strip_prefix(crate_name)
        .and_then(|rest| rest.strip_prefix("::"))
    else {
        return false;
    };
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && !name.ends_with('_')
        && !name.contains("__")
}

/// One error of a test's rows, boxed with the name of its type, for
/// [`shared_codes`].
///
/// Derived `Debug` prints a variant without its enum, so two enums'
/// `Unauthorized` variants look alike; the type name tells them apart.
///
/// Hidden from the documentation, as [`is_code_of`] is.
#[doc(hidden)]
pub fn named<E: miette::Diagnostic + 'static>(
    error: E,
) -> (&'static str, Box<dyn miette::Diagnostic>) {
    (std::any::type_name::<E>(), Box::new(error))
}

/// The codes that more than one variant carries, each with the variants
/// that carry it.
///
/// Callers branch on a code, so two variants that share one by mistake (a
/// copied `#[diagnostic(code(..))]` line) are two errors a caller cannot
/// tell apart. Each crate's tests pass one error of every variant, with its
/// type's name (see [`named`]), and compare the result with the codes it
/// shares on purpose.
///
/// A variant is its type's name and its `Debug` text, so two variants
/// with the same message are still two. A wrapper that forwards its inner
/// error's code is not a second variant: its `Debug` text holds the inner
/// error's in parentheses (`Kms(Unexpected("kms"))`), so a row whose `Debug`
/// text holds another row's of the same code that way counts as that row.
/// The test builds the wrapper's inner error with the same value as that
/// error's own row, and gives rows of unrelated variants different values,
/// so that one's `Debug` text does not hold another's by chance.
///
/// Hidden from the documentation, as [`is_code_of`] is.
#[doc(hidden)]
pub fn shared_codes<'a>(
    errors: impl IntoIterator<Item = (&'a str, &'a dyn miette::Diagnostic)>,
) -> std::collections::BTreeMap<String, std::collections::BTreeSet<String>> {
    use std::collections::{BTreeMap, BTreeSet};
    // Per code: each variant's `Debug` text, keyed with its type's name.
    let mut by_code = BTreeMap::<String, BTreeSet<(String, String)>>::new();
    for (type_name, error) in errors {
        if let Some(code) = error.code() {
            let _ = by_code
                .entry(code.to_string())
                .or_default()
                .insert((format!("{error:?}"), type_name.to_owned()));
        }
    }
    by_code
        .into_iter()
        .filter_map(|(code, rows)| {
            let variants: BTreeSet<String> = rows
                .iter()
                .filter(|(debug, _)| {
                    !rows
                        .iter()
                        .any(|(inner, _)| inner != debug && debug.contains(&format!("({inner})")))
                })
                .map(|(debug, type_name)| format!("{type_name}: {debug}"))
                .collect();
            (variants.len() > 1).then_some((code, variants))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, thiserror::Error, miette::Diagnostic)]
    enum Probe {
        #[error("first")]
        #[diagnostic(code(probe::one))]
        First,
        #[error("second")]
        #[diagnostic(code(probe::one))]
        Second,
        #[error("wrapped: {0}")]
        #[diagnostic(transparent)]
        Wrapper(Box<Probe>),
        #[error("third")]
        #[diagnostic(code(probe::three))]
        Third,
    }

    /// Two variants with one code are reported; a wrapper forwarding its
    /// inner error's code, after a prefix of its own, is not a second one.
    #[test]
    fn a_shared_code_is_found_and_a_wrapper_is_not_one() {
        let errors = [
            Probe::First,
            Probe::Second,
            Probe::Third,
            Probe::Wrapper(Box::new(Probe::Third)),
        ];
        let shared = shared_codes(
            errors
                .iter()
                .map(|error| ("Probe", error as &dyn miette::Diagnostic)),
        );
        assert_eq!(shared.keys().collect::<Vec<_>>(), ["probe::one"]);
        assert_eq!(shared["probe::one"].len(), 2);
    }

    #[derive(Debug, thiserror::Error, miette::Diagnostic)]
    enum Other {
        #[error("first")]
        #[diagnostic(code(probe::one))]
        First,
    }

    /// Two variants with the same message and the same code are two
    /// variants, also when they share a name in two enums.
    #[test]
    fn a_shared_code_is_found_when_the_messages_are_the_same() {
        let rows = [named(Probe::First), named(Other::First)];
        let shared = shared_codes(rows.iter().map(|(name, error)| (*name, error.as_ref())));
        assert_eq!(shared.keys().collect::<Vec<_>>(), ["probe::one"]);
        assert_eq!(shared["probe::one"].len(), 2, "{shared:#?}");
    }

    #[test]
    fn a_code_is_its_crate_then_one_snake_case_name() {
        for code in [
            "stack_encrypt::aead",
            "stack_encrypt::foreign_keyset",
            "stack_kms::keyset_not_found",
            "stack_encrypt::v1_leaf",
        ] {
            let crate_name = code.split("::").next().unwrap_or_default();
            assert!(is_code_of(crate_name, code), "{code}");
        }
        for (crate_name, code) in [
            ("stack_encrypt", "stack_kms::aead"),
            ("stack_encrypt", "stack_encryptaead"),
            ("stack_encrypt", "stack_encrypt::"),
            ("stack_encrypt", "stack_encrypt::Aead"),
            ("stack_encrypt", "stack_encrypt::foreign-keyset"),
            ("stack_encrypt", "stack_encrypt::plan::no_context"),
            ("stack_encrypt", "stack_encrypt::_aead"),
            ("stack_encrypt", "stack_encrypt::1aead"),
            ("stack_encrypt", "stack_encrypt::aead_"),
            ("stack_encrypt", "stack_encrypt::foreign__keyset"),
            ("stack_auth", "INVALID_CRN"),
        ] {
            assert!(!is_code_of(crate_name, code), "{code}");
        }
    }

    #[test]
    fn payload_keeps_every_field() {
        let fields = payload([("field", "age".into()), ("count", 2.into())]);
        assert_eq!(fields.len(), 2);
        assert_eq!(fields["field"], "age");
        assert_eq!(fields["count"], 2);
    }
}
