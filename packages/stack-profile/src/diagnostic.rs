//! The structured fields an error carries, and what an error may contain.

/// The structured fields an error carries beside its message, its miette
/// [`code`](miette::Diagnostic::code) and its help.
///
/// Every error in `stack-profile`, `stack-auth`, `stack-kms` and
/// `stack-encrypt` implements it. Those are the crates whose errors reach a
/// caller through a language binding. The trait is defined here because this
/// crate is the one all four depend on, and each of the others re-exports
/// it, so a caller names it from the crate it uses.
///
/// [`payload`](Self::payload) gives the error's facts as data: which keyset a
/// value was sealed under, which plan field was refused, how long a context
/// was. A binding hands them to its caller beside the code, so the caller can
/// branch on a field instead of parsing a message. Codes are for crossing a
/// boundary: Rust code that needs to branch on an error matches the variant.
///
/// # What an error may contain
///
/// The rule covers an error's message (its `Display`), its help and every
/// field of its payload, and every error under it that a binding reports as
/// a cause. The Go guests enforce it with a leak test: every error path a
/// test can reach is driven with marker values, and the test fails if a
/// marker appears anywhere in what the guest encodes.
///
/// **Allowed:**
///
/// - keyset ids and names
/// - counts and lengths
/// - term kinds and index names
/// - field names from a plan or a Go struct: these describe the schema, not
///   the data
/// - ZeroKMS request kinds and HTTP status numbers
/// - workspace ids, workspace CRNs and region names
/// - the path of a profile file, which names the store and not its contents
/// - a description the CipherStash token service sends for a person to read
///   (an OAuth `error_description`)
/// - the message of an error this rule also governs: one from these four
///   crates, or from a library whose messages are fixed text, such as
///   `url::ParseError`
///
/// **Never allowed:**
///
/// - plaintext, or any part of it
/// - key material: data keys, index keys, client keys
/// - access tokens and refresh tokens
/// - ciphertext bytes and index term bytes
/// - raw context values
///
/// **Decided, with the reason:**
///
/// - **Context descriptors are left out.** A context can be built from a
///   record field (`#[stash(context_field)]`), so its descriptor can hold
///   customer data. An error about a context gives the descriptor's length
///   and its number of parts instead.
/// - **An error from another library gives its type, not its message.** That
///   message is text these crates do not control: an HTTP client's error can
///   carry a URL with its query string, and a JSON parser's can quote the
///   input it refused. Where these crates wrap such an error, their message
///   names what failed, and the wrapped error stays reachable through
///   [`source`](std::error::Error::source) for a caller in the same process,
///   who decides what to log. It never appears in a message or a payload.
/// - **A slot any implementation can fill shows that implementation's
///   message**, and the implementation answers for it under this rule. Such
///   a slot is a `Box<dyn Error>` a trait implementor hands back:
///   `stack_encrypt::Error::Other` from an `EncryptFrom` or `DecryptInto`
///   implementation, `TargetError::Other` from an EQL type resolver. Their
///   own report ("unsupported EQL ciphertext producer or version") is the
///   one a caller needs, so it is shown as given. An implementation that
///   fills one names what it refused, never a byte of the value or the
///   ciphertext, and does not pass another library's message through.
/// - **ZeroKMS response bodies are left out**, until someone confirms that a
///   ZeroKMS error body never echoes what the request carried. An error from
///   a ZeroKMS request gives the request kind and the HTTP status instead.
///
/// A field that falls under none of these needs a decision before it is
/// added, recorded here.
pub trait ErrorPayload: miette::Diagnostic {
    /// The error's structured fields, keyed by `snake_case` name. Every value
    /// obeys the rule above. Empty unless the error has facts worth
    /// branching on.
    fn payload(&self) -> serde_json::Map<String, serde_json::Value> {
        serde_json::Map::new()
    }
}

/// A payload built from `(name, value)` pairs.
///
/// Shared by the four crates' [`ErrorPayload`] impls so each reads as a list
/// of fields rather than a map built by hand.
pub fn payload<const N: usize>(
    fields: [(&str, serde_json::Value); N],
) -> serde_json::Map<String, serde_json::Value> {
    fields
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect()
}

/// A JSON error as the rule allows it: what kind of error, and where. Never
/// serde_json's own message, which can quote the input it refused:
/// `syntax error at line 1 column 5`.
pub fn describe_json_error(error: &serde_json::Error) -> String {
    let kind = match error.classify() {
        serde_json::error::Category::Io => "read error",
        serde_json::error::Category::Syntax => "syntax error",
        serde_json::error::Category::Data => "unexpected data",
        serde_json::error::Category::Eof => "unexpected end of input",
    };
    format!("{kind} at line {} column {}", error.line(), error.column())
}

/// Whether `code` has the shape every code from these crates has: the crate's
/// name, `::`, then a `snake_case` name — `stack_encrypt::foreign_keyset`.
///
/// Each crate's code test runs every code it can produce through this, so a
/// code in the wrong crate's namespace, or spelled in another case, fails
/// there rather than reaching a binding.
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

#[cfg(test)]
mod tests {
    use super::*;

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
