//! The mapping from [`stack_encrypt::Error`] (and the dynamic and KMS
//! errors under it) onto the status table.
//!
//! The numbers themselves are [`stack_guest_abi::status`]'s — one table for
//! every guest, never renumbered, decoded once by the Go host — and are
//! re-exported here so this crate's modules and tests name them as they
//! always have. Defined outside the wasm32-gated ABI module so native builds
//! — the ops unit tests — can reference them too.
//!
//! What this guest decides is *which* number a given failure is. Codes 5–10
//! map the ZeroKMS request outcomes ([`ViturRequestErrorKind`]-shaped) so a
//! Go caller can distinguish a bad token from a tampered ciphertext without
//! parsing strings; 11 is a term-derivation failure (a caller-input
//! condition, e.g. match text that yields no tokens); 12 is a keyset-scoped
//! open refusing a leaf whose keyset id is not the scope's — a host's own
//! constraint, checked before the leaf is authenticated and so not a
//! statement about tampering.
//!
//! # What each verdict means for this guest
//!
//! The shared table documents each code as the verdict a host acts on;
//! what follows is how this guest's exports arrive at them.
//!
//! - [`STATUS_AUTH`] is an AEAD open failure. Against ZeroKMS a wrong
//!   context does not get that far — every data key is bound to its
//!   context's descriptor, so the retrieve is refused first, as
//!   [`STATUS_KMS_FORBIDDEN`]: that is the production form of a
//!   wrong-context open. Only a key source that ignores descriptors (the
//!   native tests' fake) reports a wrong context as `STATUS_AUTH`.
//! - [`STATUS_ENCODING`] covers, besides malformed transport bytes and a
//!   bad pointer/length pair, a malformed config and an empty context on
//!   the record and term exports.
//! - [`STATUS_KMS_UNAUTHORIZED`] is kept to a refused credential. A token
//!   with no ZeroKMS `services` claim, or a host `token_get` that failed,
//!   arrives through the auth strategy too but is [`STATUS_KMS_TRANSPORT`]:
//!   no number of refreshes can fix it (`status_for_auth` draws the line).
//! - [`STATUS_KMS_TRANSPORT`] also covers an endpoint that could not be
//!   resolved: no `zerokms_url` in the config *and* no ZeroKMS entry in the
//!   token's `services` claim.
//! - [`STATUS_FOREIGN_KEYSET`] is an opening export constrained to one
//!   keyset (`{"name"}`, `{"id"}` or `{"default"}` in its options) whose
//!   leaf named another. A host that means "whichever keyset" opens with
//!   `{"any"}`. The comparison reads the keyset id *out of the leaf*, before
//!   anything is retrieved and so before anything is authenticated, which
//!   means a flipped byte in that field arrives here exactly as a genuinely
//!   misrouted row does. The id is bound into the leaf's context, so the
//!   tampered leaf cannot go on to open — it fails as [`STATUS_AUTH`] — but
//!   that verdict is only reached on the path where the constraint let it
//!   through. Read this status as "not this keyset's row", never as "an
//!   untampered row".
//! - [`STATUS_CONTEXT_MISMATCH`] is the same kind of constraint on the
//!   record export: the host named, in its options, the context it expects
//!   a record's context field to hold, and the stored field says otherwise.
//!   The field is a passthrough, so this is read before anything is
//!   retrieved or authenticated: "not the row this caller asked for", never
//!   "an untampered row". A stored context changed in storage fails later,
//!   as [`STATUS_KMS_FORBIDDEN`] or [`STATUS_AUTH`], because every field was
//!   sealed under the original.

use stack_auth::AuthError;
use stack_encrypt::ErrorPayload;
use stack_guest_abi::last_error;
use stack_kms::{GenerateKeyError, LoadKeysetError, RetrieveKeyError};
use zerokms_protocol::{ViturRequestError, ViturRequestErrorKind};

pub use stack_guest_abi::status::{
    STATUS_AUTH, STATUS_CONTEXT_MISMATCH, STATUS_ENCODING, STATUS_FOREIGN_KEYSET, STATUS_INTERNAL,
    STATUS_KMS_CONFLICT, STATUS_KMS_FORBIDDEN, STATUS_KMS_NOT_FOUND, STATUS_KMS_OTHER,
    STATUS_KMS_TRANSPORT, STATUS_KMS_UNAUTHORIZED, STATUS_STATE, STATUS_TERM,
};

/// Record a sealing/opening error as the last error
/// ([`last_error`]) and return its status: what every export's
/// `map_err` calls, so the status a host acts on and the error it can ask
/// for come from the one site.
pub fn fail_error(error: &stack_encrypt::Error) -> u32 {
    record(error);
    status_for_error(error)
}

/// [`fail_error`] for a dynamic-path error.
pub fn fail_dynamic(error: &stack_encrypt::dynamic::Error) -> u32 {
    record(error);
    status_for_dynamic(error)
}

/// Record an error with its structured fields and this guest's describer.
fn record<E: ErrorPayload>(error: &E) {
    last_error::record_with(error, error.payload(), &describe);
}

/// What this guest vouches for in a cause from another library: a ZeroKMS
/// request error by its kind and static message (its response stays behind
/// its own source), stack-kms's response classifications by their
/// deliberately bodiless messages, and what [`last_error::describe_std`]
/// knows. Anything else is reported only as a cause from another library.
pub fn describe(cause: &(dyn std::error::Error + 'static)) -> Option<String> {
    if let Some(error) = cause.downcast_ref::<ViturRequestError>() {
        return Some(format!("ZeroKMS request failed ({error})"));
    }
    if let Some(error) = cause.downcast_ref::<stack_kms::FailureResponse>() {
        return Some(format!("ZeroKMS responded with status {}", error.status));
    }
    if cause
        .downcast_ref::<stack_kms::BaseUrlUnresolved>()
        .is_some()
        || cause
            .downcast_ref::<stack_kms::UnexpectedContentType>()
            .is_some()
    {
        return Some(cause.to_string());
    }
    last_error::describe_std(cause)
}

/// Map a sealing/opening error onto the ABI status word.
///
/// Total over [`stack_encrypt::Error`] (which is `#[non_exhaustive]`, so the
/// catch-all arm is required as well as convenient): composition-bug variants
/// (`ResponseShape`, `KeysetMismatch`, `NoKeyset`, `KeyCountMismatch`) and
/// everything else unexpected collapse into [`STATUS_INTERNAL`] — statuses
/// distinguish what a host can act on, not what it can only log.
pub fn status_for_error(error: &stack_encrypt::Error) -> u32 {
    match error {
        stack_encrypt::Error::Aead => STATUS_AUTH,
        stack_encrypt::Error::Term(_) => STATUS_TERM,
        stack_encrypt::Error::ForeignKeyset { .. } => STATUS_FOREIGN_KEYSET,
        // A record's stored context field is not the one the host named in
        // its options: the host's own constraint, checked before any key is
        // retrieved, like a foreign keyset and unlike a wrong-context open.
        stack_encrypt::Error::ContextMismatch { .. } => STATUS_CONTEXT_MISMATCH,
        stack_encrypt::Error::Kms(kms) => status_for_kms(kms),
        // A context that renders past ZeroKMS's descriptor limit is the
        // caller's input, refused before any request is sent.
        stack_encrypt::Error::DescriptorTooLong { .. } => STATUS_ENCODING,
        // A plan refusal — a value or stored record that does not fit the
        // plan it is run with, a typed field opened to another kind — is a
        // statement about the caller's input, raised by the engine the
        // record exports run their plans through.
        stack_encrypt::Error::Plan(_) => STATUS_ENCODING,
        _ => STATUS_INTERNAL,
    }
}

/// A dynamic-path error as a status code.
///
/// The split the library draws is the one the ABI needs: `Context`, `Term`,
/// `Plan`, `UntypedIndex`, `Source` and `Record` are each a statement about
/// the caller's input, decided before any key is minted or retrieved, so they are
/// [`STATUS_ENCODING`] — named one by one, because that verdict is the
/// host's to act on and must be given deliberately. `Cipher` defers to
/// [`status_for_error`]; `Internal` is the library's own invariant failing
/// — a slot count that did not line up, a re-proof that could not fail —
/// and is [`STATUS_INTERNAL`], never a verdict on the input.
///
/// The catch-all is required (`Error` is `#[non_exhaustive]`, so a variant
/// added upstream cannot fail this match at compile time) and it goes to
/// [`STATUS_INTERNAL`]: an unclassified failure is reported as ours until
/// someone reads the new variant and says otherwise here. The one wrong
/// default would be the other way round — telling a host to fix its input
/// over a fault that is not in its input.
pub fn status_for_dynamic(error: &stack_encrypt::dynamic::Error) -> u32 {
    use stack_encrypt::dynamic::Error;
    match error {
        Error::Context { .. }
        | Error::Term { .. }
        | Error::Plan { .. }
        | Error::UntypedIndex { .. }
        | Error::Source { .. }
        | Error::Record { .. } => STATUS_ENCODING,
        Error::Cipher(e) => status_for_error(e),
        // A target refusal is a statement about the plan, the label or the
        // value (an unknown or unproducible type, an extended plan, a value
        // of another kind, stored bytes that are not the type) — malformed
        // input, like the rest — save the resolver's own failure.
        Error::Target(stack_encrypt::dynamic::TargetError::Other(_)) => STATUS_INTERNAL,
        Error::Target(_) => STATUS_ENCODING,
        Error::Internal => STATUS_INTERNAL,
        _ => STATUS_INTERNAL,
    }
}

// These matches are deliberately exhaustive — no `_` arms. None of the
// stack-kms error enums is `#[non_exhaustive]`, so exhaustiveness is free
// compiler coverage: `GenerateKeyError` already grew `Unauthorized` /
// `Forbidden` out of the shared `From<ViturRequestError>` pattern, and a
// variant added tomorrow must be classified here before this crate builds,
// instead of silently falling through a catch-all to [`STATUS_KMS_OTHER`]
// and costing a Go host its refresh signal.
fn status_for_kms(error: &stack_kms::Error) -> u32 {
    match error {
        stack_kms::Error::GenerateKey(e) => match e {
            GenerateKeyError::Unauthorized => STATUS_KMS_UNAUTHORIZED,
            GenerateKeyError::Forbidden => STATUS_KMS_FORBIDDEN,
            GenerateKeyError::RequestFailed(e) => status_for_kind(&e.kind),
            GenerateKeyError::GenerateIv(_) => STATUS_INTERNAL,
            // A response that did not line up with the request, or key
            // material the client could not use: server-side malformations.
            GenerateKeyError::InvalidNumberOfKeys { .. }
            | GenerateKeyError::InvalidKeyMaterial(_) => STATUS_KMS_OTHER,
        },
        stack_kms::Error::RetrieveKey(e) => match e {
            RetrieveKeyError::RequestFailed(e) => status_for_kind(&e.kind),
            // A per-key server-side "no key for this iv/tag".
            RetrieveKeyError::FailedRetrieval(_) => STATUS_KMS_NOT_FOUND,
            RetrieveKeyError::InvalidNumberOfKeys { .. }
            | RetrieveKeyError::InvalidKeyMaterial(_) => STATUS_KMS_OTHER,
        },
        stack_kms::Error::LoadKeyset(e) => match e {
            LoadKeysetError::Unauthorized(_) => STATUS_KMS_UNAUTHORIZED,
            LoadKeysetError::Forbidden(_) => STATUS_KMS_FORBIDDEN,
            LoadKeysetError::KeysetNotFound(_) => STATUS_KMS_NOT_FOUND,
            LoadKeysetError::RequestFailed(e) => status_for_kind(&e.kind),
            LoadKeysetError::InvalidKeyMaterial(_) => STATUS_KMS_OTHER,
        },
        stack_kms::Error::Auth(auth) => status_for_auth(auth),
        stack_kms::Error::ConnectionInit(_) | stack_kms::Error::InvalidEndpoint(_) => {
            STATUS_KMS_TRANSPORT
        }
        stack_kms::Error::Unexpected(_) => STATUS_KMS_OTHER,
    }
}

/// Split the auth strategy's failures into "the credential was refused"
/// (retry after a refresh) and "the client is misconfigured" (retrying is a
/// spin).
///
/// This split matters because `StackKms::get_token` runs *before* any request
/// leaves the guest and folds two very different things into
/// [`stack_kms::Error::Auth`]: a genuinely refused credential, and
/// `token.zerokms_url()` failing because the config named no `zerokms_url`
/// and the host's token carries no ZeroKMS `services` claim — an
/// `AuthError::InvalidToken`. Mapping the latter to
/// [`STATUS_KMS_UNAUTHORIZED`] would tell a Go host to refresh its token and
/// try again, forever, over a config problem no token can fix.
fn status_for_auth(error: &AuthError) -> u32 {
    match error {
        // The server (or the strategy) refused the credential itself: a new
        // token is the fix. `AuthError` is `#[non_exhaustive]`, so the arms
        // below need the `_` catch-all and a variant added upstream would
        // silently classify as TRANSPORT ("do not refresh") — which is why
        // the refresh signal keys off `is_credential_rejection()`, whose
        // match *is* exhaustive inside stack-auth: new refused-credential
        // variants are classified there, at compile time, and picked up here
        // with no change.
        e if e.is_credential_rejection() => STATUS_KMS_UNAUTHORIZED,
        // Authenticated, but not allowed.
        AuthError::AccessDenied(_) | AuthError::UsageLimitExceeded(_) => STATUS_KMS_FORBIDDEN,
        // Server-side faults with no client-side remedy.
        AuthError::Server(_) | AuthError::Internal(_) => STATUS_KMS_OTHER,
        // Everything else is configuration or host transport: a malformed or
        // claim-less token (`InvalidToken` — the unresolved-endpoint case), a
        // bad URL/CRN/region/workspace, a failed request to the token issuer,
        // or `Custom`, which is what `HostTokenStrategy` reports when the
        // host's `token_get` import returns non-zero or hands back bytes that
        // are not a token.
        _ => STATUS_KMS_TRANSPORT,
    }
}

fn status_for_kind(kind: &ViturRequestErrorKind) -> u32 {
    match kind {
        ViturRequestErrorKind::Unauthorized => STATUS_KMS_UNAUTHORIZED,
        ViturRequestErrorKind::Forbidden => STATUS_KMS_FORBIDDEN,
        ViturRequestErrorKind::NotFound => STATUS_KMS_NOT_FOUND,
        ViturRequestErrorKind::Conflict => STATUS_KMS_CONFLICT,
        ViturRequestErrorKind::PrepareRequest | ViturRequestErrorKind::SendRequest => {
            STATUS_KMS_TRANSPORT
        }
        _ => STATUS_KMS_OTHER,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerokms_protocol::ViturRequestError;

    fn vitur(kind: ViturRequestErrorKind) -> ViturRequestError {
        ViturRequestError::new(kind, "stubbed", std::io::Error::other("boom"))
    }

    #[test]
    fn aead_and_composition_errors_map_to_the_vitaminc_codes() {
        assert_eq!(status_for_error(&stack_encrypt::Error::Aead), STATUS_AUTH);
        assert_eq!(
            status_for_error(&stack_encrypt::Error::DescriptorTooLong { len: 513 }),
            STATUS_ENCODING
        );
        assert_eq!(
            status_for_error(&stack_encrypt::Error::ResponseShape),
            STATUS_INTERNAL
        );
    }

    #[test]
    fn kms_request_kinds_map_to_distinct_codes() {
        let cases = [
            (ViturRequestErrorKind::Unauthorized, STATUS_KMS_UNAUTHORIZED),
            (ViturRequestErrorKind::Forbidden, STATUS_KMS_FORBIDDEN),
            (ViturRequestErrorKind::NotFound, STATUS_KMS_NOT_FOUND),
            (ViturRequestErrorKind::Conflict, STATUS_KMS_CONFLICT),
            (ViturRequestErrorKind::SendRequest, STATUS_KMS_TRANSPORT),
            (ViturRequestErrorKind::ParseResponse, STATUS_KMS_OTHER),
        ];
        for (i, (kind, expected)) in cases.into_iter().enumerate() {
            let err = stack_encrypt::Error::Kms(stack_kms::Error::RetrieveKey(
                RetrieveKeyError::RequestFailed(vitur(kind)),
            ));
            assert_eq!(status_for_error(&err), expected, "case {i}");
        }
    }

    #[test]
    fn a_missing_data_key_is_not_found() {
        let err = stack_encrypt::Error::Kms(stack_kms::Error::RetrieveKey(
            RetrieveKeyError::FailedRetrieval("no key".into()),
        ));
        assert_eq!(status_for_error(&err), STATUS_KMS_NOT_FOUND);
    }

    /// The exact configuration the guest hits when `se_cipher_init` is given
    /// no `zerokms_url` and the host hands over a token with no ZeroKMS
    /// `services` claim: `StackKms::get_token` fails *before* sending
    /// anything, with the real error this produces. It must not read as "your
    /// token was rejected".
    #[test]
    fn an_unresolvable_endpoint_is_transport_not_unauthorized() {
        use stack_auth::{SecretToken, ServiceToken};

        // A token that is not a CTS-minted JWT, so it carries no services
        // claim at all — the error comes from `zerokms_url()` itself, not a
        // hand-built variant.
        let token = ServiceToken::new(SecretToken::new("not-a-cts-jwt"));
        let err = token
            .zerokms_url()
            .expect_err("a non-JWT has no services claim");
        assert!(
            matches!(err, stack_auth::AuthError::InvalidToken(_)),
            "expected InvalidToken, got: {err:?}"
        );

        let status = status_for_error(&stack_encrypt::Error::Kms(stack_kms::Error::Auth(err)));
        assert_eq!(
            status, STATUS_KMS_TRANSPORT,
            "a config fault must not tell the host to refresh and retry"
        );
    }

    #[test]
    fn a_failed_host_token_import_is_transport_not_unauthorized() {
        // What `HostTokenStrategy` reports when `token_get` returns non-zero.
        let err = stack_auth::AuthError::Custom(stack_auth::CustomError(
            "host token_get failed with status 7".to_string(),
        ));
        assert_eq!(
            status_for_error(&stack_encrypt::Error::Kms(stack_kms::Error::Auth(err))),
            STATUS_KMS_TRANSPORT
        );
    }

    #[test]
    fn a_refused_credential_is_still_unauthorized() {
        let err = stack_auth::AuthError::TokenExpired(stack_auth::TokenExpired);
        assert_eq!(
            status_for_error(&stack_encrypt::Error::Kms(stack_kms::Error::Auth(err))),
            STATUS_KMS_UNAUTHORIZED
        );
    }

    #[test]
    fn a_plan_refusal_is_the_callers_input() {
        assert_eq!(
            status_for_error(&stack_encrypt::Error::Plan(
                stack_encrypt::PlanError::NoContext
            )),
            STATUS_ENCODING
        );
    }

    #[test]
    fn a_context_mismatch_is_its_own_status() {
        use stack_encrypt::Describe;
        let stored = stack_encrypt::Label::parse("tenants/globex")
            .expect("a label")
            .descriptor();
        assert_eq!(
            status_for_error(&stack_encrypt::Error::ContextMismatch { stored }),
            STATUS_CONTEXT_MISMATCH
        );
    }

    #[test]
    fn a_foreign_keyset_is_its_own_status_and_scope_bugs_are_internal() {
        let (a, b) = (uuid::Uuid::from_u128(1), uuid::Uuid::from_u128(2));
        assert_eq!(
            status_for_error(&stack_encrypt::Error::ForeignKeyset {
                expected: a,
                found: b
            }),
            STATUS_FOREIGN_KEYSET
        );
        assert_eq!(
            status_for_error(&stack_encrypt::Error::KeysetMismatch { left: a, right: b }),
            STATUS_INTERNAL
        );
        assert_eq!(
            status_for_error(&stack_encrypt::Error::NoKeyset),
            STATUS_INTERNAL
        );
    }

    /// The two `Error::Target` arms, in order: every target refusal is the
    /// caller's input, and the resolver's own failure is never reported as
    /// such. Swapping the arms, or dropping the `Other` one, fails here.
    #[test]
    fn target_refusals_are_encoding_and_a_resolver_failure_is_internal() {
        use stack_encrypt::dynamic::{Error, TargetError};
        use vitaminc_aead_value::ValueKind;
        let refusals = [
            TargetError::NoTargets {
                name: "TextEq".into(),
            },
            TargetError::Unknown {
                name: "Nope".into(),
            },
            TargetError::Unproducible {
                name: "TextOrdOre".into(),
                reason: "block ORE".into(),
            },
            TargetError::Extended {
                name: "email".into(),
                label: "users/email".into(),
            },
            TargetError::ContextField {
                name: "email".into(),
                context_field: "tenant".into(),
            },
            TargetError::NoQuery {
                name: "Text".into(),
            },
            TargetError::Kind {
                name: "email".into(),
                target: "TextEq".into(),
                expected: Some(ValueKind::String),
                declared: ValueKind::UInt64,
            },
            TargetError::Column {
                name: "email".into(),
                label: "app/users/email".into(),
                reason: "two segments".into(),
            },
            TargetError::Plaintext {
                name: "email".into(),
                target: "TextEq".into(),
                expected: Some(ValueKind::String),
                found: None,
            },
            TargetError::Stored {
                name: "email".into(),
                target: "TextEq".into(),
                reason: "not JSON".into(),
            },
        ];
        for refusal in refusals {
            let label = refusal.to_string();
            assert_eq!(
                status_for_dynamic(&Error::Target(refusal)),
                STATUS_ENCODING,
                "{label}: a target refusal is the caller's input"
            );
        }
        assert_eq!(
            status_for_dynamic(&Error::Target(TargetError::Other("boom".into()))),
            STATUS_INTERNAL,
            "the resolver's own failure is never the caller's input"
        );
    }

    #[test]
    fn dynamic_input_errors_are_encoding_and_a_library_bug_is_internal() {
        use stack_encrypt::dynamic::{Error, Reason};
        use stack_encrypt::sem::MatchOptions;
        use stack_encrypt::target::IndexSpec;
        let age = || Some("age".to_string());
        for (label, err) in [
            (
                "a bad context",
                Error::Context {
                    field: None,
                    reason: Reason::EmptyContext,
                },
            ),
            (
                "a bad term request",
                Error::Term {
                    field: age(),
                    kind: IndexSpec::Match(MatchOptions::default()),
                },
            ),
            (
                "a bad plan",
                Error::Plan {
                    field: age(),
                    reason: Reason::DuplicateOutput,
                },
            ),
            (
                "an indexed field with no type",
                Error::UntypedIndex {
                    field: "age".to_string(),
                },
            ),
            (
                "a bad source",
                Error::Source {
                    field: age(),
                    reason: Reason::FieldMissing,
                },
            ),
            (
                "a bad record",
                Error::Record {
                    field: age(),
                    reason: Reason::NoCiphertextNode,
                },
            ),
        ] {
            assert_eq!(
                status_for_dynamic(&err),
                STATUS_ENCODING,
                "{label} is the caller's input"
            );
        }
        assert_eq!(
            status_for_dynamic(&Error::Internal),
            STATUS_INTERNAL,
            "a library invariant failing is never the caller's fault"
        );
        assert_eq!(
            status_for_dynamic(&Error::Cipher(stack_encrypt::Error::Aead)),
            STATUS_AUTH,
            "a cipher failure keeps its own status"
        );
    }

    #[test]
    fn term_errors_are_derivation_failures() {
        // An empty context never reaches a term — it is `STATUS_ENCODING`
        // at the boundary, where the context is proven — so every term
        // error that does arrive is a derivation failure.
        assert_eq!(
            status_for_error(&stack_encrypt::Error::Term(
                stack_encrypt::sem::TermError::EmptyTermText
            )),
            STATUS_TERM
        );
    }
}
