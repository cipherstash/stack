//! Status codes for the ABI's packed result encoding (see [`crate::abi`]),
//! and the mapping from [`stack_encrypt::Error`] onto them.
//!
//! Defined outside the wasm32-gated ABI module so native builds — the ops
//! unit tests — can reference them too. The Go host mirrors these values;
//! they are part of the guest/host contract and must not be renumbered.
//!
//! Codes 1–4 are byte-for-byte the vitaminc guest's codes (`vcencrypt`'s
//! `status.rs`), so the two guests read identically from the host side;
//! code 3 there is "unknown handle", and here — where there is no handle —
//! it is the call-order violation that means the same thing to a host: no
//! cipher for this call. Codes 5–10 map the ZeroKMS request outcomes
//! ([`ViturRequestErrorKind`]-shaped) so a Go caller can distinguish a bad
//! token from a tampered ciphertext without parsing strings. Code 11 is a
//! term-derivation failure (a caller-input condition, e.g. match text that
//! yields no tokens). Code 12 is a keyset-scoped open refusing a leaf whose
//! keyset id is not the scope's — a host's own constraint, checked before
//! the leaf is authenticated and so not a statement about tampering.

use stack_auth::AuthError;
use stack_kms::{GenerateKeyError, LoadKeysetError, RetrieveKeyError};
use zerokms_protocol::ViturRequestErrorKind;

/// AEAD open failure: a tampered ciphertext, a wrong element derivation, or
/// a wrong AAD that reached the AEAD. Against ZeroKMS a wrong AAD does not
/// get that far — every data key is bound to its context's descriptor, so
/// the retrieve is refused first, as [`STATUS_KMS_FORBIDDEN`]. Only a key
/// source that ignores descriptors (the native tests' fake) reports a wrong
/// AAD here.
pub const STATUS_AUTH: u32 = 1;
/// Invalid input at the boundary: malformed transport bytes, a malformed
/// cipher config, an empty encryption context, or a pointer/length pair that
/// fails validation against linear memory.
pub const STATUS_ENCODING: u32 = 2;
/// The call is out of order: an operation before `se_cipher_init`, or
/// after `se_shutdown`, or `se_cipher_init` twice. A host fixes its call
/// sequence; nothing here is a guest bug. (The vitaminc guest's code 3 is
/// "unknown handle", the same condition under a handle scheme.)
pub const STATUS_STATE: u32 = 3;
/// A caught panic, a response that did not match its
/// requests, or any other unexpected internal failure.
pub const STATUS_INTERNAL: u32 = 4;
/// ZeroKMS (or the auth strategy) rejected the *credential*: an expired or
/// rejected access token, or a credential exchange the server refused.
///
/// The one status a host should answer by refreshing the token and retrying.
/// Deliberately narrow for that reason: a configuration fault that merely
/// *arrives* through the auth strategy — a token with no ZeroKMS `services`
/// claim, a host `token_get` that failed — is [`STATUS_KMS_TRANSPORT`], since
/// no number of refreshes can fix it.
pub const STATUS_KMS_UNAUTHORIZED: u32 = 5;
/// ZeroKMS rejected the request as forbidden: the token is valid but lacks
/// permission, the keyset is disabled, the organisation is over its usage
/// allowance — or, on decrypt, the AAD/context is not the one the value
/// was sealed under, so the data key cannot be re-derived. That last one is
/// the production form of a wrong-context open; see [`STATUS_AUTH`].
pub const STATUS_KMS_FORBIDDEN: u32 = 6;
/// ZeroKMS could not find the resource: an unknown keyset (or client), or a
/// data key that does not exist for the presented `iv`/`tag`.
pub const STATUS_KMS_NOT_FOUND: u32 = 7;
/// ZeroKMS reported a resource conflict.
pub const STATUS_KMS_CONFLICT: u32 = 8;
/// No ZeroKMS verdict was reached: the host's `transport_send` errored, the
/// host's `token_get` errored, the endpoint is unknown or invalid (no
/// `zerokms_url` in the config *and* no ZeroKMS entry in the token's
/// `services` claim), or the request could not be prepared.
///
/// Not retryable by refreshing a token — these are configuration or host
/// faults. See [`STATUS_KMS_UNAUTHORIZED`] for the one that is.
pub const STATUS_KMS_TRANSPORT: u32 = 9;
/// ZeroKMS failed in a way none of the codes above capture: a malformed
/// response, invalid key material, or an unclassified server error.
pub const STATUS_KMS_OTHER: u32 = 10;
/// An index term failed to derive: e.g. match text that yields no tokens, or
/// a value/scheme combination the term does not support.
pub const STATUS_TERM: u32 = 11;
/// An opening export was constrained to one keyset (`{"name"}`, `{"id"}` or
/// `{"default"}` in its options) and the leaf named another. Refused before
/// any key is retrieved. A host that means "whichever keyset" opens with
/// `{"any"}`.
///
/// A constraint failure, and only that — never provenance. The comparison
/// reads the keyset id *out of the leaf*, before anything is retrieved and
/// so before anything is authenticated, which means a flipped byte in that
/// field arrives here exactly as a genuinely misrouted row does. The id is
/// bound into the leaf AAD, so the tampered leaf cannot go on to open —
/// it fails as [`STATUS_AUTH`] — but that verdict is only reached on the
/// path where the constraint let it through. Read this status as "not this
/// keyset's row", never as "an untampered row".
pub const STATUS_FOREIGN_KEYSET: u32 = 12;

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
        stack_encrypt::Error::Kms(kms) => status_for_kms(kms),
        // A context that renders past ZeroKMS's descriptor limit is the
        // caller's input, refused before any request is sent.
        stack_encrypt::Error::DescriptorTooLong { .. } => STATUS_ENCODING,
        _ => STATUS_INTERNAL,
    }
}

/// A dynamic-path error as a status code.
///
/// The split the library draws is the one the ABI needs: every variant but
/// `Cipher` and `Internal` is a statement about the caller's input, decided
/// before any key is minted or retrieved, so it is [`STATUS_ENCODING`].
/// `Cipher` defers to [`status_for_error`]; `Internal` is the library's own
/// invariant failing — a slot count that did not line up, a re-proof that
/// could not fail — and is [`STATUS_INTERNAL`], never a verdict on the
/// input. The catch-all is required (`Error` is `#[non_exhaustive]`) and
/// covers input variants only: a variant added tomorrow that is not about
/// the input must be classified here.
pub fn status_for_dynamic(error: &stack_encrypt::dynamic::Error) -> u32 {
    match error {
        stack_encrypt::dynamic::Error::Cipher(e) => status_for_error(e),
        stack_encrypt::dynamic::Error::Internal => STATUS_INTERNAL,
        _ => STATUS_ENCODING,
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

    #[test]
    fn dynamic_input_errors_are_encoding_and_a_library_bug_is_internal() {
        use stack_encrypt::dynamic::{Error, TermKind};
        for (label, err) in [
            ("a bad context", Error::Context),
            (
                "a bad term request",
                Error::Term {
                    kind: TermKind::Match,
                },
            ),
            ("a bad plan", Error::Plan),
            ("a bad source", Error::Source),
            ("a bad record", Error::Record),
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
