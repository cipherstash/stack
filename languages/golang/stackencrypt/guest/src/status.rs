//! Status codes for the ABI's packed result encoding (see [`crate::abi`]),
//! and the mapping from [`stack_encrypt::Error`] onto them.
//!
//! Defined outside the wasm32-gated ABI module so native builds — the ops
//! unit tests — can reference them too. The Go host mirrors these values;
//! they are part of the guest/host contract and must not be renumbered.
//!
//! Codes 1–4 are byte-for-byte the vitaminc guest's codes (`vcencrypt`'s
//! `status.rs`), so the two guests read identically from the host side.
//! Codes 5–10 map the ZeroKMS request outcomes
//! ([`ViturRequestErrorKind`]-shaped) so a Go caller can distinguish a bad
//! token from a tampered ciphertext without parsing strings. Code 11 is a
//! term-derivation failure (a caller-input condition, e.g. match text that
//! yields no tokens).

use stack_kms::{GenerateKeyError, LoadKeysetError, RetrieveKeyError};
use zerokms_protocol::ViturRequestErrorKind;

/// AEAD open failure: wrong key, wrong AAD, or tampered ciphertext.
pub const STATUS_AUTH: u32 = 1;
/// Invalid input at the boundary: malformed transport bytes, a malformed
/// cipher config, an empty encryption context, or a pointer/length pair that
/// fails validation against linear memory.
pub const STATUS_ENCODING: u32 = 2;
/// The cipher handle is unknown (never issued, or already freed).
pub const STATUS_BAD_HANDLE: u32 = 3;
/// A caught panic, handle-id exhaustion, a response that did not match its
/// requests, or any other unexpected internal failure.
pub const STATUS_INTERNAL: u32 = 4;
/// ZeroKMS (or the auth strategy) rejected the request as unauthenticated:
/// a missing, expired, or invalid access token.
pub const STATUS_KMS_UNAUTHORIZED: u32 = 5;
/// ZeroKMS rejected the request as forbidden: the token is valid but lacks
/// permission (or the keyset is disabled).
pub const STATUS_KMS_FORBIDDEN: u32 = 6;
/// ZeroKMS could not find the resource: an unknown keyset (or client), or a
/// data key that does not exist for the presented `iv`/`tag`.
pub const STATUS_KMS_NOT_FOUND: u32 = 7;
/// ZeroKMS reported a resource conflict.
pub const STATUS_KMS_CONFLICT: u32 = 8;
/// The transport failed before a ZeroKMS verdict: the host's HTTP call
/// errored, the endpoint is unknown or invalid, or the request could not be
/// prepared.
pub const STATUS_KMS_TRANSPORT: u32 = 9;
/// ZeroKMS failed in a way none of the codes above capture: a malformed
/// response, invalid key material, or an unclassified server error.
pub const STATUS_KMS_OTHER: u32 = 10;
/// An index term failed to derive: e.g. match text that yields no tokens, or
/// a value/scheme combination the term does not support.
pub const STATUS_TERM: u32 = 11;

/// Map a sealing/opening error onto the ABI status word.
///
/// Total over [`stack_encrypt::Error`]: composition-bug variants
/// (`ResponseShape`, `CipherMismatch`, `KeyCountMismatch`) and everything
/// else unexpected collapse into [`STATUS_INTERNAL`] — statuses distinguish
/// what a host can act on, not what it can only log.
pub fn status_for_error(error: &stack_encrypt::Error) -> u32 {
    match error {
        stack_encrypt::Error::Aead => STATUS_AUTH,
        stack_encrypt::Error::EmptyContext => STATUS_ENCODING,
        stack_encrypt::Error::Term(_) => STATUS_TERM,
        stack_encrypt::Error::Kms(kms) => status_for_kms(kms),
        _ => STATUS_INTERNAL,
    }
}

/// Map a term-derivation error directly (the term entry points return
/// [`stack_encrypt::sem::TermError`], not the sealing error).
pub fn status_for_term_error(error: &stack_encrypt::sem::TermError) -> u32 {
    match error {
        stack_encrypt::sem::TermError::EmptyContext => STATUS_ENCODING,
        _ => STATUS_TERM,
    }
}

fn status_for_kms(error: &stack_kms::Error) -> u32 {
    match error {
        stack_kms::Error::GenerateKey(e) => match e {
            GenerateKeyError::Unauthorized => STATUS_KMS_UNAUTHORIZED,
            GenerateKeyError::Forbidden => STATUS_KMS_FORBIDDEN,
            GenerateKeyError::RequestFailed(e) => status_for_kind(&e.kind),
            GenerateKeyError::GenerateIv(_) => STATUS_INTERNAL,
            _ => STATUS_KMS_OTHER,
        },
        stack_kms::Error::RetrieveKey(e) => match e {
            RetrieveKeyError::RequestFailed(e) => status_for_kind(&e.kind),
            // A per-key server-side "no key for this iv/tag".
            RetrieveKeyError::FailedRetrieval(_) => STATUS_KMS_NOT_FOUND,
            _ => STATUS_KMS_OTHER,
        },
        stack_kms::Error::LoadKeyset(e) => match e {
            LoadKeysetError::Unauthorized(_) => STATUS_KMS_UNAUTHORIZED,
            LoadKeysetError::Forbidden(_) => STATUS_KMS_FORBIDDEN,
            LoadKeysetError::KeysetNotFound(_) => STATUS_KMS_NOT_FOUND,
            LoadKeysetError::RequestFailed(e) => status_for_kind(&e.kind),
            _ => STATUS_KMS_OTHER,
        },
        // No token means no authenticated request could even be attempted.
        stack_kms::Error::Auth(_) => STATUS_KMS_UNAUTHORIZED,
        stack_kms::Error::ConnectionInit(_) | stack_kms::Error::InvalidEndpoint(_) => {
            STATUS_KMS_TRANSPORT
        }
        _ => STATUS_KMS_OTHER,
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
    fn aead_and_context_errors_map_to_the_vitaminc_codes() {
        assert_eq!(status_for_error(&stack_encrypt::Error::Aead), STATUS_AUTH);
        assert_eq!(
            status_for_error(&stack_encrypt::Error::EmptyContext),
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

    #[test]
    fn term_errors_split_empty_context_from_derivation() {
        assert_eq!(
            status_for_term_error(&stack_encrypt::sem::TermError::EmptyContext),
            STATUS_ENCODING
        );
        assert_eq!(
            status_for_term_error(&stack_encrypt::sem::TermError::EmptyTermText),
            STATUS_TERM
        );
    }
}
