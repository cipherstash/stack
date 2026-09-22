//! The status table: the low 32 bits of a packed error result (see
//! [`crate::abi`]).
//!
//! **One numbering for every guest.** The Go host decodes these values once,
//! in the internal package both public packages share, so a number means the
//! same thing whichever guest reported it. The codes here are part of the
//! guest/host contract and are never renumbered or reused; a guest that needs
//! a status of its own appends after the last one, in this file, so the
//! table stays one table.
//!
//! Codes 1–4 are byte-for-byte the vitaminc guest's codes (`vcencrypt`'s
//! `status.rs`), so every guest reads identically from the host side; code 3
//! there is "unknown handle", and here — where there is no handle — it is
//! the call-order violation that means the same thing to a host: nothing to
//! run this call against. Codes 5–10 are the ZeroKMS request outcomes, so a
//! host can distinguish a bad token from a tampered ciphertext without
//! parsing strings; 11 and 12 are the crypto guest's term and keyset-scope
//! conditions. The mapping from a library's error type onto these numbers
//! is each guest's own (`status_for_error` and friends in the crypto guest):
//! this module names the numbers, not the libraries.

/// AEAD open failure: a tampered ciphertext, a wrong element derivation, or
/// a wrong AAD that reached the AEAD. Against ZeroKMS a wrong AAD does not
/// get that far — every data key is bound to its context's descriptor, so
/// the retrieve is refused first, as [`STATUS_KMS_FORBIDDEN`]. Only a key
/// source that ignores descriptors (the native tests' fake) reports a wrong
/// AAD here.
pub const STATUS_AUTH: u32 = 1;
/// Invalid input at the boundary: malformed transport bytes, a malformed
/// config, an empty encryption context, or a pointer/length pair that fails
/// validation against linear memory.
pub const STATUS_ENCODING: u32 = 2;
/// The call is out of order: an operation before the guest's init export, or
/// after its shutdown, or init twice. A host fixes its call sequence;
/// nothing here is a guest bug. (The vitaminc guest's code 3 is "unknown
/// handle", the same condition under a handle scheme.)
pub const STATUS_STATE: u32 = 3;
/// A caught panic, a response that did not match its requests, or any other
/// unexpected internal failure.
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

/// The last code in the table. A guest appending a code of its own starts
/// at `LAST_STATUS + 1` and moves this constant with it, so two guests can
/// never claim one number.
pub const LAST_STATUS: u32 = STATUS_FOREIGN_KEYSET;

#[cfg(test)]
mod tests {
    use super::*;

    /// The table is dense from 1 and every code is distinct; a renumbering
    /// or a gap would break the Go decoder's contract silently.
    #[test]
    fn the_table_is_dense_and_distinct() {
        let codes = [
            STATUS_AUTH,
            STATUS_ENCODING,
            STATUS_STATE,
            STATUS_INTERNAL,
            STATUS_KMS_UNAUTHORIZED,
            STATUS_KMS_FORBIDDEN,
            STATUS_KMS_NOT_FOUND,
            STATUS_KMS_CONFLICT,
            STATUS_KMS_TRANSPORT,
            STATUS_KMS_OTHER,
            STATUS_TERM,
            STATUS_FOREIGN_KEYSET,
        ];
        for (i, code) in codes.iter().enumerate() {
            assert_eq!(*code, i as u32 + 1, "code {i} is out of sequence");
        }
        assert_eq!(LAST_STATUS, codes[codes.len() - 1]);
        // Zero is never a status: it is the high half of a *successful*
        // packed result, and a status of zero would be unrepresentable.
        assert!(codes.iter().all(|c| *c != 0));
    }
}
