package encrypt

import "github.com/cipherstash/stack/languages/golang/internal/guest"

// Failure kinds surfaced across the boundary: the guest reports a status
// code, and these are what the codes decode to. They separate a tampered
// ciphertext from a bad token from a malformed input, and reveal nothing
// about plaintext or key material. Check one with errors.Is; the detail
// behind it is a [Diagnostic].
//
// They are the sentinels every guest package shares (one status table for
// every guest, decoded once), exposed here under this package's names: an
// error from auth is the same value, so errors.Is holds across the
// two.
var (
	// ErrAuthentication is an AEAD open failure: a tampered ciphertext, a
	// wrong element derivation, or a wrong AAD that reached the AEAD. Against
	// ZeroKMS a wrong AAD is usually refused earlier as ErrForbidden, because
	// every data key is bound to its context.
	ErrAuthentication = guest.ErrAuthentication
	// ErrEncoding is a malformed input: a value, ciphertext, plan, context,
	// selector or config the guest refused before any cryptography.
	ErrEncoding = guest.ErrEncoding
	// ErrState is a call on a client that has been closed.
	ErrState = guest.ErrState
	// ErrInternal is a guest panic or any other unexpected guest failure.
	ErrInternal = guest.ErrInternal
	// ErrUnauthorized is ZeroKMS refusing the bearer token (HTTP 401): the
	// token is invalid, expired, or for another workspace.
	ErrUnauthorized = guest.ErrUnauthorized
	// ErrForbidden is ZeroKMS refusing the request (HTTP 403): the token is
	// valid but not permitted, or a data key's bound context did not match
	// the one presented — the production form of a wrong-AAD open.
	ErrForbidden = guest.ErrForbidden
	// ErrNotFound is ZeroKMS reporting a missing resource (HTTP 404): an
	// unknown keyset name or id, or a data key that does not exist.
	ErrNotFound = guest.ErrNotFound
	// ErrConflict is ZeroKMS reporting a resource conflict (HTTP 409).
	ErrConflict = guest.ErrConflict
	// ErrTransport is a failure to reach ZeroKMS or to read its response:
	// the transport returned an error, or the endpoint could not be resolved.
	ErrTransport = guest.ErrTransport
	// ErrKMS is any other ZeroKMS failure: an unparseable response, invalid
	// key material, or an unclassified server error.
	ErrKMS = guest.ErrKMS
	// ErrTerm is a term derivation the scheme could not perform for the
	// given input, such as match text that yields no tokens.
	ErrTerm = guest.ErrTerm
	// ErrForeignKeyset is a keyset-bound Cipher refusing a ciphertext sealed
	// under another keyset, before any key is retrieved. Open it through the
	// Client, which is not bound to one keyset.
	ErrForeignKeyset = guest.ErrForeignKeyset
	// ErrContextMismatch is a row whose context field, stored in the clear
	// beside its sealed fields, is not the context named with
	// [Cipher.Context]. Refused before any key is retrieved; a row stored
	// under another tenant is a mismatch, never a decrypted value.
	ErrContextMismatch = guest.ErrContextMismatch
	// ErrMemoryLock is guest memory that could not be locked in RAM (or,
	// on Linux, excluded from core dumps). NewClient returns it when
	// WithRequireLockedMemory is given, and so does any later call under
	// that setting whose growth of the guest's memory could not be locked;
	// otherwise Client.MemoryLockError reports it and the client works on
	// with unlocked memory. The wrapped error names the limit that refused
	// the lock and the size the guest holds: on Linux, RLIMIT_MEMLOCK
	// (ulimit -l, a systemd LimitMEMLOCK=, or a pod's securityContext).
	ErrMemoryLock = guest.ErrMemoryLock
)

// Diagnostic is the full error behind a failure the guest reports, beside
// the kind: every such failure is a *Diagnostic wrapping one of the
// sentinels above, so errors.Is matches the kind and errors.As reads the
// rest:
//
//	var d *encrypt.Diagnostic
//	if errors.As(err, &d) {
//		log.Printf("%s: %s (%s)", d.Code, d.Message, d.Help)
//	}
//
// Its fields are Code ("stack_encrypt::foreign_keyset",
// "stack_kms::keyset_not_found", ...; stable), Message (what Error
// returns), Help, URL, Severity, Fields (the structured fields, by name)
// and Causes (the errors behind it, outermost first). Accessors read the
// fields a caller branches on: ExpectedKeyset and FoundKeyset on an
// [ErrForeignKeyset] (each a [KeysetID]'s bytes), and Field and Reason on a
// refused plan, record or value.
//
// What one may carry is fixed: keyset ids and names, field names, counts,
// index kinds, ZeroKMS request kinds and HTTP statuses. Never plaintext,
// key material, tokens, ciphertext or term bytes, or the values of an
// encryption context.
//
// Errors the client raises itself carry none: a closed client ([ErrState]),
// a guest that did not return, [ErrMemoryLock], and an argument refused
// before it reached the guest. A guest built before the detail existed
// returns the bare sentinel too.
//
// It is the same type as auth.Diagnostic, by identity.
type Diagnostic = guest.Diagnostic

// Cause is one error in a [Diagnostic]'s cause chain: a Code and a Message.
// A cause from a library outside the stack crates has no Code, and its
// Message is a description the guest vouches for, never that library's own
// text.
type Cause = guest.Cause
