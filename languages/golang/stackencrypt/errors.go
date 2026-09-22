package stackencrypt

import "github.com/cipherstash/cipherstash-suite/bindings/go/internal/guest"

// Failure kinds surfaced across the boundary. The guest reports a status
// code and nothing else, so these are the whole vocabulary: they separate a
// tampered ciphertext from a bad token from a malformed input, and reveal
// nothing about plaintext or key material.
//
// They are the sentinels every guest package shares (one status table for
// every guest, decoded once), exposed here under this package's names: an
// error from stackauth is the same value, so errors.Is holds across the
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
	// ErrMemoryLock is guest memory that could not be locked in RAM (or,
	// on Linux, excluded from core dumps). NewClient returns it when
	// Config.RequireLockedMemory is set, and so does any later call under
	// that setting whose growth of the guest's memory could not be locked;
	// otherwise Client.MemoryLockError reports it and the client works on
	// with unlocked memory. The wrapped error names the limit that refused
	// the lock and the size the guest holds: on Linux, RLIMIT_MEMLOCK
	// (ulimit -l, a systemd LimitMEMLOCK=, or a pod's securityContext).
	ErrMemoryLock = guest.ErrMemoryLock
)
