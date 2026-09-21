package stackencrypt

import (
	"errors"
	"fmt"
)

// Failure kinds surfaced across the boundary. The guest reports a status
// code and nothing else, so these are the whole vocabulary: they separate a
// tampered ciphertext from a bad token from a malformed input, and reveal
// nothing about plaintext or key material.
var (
	// ErrAuthentication is an AEAD open failure: a tampered ciphertext, a
	// wrong element derivation, or a wrong AAD that reached the AEAD. Against
	// ZeroKMS a wrong AAD is usually refused earlier as ErrForbidden, because
	// every data key is bound to its context.
	ErrAuthentication = errors.New("stackencrypt: authentication failed")
	// ErrEncoding is a malformed input: a value, ciphertext, plan, context,
	// selector or config the guest refused before any cryptography.
	ErrEncoding = errors.New("stackencrypt: malformed input")
	// ErrState is a call on a client that has been closed.
	ErrState = errors.New("stackencrypt: client is closed")
	// ErrInternal is a guest panic or any other unexpected guest failure.
	ErrInternal = errors.New("stackencrypt: internal guest failure")
	// ErrUnauthorized is ZeroKMS refusing the bearer token (HTTP 401): the
	// token is invalid, expired, or for another workspace.
	ErrUnauthorized = errors.New("stackencrypt: ZeroKMS rejected the access token")
	// ErrForbidden is ZeroKMS refusing the request (HTTP 403): the token is
	// valid but not permitted, or a data key's bound context did not match
	// the one presented — the production form of a wrong-AAD open.
	ErrForbidden = errors.New("stackencrypt: ZeroKMS refused the request")
	// ErrNotFound is ZeroKMS reporting a missing resource (HTTP 404): an
	// unknown keyset name or id, or a data key that does not exist.
	ErrNotFound = errors.New("stackencrypt: ZeroKMS resource not found")
	// ErrConflict is ZeroKMS reporting a resource conflict (HTTP 409).
	ErrConflict = errors.New("stackencrypt: ZeroKMS resource conflict")
	// ErrTransport is a failure to reach ZeroKMS or to read its response:
	// the transport returned an error, or the endpoint could not be resolved.
	ErrTransport = errors.New("stackencrypt: ZeroKMS transport failed")
	// ErrKMS is any other ZeroKMS failure: an unparseable response, invalid
	// key material, or an unclassified server error.
	ErrKMS = errors.New("stackencrypt: ZeroKMS request failed")
	// ErrTerm is a term derivation the scheme could not perform for the
	// given input, such as match text that yields no tokens.
	ErrTerm = errors.New("stackencrypt: term derivation failed")
	// ErrForeignKeyset is a keyset-bound Cipher refusing a ciphertext sealed
	// under another keyset, before any key is retrieved. Open it through the
	// Client, which is not bound to one keyset.
	ErrForeignKeyset = errors.New("stackencrypt: ciphertext belongs to another keyset")
	// ErrMemoryLock is guest memory that could not be locked in RAM (or,
	// on Linux, excluded from core dumps). NewClient returns it when
	// Config.RequireLockedMemory is set, and so does any later call under
	// that setting whose growth of the guest's memory could not be locked;
	// otherwise Client.MemoryLockError reports it and the client works on
	// with unlocked memory. The wrapped error names the limit that refused
	// the lock and the size the guest holds: on Linux, RLIMIT_MEMLOCK
	// (ulimit -l, a systemd LimitMEMLOCK=, or a pod's securityContext).
	ErrMemoryLock = errors.New("stackencrypt: guest memory is not locked")
)

// Guest status codes (guest/src/status.rs). Part of the guest/host
// contract; never renumbered.
const (
	statusAuth            = 1
	statusEncoding        = 2
	statusState           = 3
	statusInternal        = 4
	statusKMSUnauthorized = 5
	statusKMSForbidden    = 6
	statusKMSNotFound     = 7
	statusKMSConflict     = 8
	statusKMSTransport    = 9
	statusKMSOther        = 10
	statusTerm            = 11
	statusForeignKeyset   = 12
)

func statusError(status uint32) error {
	switch status {
	case statusAuth:
		return ErrAuthentication
	case statusEncoding:
		return ErrEncoding
	case statusState:
		return ErrState
	case statusInternal:
		return ErrInternal
	case statusKMSUnauthorized:
		return ErrUnauthorized
	case statusKMSForbidden:
		return ErrForbidden
	case statusKMSNotFound:
		return ErrNotFound
	case statusKMSConflict:
		return ErrConflict
	case statusKMSTransport:
		return ErrTransport
	case statusKMSOther:
		return ErrKMS
	case statusTerm:
		return ErrTerm
	case statusForeignKeyset:
		return ErrForeignKeyset
	default:
		// A status this host does not know is still an internal failure;
		// the code is kept so a guest/host version skew is diagnosable.
		return fmt.Errorf("%w (unrecognized guest status %d)", ErrInternal, status)
	}
}
