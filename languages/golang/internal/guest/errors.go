package guest

import "errors"

// Failure kinds a guest surfaces across the boundary. A guest reports a
// status code and nothing else (see StatusError), so these are the whole
// vocabulary: they separate a tampered ciphertext from a bad token from a
// malformed input, and reveal nothing about plaintext or key material. The
// public packages expose them under their own names; the values are these.
var (
	// ErrAuthentication is an AEAD open failure: a tampered ciphertext, a
	// wrong element derivation, or a wrong AAD that reached the AEAD. Against
	// ZeroKMS a wrong AAD is usually refused earlier as ErrForbidden, because
	// every data key is bound to its context.
	ErrAuthentication = errors.New("cipherstash: authentication failed")
	// ErrEncoding is a malformed input: a value, ciphertext, plan, context,
	// selector, path or config the guest refused before doing anything with
	// it.
	ErrEncoding = errors.New("cipherstash: malformed input")
	// ErrState is a call on something that has been closed: a client, a
	// store, or an instance an interrupted call took down.
	ErrState = errors.New("cipherstash: closed")
	// ErrInternal is a guest panic or any other unexpected guest failure.
	ErrInternal = errors.New("cipherstash: internal guest failure")
	// ErrUnauthorized is ZeroKMS refusing the bearer token (HTTP 401): the
	// token is invalid, expired, or for another workspace.
	ErrUnauthorized = errors.New("cipherstash: ZeroKMS rejected the access token")
	// ErrForbidden is ZeroKMS refusing the request (HTTP 403): the token is
	// valid but not permitted, or a data key's bound context did not match
	// the one presented — the production form of a wrong-AAD open.
	ErrForbidden = errors.New("cipherstash: ZeroKMS refused the request")
	// ErrNotFound is ZeroKMS reporting a missing resource (HTTP 404): an
	// unknown keyset name or id, or a data key that does not exist.
	ErrNotFound = errors.New("cipherstash: ZeroKMS resource not found")
	// ErrConflict is ZeroKMS reporting a resource conflict (HTTP 409).
	ErrConflict = errors.New("cipherstash: ZeroKMS resource conflict")
	// ErrTransport is a failure to reach ZeroKMS or to read its response:
	// the transport returned an error, or the endpoint could not be resolved.
	ErrTransport = errors.New("cipherstash: ZeroKMS transport failed")
	// ErrKMS is any other ZeroKMS failure: an unparseable response, invalid
	// key material, or an unclassified server error.
	ErrKMS = errors.New("cipherstash: ZeroKMS request failed")
	// ErrTerm is a term derivation the scheme could not perform for the
	// given input, such as match text that yields no tokens.
	ErrTerm = errors.New("cipherstash: term derivation failed")
	// ErrForeignKeyset is a keyset-bound cipher refusing a ciphertext sealed
	// under another keyset, before any key is retrieved.
	ErrForeignKeyset = errors.New("cipherstash: ciphertext belongs to another keyset")
	// ErrProfileIO is a profile file that could not be read or written.
	ErrProfileIO = errors.New("cipherstash: profile file could not be read or written")
	// ErrProfileJSON is a profile file that is not the JSON its type expects.
	ErrProfileJSON = errors.New("cipherstash: profile file is not valid")
	// ErrProfileNotFound is a profile file that does not exist in the store
	// asked: no secretkey.json, auth.json or device.json there.
	ErrProfileNotFound = errors.New("cipherstash: profile file not found")
	// ErrInvalidFilename is a filename the store refuses: empty, absolute,
	// or naming a path.
	ErrInvalidFilename = errors.New("cipherstash: invalid profile filename")
	// ErrNoCurrentWorkspace is a workspace-scoped operation with no current
	// workspace set.
	ErrNoCurrentWorkspace = errors.New("cipherstash: no current workspace; run `stash auth login`")
	// ErrInvalidWorkspaceID is a workspace id that is not sixteen base32
	// characters.
	ErrInvalidWorkspaceID = errors.New("cipherstash: invalid workspace id")
	// ErrWorkspaceNotFound is a workspace with no local profile data: nothing
	// has logged in to it on this machine.
	ErrWorkspaceNotFound = errors.New("cipherstash: workspace has no local profile; log in to it first")
	// ErrAuthInvalidGrant is an OAuth refresh grant the auth server rejected.
	ErrAuthInvalidGrant = errors.New("cipherstash: auth server rejected the refresh grant")
	// ErrAuthInvalidClient is a client credential the auth server rejected.
	ErrAuthInvalidClient = errors.New("cipherstash: auth server rejected the client")
	// ErrAuthUsageLimit is an account blocked by its usage allowance.
	ErrAuthUsageLimit = errors.New("cipherstash: account usage limit exceeded")
	// ErrAuthNotAuthenticated means no usable auth credential is available.
	ErrAuthNotAuthenticated = errors.New("cipherstash: no usable authentication credential")
	// ErrAuthTransport is a failed auth HTTP exchange or response read.
	ErrAuthTransport = errors.New("cipherstash: auth transport failed")
	// ErrAuthConfig is invalid auth configuration or token data.
	ErrAuthConfig = errors.New("cipherstash: invalid auth configuration or token")
	// ErrAuthOther is an auth failure outside the actionable categories above.
	ErrAuthOther = errors.New("cipherstash: authentication failed")
	// ErrAuthRefreshRequired tells the Go credential host to take the
	// cross-process lock and call the device-session refresh export.
	ErrAuthRefreshRequired = errors.New("cipherstash: device session needs refresh")
	// ErrMemoryLock is guest memory that could not be locked in RAM (or,
	// on Linux, excluded from core dumps). A constructor returns it when
	// asked for locked memory and refused, and so does any later call under
	// that setting whose growth of the guest's memory could not be locked;
	// otherwise the instance reports it and works on with unlocked memory.
	// The wrapped error names the limit that refused the lock and the size
	// the guest holds: on Linux, RLIMIT_MEMLOCK (ulimit -l, a systemd
	// LimitMEMLOCK=, or a pod's securityContext).
	ErrMemoryLock = errors.New("cipherstash: guest memory is not locked")
)
