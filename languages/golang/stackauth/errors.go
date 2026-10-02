package stackauth

import (
	"errors"

	"github.com/cipherstash/stack/languages/golang/internal/guest"
)

// Failure kinds the profile reports. The guest reports a status code from
// the one table every guest shares, so these are the sentinels of the
// shared decoder exposed under this package's names; an error from
// stackencrypt of the same kind is the same value.
var (
	// ErrNotFound is a profile file that does not exist in the store asked:
	// no secretkey.json, auth.json or device.json there. For the workspace's
	// files that means nothing has logged in to it on this machine.
	ErrNotFound = guest.ErrProfileNotFound
	// ErrInvalid is a profile file that is not the JSON its type expects.
	ErrInvalid = guest.ErrProfileJSON
	// ErrIO is a profile file that could not be read or written.
	ErrIO = guest.ErrProfileIO
	// ErrInvalidFilename is a filename the store refuses: empty, absolute,
	// or naming a path.
	ErrInvalidFilename = guest.ErrInvalidFilename
	// ErrNoCurrentWorkspace is a workspace-scoped operation with no current
	// workspace set: run `stash auth login`.
	ErrNoCurrentWorkspace = guest.ErrNoCurrentWorkspace
	// ErrInvalidWorkspaceID is a workspace id that is not sixteen base32
	// characters. Refused before any path is built from it.
	ErrInvalidWorkspaceID = guest.ErrInvalidWorkspaceID
	// ErrWorkspaceNotFound is a workspace with no directory under
	// workspaces/: nothing has logged in to it on this machine.
	ErrWorkspaceNotFound = guest.ErrWorkspaceNotFound
	// ErrEncoding is an input the guest refused: a directory, id or filename
	// that is not UTF-8.
	ErrEncoding = guest.ErrEncoding
	// ErrState is a call on a store that has been closed.
	ErrState = guest.ErrState
	// ErrInternal is a guest panic or any other unexpected guest failure.
	ErrInternal = guest.ErrInternal
	// ErrInvalidGrant is an OAuth refresh grant the auth server rejected.
	ErrInvalidGrant = guest.ErrAuthInvalidGrant
	// ErrInvalidClient is a client credential the auth server rejected.
	ErrInvalidClient = guest.ErrAuthInvalidClient
	// ErrUsageLimit is an account blocked by its usage allowance.
	ErrUsageLimit = guest.ErrAuthUsageLimit
	// ErrNotAuthenticated means no usable auth credential is available.
	ErrNotAuthenticated = guest.ErrAuthNotAuthenticated
	// ErrAuthTransport is a failed auth HTTP exchange or response read.
	ErrAuthTransport = guest.ErrAuthTransport
	// ErrAuthConfig is invalid auth configuration or token data.
	ErrAuthConfig = guest.ErrAuthConfig
	// ErrAuthOther is an auth failure outside the actionable categories above.
	ErrAuthOther = guest.ErrAuthOther
	// ErrMemoryLock is guest memory that could not be locked in RAM (or, on
	// Linux, excluded from core dumps). Open returns it under
	// [RequireLockedMemory]; otherwise [ProfileStore.MemoryLockError]
	// reports it and the store works on with unlocked memory.
	ErrMemoryLock = guest.ErrMemoryLock

	// ErrNoProfile is a profile directory that does not exist: nothing has
	// logged in on this machine, or CS_CONFIG_PATH names the wrong place.
	ErrNoProfile = errors.New("stackauth: no profile directory; run `stash auth login`")
)
