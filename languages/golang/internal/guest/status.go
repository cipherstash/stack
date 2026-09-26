package guest

import "fmt"

// Guest status codes: the low half of a packed error result, from the one
// table every guest reports through (packages/stack-guest-abi, status.rs).
// One numbering for both guests, never renumbered; a guest that needs a
// code of its own appends after the last one there, and here.
const (
	StatusAuth            = 1
	StatusEncoding        = 2
	StatusState           = 3
	StatusInternal        = 4
	StatusKMSUnauthorized = 5
	StatusKMSForbidden    = 6
	StatusKMSNotFound     = 7
	StatusKMSConflict     = 8
	StatusKMSTransport    = 9
	StatusKMSOther        = 10
	StatusTerm            = 11
	StatusForeignKeyset   = 12
	// The credential guest's profile conditions.
	StatusProfileIO                 = 13
	StatusProfileJSON               = 14
	StatusProfileNotFound           = 15
	StatusProfileInvalidFilename    = 16
	StatusProfileNoCurrentWorkspace = 17
	StatusProfileInvalidWorkspaceID = 18
	StatusProfileWorkspaceNotFound  = 19
	StatusAuthInvalidGrant          = 20
	StatusAuthInvalidClient         = 21
	StatusAuthUsageLimit            = 22
	StatusAuthNotAuthenticated      = 23
	StatusAuthTransport             = 24
	StatusAuthConfig                = 25
	StatusAuthOther                 = 26
	StatusAuthRefreshRequired       = 27
)

// StatusError is the sentinel a guest status decodes to. A status this host
// does not know is still an internal failure; the code is kept so a
// guest/host version skew is diagnosable.
func StatusError(status uint32) error {
	switch status {
	case StatusAuth:
		return ErrAuthentication
	case StatusEncoding:
		return ErrEncoding
	case StatusState:
		return ErrState
	case StatusInternal:
		return ErrInternal
	case StatusKMSUnauthorized:
		return ErrUnauthorized
	case StatusKMSForbidden:
		return ErrForbidden
	case StatusKMSNotFound:
		return ErrNotFound
	case StatusKMSConflict:
		return ErrConflict
	case StatusKMSTransport:
		return ErrTransport
	case StatusKMSOther:
		return ErrKMS
	case StatusTerm:
		return ErrTerm
	case StatusForeignKeyset:
		return ErrForeignKeyset
	case StatusProfileIO:
		return ErrProfileIO
	case StatusProfileJSON:
		return ErrProfileJSON
	case StatusProfileNotFound:
		return ErrProfileNotFound
	case StatusProfileInvalidFilename:
		return ErrInvalidFilename
	case StatusProfileNoCurrentWorkspace:
		return ErrNoCurrentWorkspace
	case StatusProfileInvalidWorkspaceID:
		return ErrInvalidWorkspaceID
	case StatusProfileWorkspaceNotFound:
		return ErrWorkspaceNotFound
	case StatusAuthInvalidGrant:
		return ErrAuthInvalidGrant
	case StatusAuthInvalidClient:
		return ErrAuthInvalidClient
	case StatusAuthUsageLimit:
		return ErrAuthUsageLimit
	case StatusAuthNotAuthenticated:
		return ErrAuthNotAuthenticated
	case StatusAuthTransport:
		return ErrAuthTransport
	case StatusAuthConfig:
		return ErrAuthConfig
	case StatusAuthOther:
		return ErrAuthOther
	case StatusAuthRefreshRequired:
		return ErrAuthRefreshRequired
	default:
		return fmt.Errorf("%w (unrecognized guest status %d)", ErrInternal, status)
	}
}

// PackedResult decodes a guest export's packed u64: a non-zero high half is
// an output pointer with the length in the low half; a zero high half
// carries a status code in the low half, returned as its sentinel.
func PackedResult(packed uint64) (ptr, length uint32, err error) {
	if packed>>32 == 0 {
		return 0, 0, StatusError(uint32(packed))
	}
	return uint32(packed >> 32), uint32(packed), nil
}
