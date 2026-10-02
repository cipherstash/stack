package stackencrypt

import "github.com/cipherstash/stack/languages/golang/internal/guest"

// ClientKey is the ZeroKMS client key: long-lived key material that lives
// for the process. It is opaque — it prints a redaction under every verb
// and hands its bytes to no caller — and it is wiped once consumed.
//
// It is the one type both guest packages share: stackauth reads one out of
// the developer profile, and this package consumes it. The alias is what
// makes a key read there the type taken here without stackauth importing
// this package, so a binary that only wants the profile does not carry the
// crypto guest.
type ClientKey = guest.ClientKey

// NewClientKey wraps key material — the CS_CLIENT_KEY hex form, or the
// base64 of secretkey.json — as a ClientKey. It takes ownership of b: the
// caller must not keep or reuse the slice, which is wiped along with the
// key.
func NewClientKey(b []byte) *ClientKey { return guest.NewClientKey(b) }
