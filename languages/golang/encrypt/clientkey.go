package encrypt

import (
	"errors"
	"strings"

	"github.com/cipherstash/stack/languages/golang/internal/guest"
)

// ClientKey is the ZeroKMS client key: long-lived key material that lives
// for the process. It is opaque — it prints a redaction under every verb
// and hands its bytes to no caller — and it is wiped once consumed.
//
// It is the one type both guest packages share: auth reads one out of
// the developer profile, and this package consumes it. The alias is what
// makes a key read there the type taken here without auth importing
// this package, so a binary that only wants the profile does not carry the
// crypto guest.
type ClientKey = guest.ClientKey

// NewClientKey wraps key material — the CS_CLIENT_KEY hex form, or the
// base64 of secretkey.json — as a ClientKey. It takes ownership of b: the
// caller must not keep or reuse the slice, which is wiped along with the
// key.
func NewClientKey(b []byte) *ClientKey { return guest.NewClientKey(b) }

// errKeyEncoding ends the message for a client key that is not hex or
// padded base64. It never includes the key.
const errKeyEncoding = "is not a client key: a client key is hex or padded base64"

// guestKeyRefusal is the start of the message the guest's config parser
// gives for a client key it cannot read (encrypt/guest/src/config.rs). It
// names the config key and never a value. NewClient looks for it to report
// the refusal as ErrConfig.
const guestKeyRefusal = "the config: client_key:"

// asClientKeyError reports err, from se_cipher_init, as a malformed client
// key when the guest refused the key. Any other error is returned as it is.
func asClientKeyError(err error) error {
	var d *Diagnostic
	if errors.Is(err, ErrEncoding) && errors.As(err, &d) && strings.Contains(d.Message, guestKeyRefusal) {
		return newClientKeyError("the client key does not decode to a valid keyset", err)
	}
	return err
}

// validKeyEncoding reports whether s has the form of an encoded client key:
// hex in either case, or standard base64 with its padding. These are the two
// forms the guest decodes. The check only looks at which characters appear
// and where. It decodes nothing, so it makes no copy of the key. A key that
// passes can still be refused by the guest. A key that fails can never
// decode, so NewClient refuses it before it does any other work.
func validKeyEncoding[T ~string | ~[]byte](s T) bool {
	return isHex(s) || isPaddedBase64(s)
}

func isHex[T ~string | ~[]byte](s T) bool {
	if len(s) == 0 || len(s)%2 != 0 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if ('0' > c || c > '9') && ('a' > c || c > 'f') && ('A' > c || c > 'F') {
			return false
		}
	}
	return true
}

func isPaddedBase64[T ~string | ~[]byte](s T) bool {
	if len(s) == 0 || len(s)%4 != 0 {
		return false
	}
	// At most two '=' characters, and only at the end.
	body := len(s)
	for body > 0 && s[body-1] == '=' && len(s)-body < 2 {
		body--
	}
	for i := range body {
		c := s[i]
		if ('A' > c || c > 'Z') && ('a' > c || c > 'z') && ('0' > c || c > '9') && c != '+' && c != '/' {
			return false
		}
	}
	return true
}
