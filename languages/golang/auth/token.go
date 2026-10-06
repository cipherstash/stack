package auth

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/cipherstash/stack/languages/golang/internal/guest"
	"github.com/tetratelabs/wazero/api"
)

// Token is the stored access token, as auth.json holds it and
// [ProfileStore.Token] reads it through the Rust crate's own type. The
// refresh token is not in it: the guest handles refresh through a Strategy.
type Token struct {
	// AccessToken is the bearer credential.
	AccessToken string
	// TokenType is the token's type, "Bearer".
	TokenType string
	// ExpiresAt is when the token stops being usable, from the stored
	// epoch timestamp.
	ExpiresAt time.Time
	// Region is the region the token was issued for, if stored.
	Region string
	// ClientID is the ZeroKMS client id the login provisioned, if stored.
	ClientID string
	// DeviceInstanceID is the identity of the device that logged in, if
	// stored.
	DeviceInstanceID string
}

// Usable reports whether the token is still usable at now: before its real
// expiry. The Rust crate's is_usable, not its is_expired, which subtracts a
// refresh-ahead margin that belongs to refreshing.
func (t Token) Usable(now time.Time) bool { return now.Before(t.ExpiresAt) }

// Token reads auth.json in this store (a workspace store; the root holds
// none). The transport copy of the token is wiped once it is read out.
func (s *ProfileStore) Token(ctx context.Context) (Token, error) {
	out, err := s.call(ctx, func(i *instance) api.Function { return i.token })
	if err != nil {
		return Token{}, err
	}
	defer guest.Wipe(out)
	fields, err := object(out)
	if err != nil {
		return Token{}, err
	}
	var t Token
	if t.AccessToken, err = fields.text("access_token"); err != nil {
		return Token{}, err
	}
	if t.TokenType, err = fields.text("token_type"); err != nil {
		return Token{}, err
	}
	expiresAt, err := fields.uint64Field("expires_at")
	if err != nil {
		return Token{}, err
	}
	if expiresAt > math.MaxInt64 {
		return Token{}, fmt.Errorf("%w: expires_at %d is out of range", ErrInternal, expiresAt)
	}
	t.ExpiresAt = time.Unix(int64(expiresAt), 0)
	if t.Region, err = fields.optionalText("region"); err != nil {
		return Token{}, err
	}
	if t.ClientID, err = fields.optionalText("client_id"); err != nil {
		return Token{}, err
	}
	if t.DeviceInstanceID, err = fields.optionalText("device_instance_id"); err != nil {
		return Token{}, err
	}
	return t, nil
}
