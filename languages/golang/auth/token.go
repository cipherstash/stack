package auth

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"time"

	"github.com/cipherstash/stack/languages/golang/internal/guest"
	"github.com/tetratelabs/wazero/api"
)

// Token is the stored access token, as auth.json holds it and
// [ProfileStore.Token] reads it through the Rust crate's own type. The
// refresh token is not in it: the guest handles refresh through a Strategy.
//
// fmt and slog print the access token as [redacted], under every verb. They
// print the other fields in full, because those help to debug a login.
// Read the AccessToken field to get the token itself.
//
// fmt calls no method on a value in an unexported struct field. A Token in
// an unexported field prints its access token in full. Keep a Token in an
// exported field of anything you print or log.
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

// redacted is what Token prints and logs in place of the access token.
const redacted = "[redacted]"

// String returns the token's fields, with [redacted] for the access token.
func (t Token) String() string {
	return fmt.Sprintf("auth.Token{AccessToken: %s, TokenType: %q, ExpiresAt: %s, Region: %q, ClientID: %q, DeviceInstanceID: %q}",
		redacted, t.TokenType, t.ExpiresAt.Format(time.RFC3339), t.Region, t.ClientID, t.DeviceInstanceID)
}

// GoString is what %#v prints: [Token.String].
func (t Token) GoString() string { return t.String() }

// Format prints [Token.String] for every verb fmt hands it.
func (t Token) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, t.String()) }

// LogValue is what slog records: the token's fields, with [redacted] for
// the access token.
func (t Token) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("access_token", redacted),
		slog.String("token_type", t.TokenType),
		slog.Time("expires_at", t.ExpiresAt),
		slog.String("region", t.Region),
		slog.String("client_id", t.ClientID),
		slog.String("device_instance_id", t.DeviceInstanceID),
	)
}

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
