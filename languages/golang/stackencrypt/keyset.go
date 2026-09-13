package stackencrypt

import (
	"encoding/hex"
	"errors"
	"fmt"
)

// KeysetSelector names the keyset a call binds to. The three selectors are
// [KeysetName], [KeysetID] and [DefaultKeyset]; every variant is spelled,
// there is no empty-string or nil sentinel. Names follow ZeroKMS's rules
// (non-empty, at most 64 bytes, of A-Z a-z 0-9 _ - /), checked by the
// guest before any request is made; ZeroKMS itself never issues a
// UUID-shaped name, so a name and an id cannot be confused.
type KeysetSelector interface {
	// selector renders the tagged object the guest parses.
	selector() map[string]any
}

// KeysetName selects a keyset by name. Its first use on a client is one
// ZeroKMS round trip; the binding is cached by the guest for a bounded
// window, after which the name is resolved again.
type KeysetName string

func (n KeysetName) selector() map[string]any { return map[string]any{"name": string(n)} }

// KeysetID is a keyset's UUID, the identity a sealed leaf carries. It
// selects a keyset by id; ids are never re-resolved.
type KeysetID [16]byte

func (id KeysetID) selector() map[string]any { return map[string]any{"id": id[:]} }

// String renders the id in canonical hyphenated form.
func (id KeysetID) String() string {
	var b [36]byte
	hex.Encode(b[:8], id[:4])
	b[8] = '-'
	hex.Encode(b[9:13], id[4:6])
	b[13] = '-'
	hex.Encode(b[14:18], id[6:8])
	b[18] = '-'
	hex.Encode(b[19:23], id[8:10])
	b[23] = '-'
	hex.Encode(b[24:], id[10:])
	return string(b[:])
}

// ParseKeysetID parses a canonical hyphenated UUID.
func ParseKeysetID(s string) (KeysetID, error) {
	var id KeysetID
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return id, fmt.Errorf("stackencrypt: %q is not a UUID", s)
	}
	hexed := s[:8] + s[9:13] + s[14:18] + s[19:23] + s[24:]
	if _, err := hex.Decode(id[:], []byte(hexed)); err != nil {
		return id, fmt.Errorf("stackencrypt: %q is not a UUID", s)
	}
	return id, nil
}

type defaultKeyset struct{}

func (defaultKeyset) selector() map[string]any { return map[string]any{"default": map[string]any{}} }

// DefaultKeyset selects the client's default keyset: the one named in
// [Config.Keyset], else the ZeroKMS client's own default. Selecting it is
// never a round trip.
//
// Its type is the unexported concrete one rather than [KeysetSelector] on
// purpose. A package-level var of interface type is writable by every
// importer, so one package could point this at a named keyset — or nil —
// and silently redirect [Client.DefaultCipher] and every nil selector for
// the whole process, racily. As a concrete zero-size struct it still
// passes anywhere a KeysetSelector is wanted, and the only value it can be
// reassigned is the one it already holds.
var DefaultKeyset = defaultKeyset{}

// anyKeyset is the opening-only selector: open every leaf under whichever
// keyset it was sealed with. Not exported — the Client's own decrypt
// methods are its spelling.
type anyKeyset struct{}

func (anyKeyset) selector() map[string]any { return map[string]any{"any": map[string]any{}} }

// options renders the per-call options object the guest parses.
func options(sel KeysetSelector) map[string]any {
	return map[string]any{"keyset": sel.selector()}
}

var errNilSelector = errors.New("stackencrypt: keyset selector is nil")
