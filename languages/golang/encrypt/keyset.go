package encrypt

import (
	"encoding/hex"
	"fmt"

	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
)

// KeysetSelector names the keyset a call binds to, as Rust's IdentifiedBy
// does: [KeysetName] or [KeysetID]. Every variant is spelled, there is no
// empty-string or nil sentinel; the default keyset is not a selector but
// [Client.DefaultKeyset], exactly as it is a method and not an IdentifiedBy
// variant in Rust. Names follow ZeroKMS's rules
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
		return id, fmt.Errorf("encrypt: %q is not a UUID", s)
	}
	hexed := s[:8] + s[9:13] + s[14:18] + s[19:23] + s[24:]
	if _, err := hex.Decode(id[:], []byte(hexed)); err != nil {
		return id, fmt.Errorf("encrypt: %q is not a UUID", s)
	}
	return id, nil
}

// defaultKeyset is the guest's spelling of the client's default keyset —
// the one a ZeroKMS administrator set for this client. Selecting it is
// never a round trip. Not exported: the default is [Client.DefaultKeyset],
// a method, so there is no value an importer could reassign or pass by
// mistake, and no config key that appeared to override what is the
// server's to say.
type defaultKeyset struct{}

func (defaultKeyset) selector() map[string]any { return map[string]any{"default": map[string]any{}} }

// anyKeyset is the opening-only selector: open every leaf under whichever
// keyset it was sealed with. Not exported — the Client's own decrypt
// methods are its spelling.
type anyKeyset struct{}

func (anyKeyset) selector() map[string]any { return map[string]any{"any": map[string]any{}} }

// callOptions is what one guest call takes beside its inputs: the options
// object the guest parses. Every call that touches a keyset sends one.
type callOptions struct {
	// keyset is the keyset the call binds to.
	keyset KeysetSelector
	// context is the context the guest checks each record's context field
	// against, on an open; "" names none.
	context string
	// audit is the audit metadata the guest sends with the call's data-key
	// requests; nil sends none. The guest refuses it on a call that derives
	// a term, so those calls leave it nil: see [Cipher.termCall].
	audit auditFacts
}

// wire renders the options object as the guest reads it. A key with nothing
// to say is left out.
func (o callOptions) wire() map[string]any {
	opts := map[string]any{"keyset": o.keyset.selector()}
	if o.context != "" {
		opts["context"] = o.context
	}
	if o.audit != nil {
		opts["audit"] = o.audit()
	}
	return opts
}

// marshal is the options object in the transport codec.
func (o callOptions) marshal() ([]byte, error) {
	return vcffi.Marshal(o.wire())
}

// dataKeyCall is the options of a call through this cipher that asks
// ZeroKMS for data keys: its keyset, and its audit metadata.
func (cph *Cipher) dataKeyCall() callOptions {
	return callOptions{keyset: cph.keyset, audit: cph.audit}
}

// termCall is the options of a call through this cipher that derives a
// term. A term is derived from the index key of the keyset, so the call
// asks ZeroKMS for no data key, and sends no audit metadata.
func (cph *Cipher) termCall() callOptions {
	return callOptions{keyset: cph.keyset}
}
