package encrypt

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/cipherstash/stack/languages/golang/internal/record"
)

// AuditMetadata is facts about a call that ZeroKMS writes to its audit log.
//
// Every Encrypt and Decrypt asks ZeroKMS for data keys. ZeroKMS logs each
// request with the identity that made it. AuditMetadata provides additional
// context for that log. Typical facts are the purpose of the call, a request
// ID, a trace ID, and the end user that the call acts for.
//
// Attach it to a cipher with [Cipher.Audit], or to a client with
// [Client.Audit]:
//
//	cipher := client.DefaultKeyset().Audit(encrypt.AuditMetadata{
//		"purpose":    "list issues",
//		"request_id": requestID,
//	})
//	people, err := users.Decrypt(ctx, cipher, rows)
//
// Audit metadata is optional. A cipher without it sends none. It is the
// Rust crate's AuditMetadata, and the unverified context of the ZeroKMS
// protocol.
//
// # Rules
//
//   - ZeroKMS does not verify the facts. The program states them, and
//     ZeroKMS records them as given. No key depends on them, so do not use
//     them for access control.
//   - A decrypt does not need them. A Decrypt can send different facts from
//     the Encrypt, or none.
//   - Do not send plaintext or secrets. ZeroKMS writes the facts to its
//     logs. Do not send anything derived from plaintext either.
//   - An IP address or a user agent is personal data. The SDK sends only
//     what you pass, and adds nothing.
//   - A query sends none. A query term is derived from the index key of
//     the keyset, so a query asks ZeroKMS for no data key. A query through
//     a cipher that has metadata still works.
//   - A call that asks for no data key sends none. An Encrypt or a Decrypt
//     of no rows is one such call.
//
// # Values
//
// A value has one of these types, and no other:
//
//   - nil;
//   - bool;
//   - string;
//   - an integer: int, int8, int16, int32, int64, uint, uint8, uint16,
//     uint32, or uint64;
//   - float32 or float64;
//   - time.Time;
//   - []any or []string, for a list;
//   - map[string]any or AuditMetadata, for a nested map.
//
// The first call through the cipher refuses any other type, with
// [ErrEncoding]. A []byte, a struct, a pointer, and a named type such as
// `type ID string` are four examples. Convert the value to a type in the
// list: send a []byte as text, such as its hex form.
//
// ZeroKMS records each value as you give it, with two exceptions:
//
//   - A time.Time is sent as RFC 3339 text in UTC, such as
//     "2026-11-20T10:00:00Z", because ZeroKMS has no type for a time. The
//     text keeps the instant to the nanosecond. It does not keep the zone
//     that the time was in. RFC 3339 has no form for a time outside the
//     years 0 to 9999. Such a time is refused.
//   - A float that is not finite is sent as null.
//
// ZeroKMS reads a number as an int64 or a float64. So an integer above the
// largest int64 is refused too, with ErrEncoding: send it as text.
type AuditMetadata map[string]any

// auditFacts is the metadata a cipher holds: its own copy, which no caller
// can change. nil is no metadata.
//
// It is a function that returns the facts, and not the map itself, so that
// printing a cipher never shows a fact. Package fmt prints a function as an
// address, under every verb. It prints a map, or a pointer to a struct,
// with its contents under some verbs. A fact can be personal data. A debug
// log is not the audit log.
type auditFacts func() map[string]any

// with is these facts and metadata's together. A fact in metadata replaces
// one that has the same key. The result shares nothing with metadata: every
// value is checked and copied. A value of a type that audit metadata does
// not take is an [ErrEncoding] that names Audit.
func (a auditFacts) with(metadata AuditMetadata) (auditFacts, error) {
	if len(metadata) == 0 {
		return a, nil
	}
	added, err := auditMap(metadata, 1)
	if err != nil {
		return nil, fmt.Errorf("%w: Audit: %v", ErrEncoding, err)
	}
	facts := make(map[string]any, len(added))
	if a != nil {
		for key, value := range a() {
			facts[key] = value
		}
	}
	for key, value := range added {
		facts[key] = value
	}
	return func() map[string]any { return facts }, nil
}

// maxAuditDepth is how deep a map or a list in audit metadata can nest. A
// map that holds itself would otherwise never end. The transport codec
// allows 128 levels for a whole call, and the options that carry the
// metadata use two of them.
const maxAuditDepth = 32

// errAuditDepth is the refusal of metadata nested deeper than
// [maxAuditDepth].
var errAuditDepth = fmt.Errorf("the metadata nests more than %d levels deep", maxAuditDepth)

// auditMap is a copy of m with each value as [auditValue] gives it. An
// error names the key of the fact that was refused, and never a value: a
// key is a name the program chose, and a value can be personal data.
func auditMap(m map[string]any, depth int) (map[string]any, error) {
	if depth > maxAuditDepth {
		return nil, errAuditDepth
	}
	out := make(map[string]any, len(m))
	for key, value := range m {
		if !utf8.ValidString(key) {
			return nil, errors.New("a key is not valid UTF-8")
		}
		sent, err := auditValue(value, depth)
		if err != nil {
			return nil, fmt.Errorf("the fact %q: %w", key, err)
		}
		out[key] = sent
	}
	return out, nil
}

// auditValue is value in the form the cipher sends, as the cipher's own
// copy. The type switch is the closed list of types that [AuditMetadata]
// documents, so no value is read by reflection. A time becomes RFC 3339
// text in UTC: ZeroKMS has no type for a time, and the guest's contract
// gives every language SDK this one text form. Whether a number fits is
// the engine's rule, so the engine checks it.
func auditValue(value any, depth int) (any, error) {
	switch v := value.(type) {
	case nil, bool,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64:
		return v, nil
	case string:
		if !utf8.ValidString(v) {
			return nil, errors.New("text that is not valid UTF-8")
		}
		return v, nil
	case time.Time:
		utc := v.UTC()
		if year := utc.Year(); year < 0 || year > 9999 {
			return nil, errors.New("a time outside the years 0 to 9999 has no RFC 3339 form")
		}
		return utc.Format(time.RFC3339Nano), nil
	case []any:
		if depth >= maxAuditDepth {
			return nil, errAuditDepth
		}
		out := make([]any, len(v))
		for i, item := range v {
			sent, err := auditValue(item, depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = sent
		}
		return out, nil
	case []string:
		out := make([]any, len(v))
		for i, item := range v {
			sent, err := auditValue(item, depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = sent
		}
		return out, nil
	case map[string]any:
		return auditMap(v, depth+1)
	case AuditMetadata:
		return auditMap(v, depth+1)
	case []byte:
		return nil, errors.New("a []byte is not an audit value: send it as text")
	default:
		return nil, fmt.Errorf("a %T is not an audit value", value)
	}
}

// Audit returns a cipher that sends metadata to ZeroKMS with every data-key
// request it makes, for the ZeroKMS audit log. Every Encrypt and Decrypt
// through the cipher sends it, and so does every read of an encrypted JSON
// document. A query sends none. See [AuditMetadata] for what ZeroKMS does
// with the facts, and for what you must not send.
//
// Audit adds to the facts the cipher already has. A fact in metadata
// replaces one that has the same key:
//
//	service := client.DefaultKeyset().Audit(encrypt.AuditMetadata{"service": "billing"})
//	request := service.Audit(encrypt.AuditMetadata{"request_id": requestID})
//
// The second cipher sends both facts. The first still sends one.
//
// The cipher keeps its own copy of the facts. A later change to metadata
// does not change what the cipher sends. A value of a type that
// [AuditMetadata] does not list is reported by the first call through the
// cipher, as [ErrEncoding].
func (cph *Cipher) Audit(metadata AuditMetadata) *Cipher {
	next := cph.copy()
	facts, err := cph.audit.with(metadata)
	if err != nil {
		if next.err == nil {
			next.err = err
		}
		return next
	}
	next.audit = facts
	return next
}

// Audit returns a [Decrypter] that opens records as the client does, under
// whichever keyset sealed each one. It sends metadata to ZeroKMS with every
// data-key request it makes. See [AuditMetadata] for what ZeroKMS does with
// the facts, and for what you must not send.
//
//	people, err := users.Decrypt(ctx, client.Audit(encrypt.AuditMetadata{
//		"purpose": "export",
//	}), rows)
//
// The Decrypter keeps its own copy of the facts. A value of a type that
// [AuditMetadata] does not list is reported by the first Decrypt through
// it, as [ErrEncoding].
func (c *Client) Audit(metadata AuditMetadata) Decrypter {
	facts, err := auditFacts(nil).with(metadata)
	return &auditedClient{client: c, audit: facts, err: err}
}

// auditedClient is a client with audit metadata: what [Client.Audit]
// returns.
type auditedClient struct {
	client *Client
	audit  auditFacts
	// err is a refused metadata value, reported by the first Open: no call
	// on this package panics.
	err error
}

// Open decrypts records as [Client.Open] does, and sends the metadata with
// every data-key request. For generated code.
func (a *auditedClient) Open(ctx context.Context, plan *record.Plan, records []record.Sealed) ([]record.Source, error) {
	if a == nil || a.client == nil {
		return nil, fmt.Errorf("%w: Open on a nil *Client", ErrEncoding)
	}
	if a.err != nil {
		return nil, a.err
	}
	return a.client.openAny(ctx, a.audit, plan, records)
}
