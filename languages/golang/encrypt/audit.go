package encrypt

import (
	"context"
	"fmt"

	"github.com/cipherstash/stack/languages/golang/internal/record"
	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// AuditMetadata is facts about a call that ZeroKMS writes to its audit log.
//
// Every Encrypt and Decrypt asks ZeroKMS for data keys, and ZeroKMS logs
// each request with the identity that made it. AuditMetadata provides
// additional context for that log: the purpose of the call, a request ID, a
// trace ID, or the end user that the call acts for. Attach it to a cipher
// with [Cipher.Audit], or to a client with [Client.Audit]:
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
//     logs. Do not send anything derived from plaintext either. An IP
//     address or a user agent is personal data. The SDK sends only what
//     you pass, and adds nothing.
//   - A query sends none. A query term is derived from the index key of
//     the keyset, so a query asks ZeroKMS for no data key, and there is no
//     request to send the facts with. A query through a cipher that has
//     metadata still works.
//   - A call that asks for no data key sends none: an Encrypt or a Decrypt
//     of no rows, or of rows that hold no sealed value.
//
// # Values
//
// A value is a bool, a string, an integer, a float, nil, a slice of these,
// or a map with string keys. A struct is sent as a map of its fields.
// ZeroKMS records each value as you give it, with one exception: a float
// that is not finite is sent as null.
//
// ZeroKMS has no form for these values, and the first call through the
// cipher refuses them with [ErrEncoding]:
//
//   - a []byte: send it as text, such as its hex form;
//   - a time.Time: send it as text, such as its RFC 3339 form;
//   - an integer above the largest int64: send it as text.
type AuditMetadata map[string]any

// auditFacts is the metadata a cipher holds: its own copy, which no caller
// can change. nil is no metadata.
//
// It is a function that returns the facts, and not the map itself, so that
// printing a cipher never shows a fact. Package fmt prints a function as an
// address, under every verb. It prints a map, or a pointer to a struct,
// with its contents under some verbs. A fact can be personal data, and a
// debug log is not the audit log.
type auditFacts func() map[string]any

// with is these facts and metadata's together. A fact in metadata replaces
// one that has the same key. The result shares nothing with metadata: the
// values go through the transport codec and back, which copies them and
// reports a Go value that the codec cannot carry.
func (a auditFacts) with(metadata AuditMetadata) (auditFacts, error) {
	if len(metadata) == 0 {
		return a, nil
	}
	encoded, err := vcffi.Marshal(map[string]any(metadata))
	if err != nil {
		return nil, err
	}
	decoded, err := vcffi.Unmarshal(encoded)
	if err != nil {
		return nil, err
	}
	object, ok := decoded.(vcvalue.Object)
	if !ok {
		return nil, fmt.Errorf("the metadata was read back as %T", decoded)
	}
	facts := make(map[string]any, len(object))
	if a != nil {
		for key, value := range a() {
			facts[key] = value
		}
	}
	for _, field := range object {
		facts[field.Key] = field.Value
	}
	return func() map[string]any { return facts }, nil
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
// does not change what the cipher sends. A value that the SDK cannot send
// is reported by the first call through the cipher, as [ErrEncoding].
func (cph *Cipher) Audit(metadata AuditMetadata) *Cipher {
	next := cph.copy()
	facts, err := cph.audit.with(metadata)
	if err != nil {
		if next.err == nil {
			next.err = fmt.Errorf("%w: Audit: %v", ErrEncoding, err)
		}
		return next
	}
	next.audit = facts
	return next
}

// Audit returns a [Decrypter] that opens records as the client does, under
// whichever keyset sealed each one, and sends metadata to ZeroKMS with
// every data-key request it makes. See [AuditMetadata] for what ZeroKMS
// does with the facts, and for what you must not send.
//
//	people, err := users.Decrypt(ctx, client.Audit(encrypt.AuditMetadata{
//		"purpose": "export",
//	}), rows)
//
// The Decrypter keeps its own copy of the facts. A value that the SDK
// cannot send is reported by the first Decrypt through it, as
// [ErrEncoding].
func (c *Client) Audit(metadata AuditMetadata) Decrypter {
	audited := &auditedClient{client: c}
	facts, err := audited.audit.with(metadata)
	if err != nil {
		audited.err = fmt.Errorf("%w: Audit: %v", ErrEncoding, err)
		return audited
	}
	audited.audit = facts
	return audited
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
