package encrypt

import (
	"context"
	"fmt"

	"github.com/cipherstash/stack/languages/golang/internal/record"
)

// Cipher is a [Client] bound to one keyset, and to any extension of the
// context: the Go form of the Rust crate's KeysetCipher. Generated code seals
// values, derives terms and opens records through it; a program never calls
// the engine directly. A Cipher opens only its own keyset's ciphertexts — a
// leaf sealed under another keyset is refused as [ErrForeignKeyset] before
// any key is retrieved. To open ciphertexts from any keyset, pass the
// [Client] where a [Decrypter] is taken. A Client opens only rows that a
// cipher with no extension encrypted; rows sealed through [Cipher.Extend]
// open only through a cipher with the same extension.
//
// A Cipher holds no guest state: the keyset is selected on every call, and
// loaded by the guest on first use, so one is cheap to make per request or
// per tenant.
type Cipher struct {
	client    *Client
	keyset    KeysetSelector
	extension []any
	// context is the label Context named, for a type whose context is one
	// of its fields; "" names none.
	context string
	// err is a refused extension part or context, reported by the first
	// call rather than by Extend or Context: a cipher is made without a
	// request, and no call on this package panics.
	err error
}

// Client is the client this cipher belongs to.
func (cph *Cipher) Client() *Client { return cph.client }

// Keyset is the selector this cipher is bound to.
func (cph *Cipher) Keyset() KeysetSelector { return cph.keyset }

// KeysetID resolves the cipher's keyset to its id: Rust's
// KeysetCipher::keyset_id, and in Go the one explicit resolution point,
// since a Cipher is made without a request. The first use of a name or id
// on the client is one ZeroKMS round trip, later uses come from the
// guest's cache; the default keyset never makes a request. Use it at boot
// to validate a tenant's keyset and learn its id.
func (cph *Cipher) KeysetID(ctx context.Context) (KeysetID, error) {
	return cph.client.resolveKeyset(ctx, cph.keyset)
}

// Extend returns a cipher that extends the context of every field, in every
// call through it: the write, the query and the read. It appends to the
// context the tags declare and never replaces it, so a field sealed through
// cipher.Extend("tenant-42") opens and matches only through a cipher with
// the same extension. A part is a string, a byte slice or an integer
// (int32, int64, uint32, uint64; Go's int is sent as int64); a byte slice is
// copied. Several parts nest in order: Extend(a, b) is Extend(a).Extend(b).
// An unsupported part type is reported by the first call through the
// cipher, as [ErrEncoding].
func (cph *Cipher) Extend(parts ...any) *Cipher {
	next := &Cipher{client: cph.client, keyset: cph.keyset, context: cph.context, err: cph.err}
	next.extension = append(next.extension, cph.extension...)
	for _, part := range parts {
		if err := record.CheckPart(part); err != nil && next.err == nil {
			next.err = fmt.Errorf("%w: Extend: %v", ErrEncoding, err)
		}
		next.extension = append(next.extension, part)
	}
	return next
}

// Extension is the parts the cipher extends every field's context by, in
// order. Empty for a cipher straight from [Client.Keyset].
func (cph *Cipher) Extension() []any {
	return append([]any(nil), cph.extension...)
}

// Context returns a cipher that names the context every row through it is
// under, for a type whose context is one of its own fields (a field tagged
// `context_field`): the Rust chain's `.context(..)`. Through such a cipher,
// Decrypt checks each row's stored context field against the label before
// any key is retrieved and refuses a row that names another with
// [ErrContextMismatch]; Encrypt refuses a value whose context field says
// otherwise the same way, before anything is sent; a query derives its term
// under the label, which such a type cannot derive otherwise; and a field's
// own Encrypt seals the one value under it. Without a Context, Encrypt and
// Decrypt take each row's context from the row, and a query has no context
// to derive under. A type with a `context=` tag has its context already, so
// every call through a cipher with a Context refuses it as [ErrEncoding].
// The label is segments separated by '/', such as "tenants/acme"; one that
// is not a plain label is reported by the first call, as ErrEncoding.
func (cph *Cipher) Context(label string) *Cipher {
	next := &Cipher{client: cph.client, keyset: cph.keyset, context: label, err: cph.err}
	next.extension = append(next.extension, cph.extension...)
	if _, err := record.ParseContext(label); err != nil && next.err == nil {
		next.err = fmt.Errorf("%w: Context: %v", ErrEncoding, err)
	}
	return next
}

// ContextLabel is the label [Cipher.Context] named, or "" for a cipher
// that names none.
func (cph *Cipher) ContextLabel() string { return cph.context }
