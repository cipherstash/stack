package encrypt

import (
	"context"
	"fmt"

	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
)

// Cipher is a [Client] bound to one keyset: the Go form of the Rust
// crate's KeysetCipher. It seals values, derives terms and encrypts records
// under that keyset, and opens only that keyset's ciphertexts — a leaf
// sealed under another keyset is refused as [ErrForeignKeyset] before any
// key is retrieved. To open ciphertexts from any keyset, use the Client's
// decrypt methods.
//
// A Cipher holds no guest state: the keyset is selected on every call, and
// loaded by the guest on first use.
type Cipher struct {
	client *Client
	keyset KeysetSelector
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

// Encrypt seals v under this keyset. v is encoded through the vcvalue
// model: builtins, slices, maps and structs by reflection, a type
// implementing vcffi.Encryptable by its own encoding, vcvalue.Plain marking
// a passthrough. aad is authenticated but not encrypted, and may be empty;
// the same aad must be presented to Decrypt. The leaves of v seal from
// batched ZeroKMS key requests: one per 500 keyed leaves, so one request
// for any ordinary value.
//
// The ciphertext comes back as ordinary Go values mirroring the
// plaintext's structure: Sealed leaves (and the SealedNone / SealedEmptySeq
// / SealedEmptyMap markers) where fields were encrypted, vcvalue.Plain
// where they passed through, map[string]any for records, []any for
// sequences.
func (cph *Cipher) Encrypt(ctx context.Context, v any, aad []byte) (any, error) {
	return cph.encryptValue(ctx, v, aad, false)
}

// EncryptElement seals v as a sequence element of the collection identified
// by aad — byte-identical to what Encrypt of a whole slice binds per
// element — so a single row inserted this way interchanges with rows
// written by encrypting a slice under the same aad.
func (cph *Cipher) EncryptElement(ctx context.Context, v any, aad []byte) (any, error) {
	return cph.encryptValue(ctx, v, aad, true)
}

// Decrypt opens a ciphertext sealed under this keyset. ct is the shape
// Encrypt returns (any subset of a record's entries decrypts); the
// plaintext is returned in vcvalue's decode shape: Go natives,
// vcvalue.Object for records, vcvalue.Plain for passthrough fields. A leaf
// from another keyset is ErrForeignKeyset.
func (cph *Cipher) Decrypt(ctx context.Context, ct any, aad []byte) (any, error) {
	return cph.client.decryptValue(ctx, cph.keyset, ct, aad, false)
}

// DecryptElement opens a ciphertext sealed as a sequence element — a row
// of a collection encrypted from a slice, or by EncryptElement — under the
// same aad. Elements are authenticated against a derivation of the
// collection's aad, so Decrypt cannot open a lone row.
func (cph *Cipher) DecryptElement(ctx context.Context, ct any, aad []byte) (any, error) {
	return cph.client.decryptValue(ctx, cph.keyset, ct, aad, true)
}

// Term derives one index term for value under context: the probe that
// compares against a term stored by EncryptRecords for a field sealed under
// the same keyset and the same context. value is a scalar: an integer,
// string or byte slice for Equality (floats and booleans have no equality
// encoding); a string for Match; any scalar for Ore and Ope. The result is
// one of EqualityTerm, MatchTerm, OreTerm or OpeTerm.
//
// opts are [Option]s, the options a probe shares with the record calls; a
// [RecordOption] that only a record call takes, such as [WithPlan], does
// not compile here. [ExtendContext] extends context exactly as it extends
// each field's own context in a record call, so a probe for a field
// written under an extension is the field's context plus the same option
// value the rows were written with, never a context spelled by hand.
//
// Term takes a context and returns an error because it may be a ZeroKMS
// round trip: term derivation is asynchronous in the Rust crate, and a
// ZeroKMS backend that derives terms server-side settles the same way.
func (cph *Cipher) Term(ctx context.Context, value any, context Context, kind TermKind, opts ...Option) (any, error) {
	if context.isZero() {
		return nil, fmt.Errorf("encrypt: term context is empty")
	}
	var o termOptions
	for _, opt := range opts {
		opt.applyTerm(&o)
	}
	context, err := extend(context, o.extension)
	if err != nil {
		return nil, err
	}
	encodedValue, err := vcffi.Marshal(value)
	if err != nil {
		return nil, err
	}
	// The probe value is plaintext: its transport copy is wiped once it is
	// in the guest, as is the context it binds.
	defer wipe(encodedValue)
	encodedContext, err := vcffi.Marshal(context.value())
	if err != nil {
		return nil, err
	}
	defer wipe(encodedContext)
	encodedOpts, err := vcffi.Marshal(options(cph.keyset))
	if err != nil {
		return nil, err
	}
	out, err := cph.client.call(ctx, func(inst *instance) ([]byte, error) {
		return inst.call(ctx, inst.term, buf(encodedValue), buf(encodedContext), scalar(uint64(kind)), buf(encodedOpts))
	})
	if err != nil {
		return nil, err
	}
	return typedTerm(kind, out), nil
}

func typedTerm(kind TermKind, bytes []byte) any {
	switch kind {
	case Equality:
		return EqualityTerm(bytes)
	case Match:
		return MatchTerm(bytes)
	case Ore:
		return OreTerm(bytes)
	case Ope:
		return OpeTerm(bytes)
	default:
		return bytes
	}
}

func (cph *Cipher) encryptValue(ctx context.Context, v any, aad []byte, element bool) (any, error) {
	encoded, err := vcffi.Marshal(v)
	if err != nil {
		return nil, err
	}
	// The transport copy of the plaintext is wiped once it is in the guest.
	defer wipe(encoded)
	opts, err := vcffi.Marshal(options(cph.keyset))
	if err != nil {
		return nil, err
	}
	out, err := cph.client.call(ctx, func(inst *instance) ([]byte, error) {
		fn := inst.encrypt
		if element {
			fn = inst.encryptElement
		}
		return inst.call(ctx, fn, buf(encoded), buf(aad), buf(opts))
	})
	if err != nil {
		return nil, err
	}
	// Passthrough (vcvalue.Plain) fields come back in the clear; the
	// serialized copy is wiped once decoded.
	defer wipe(out)
	return unmarshalCipherText(out)
}
