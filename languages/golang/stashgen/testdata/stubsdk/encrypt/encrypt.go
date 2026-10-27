// Package encrypt is a TEST STUB of the Stack Encrypt Go SDK, signatures
// only. The generator's tests compile generated code against it, so a change
// that emits uncompilable Go fails here. Every symbol it declares is one the
// generated code names; the SDK must declare each with these shapes.
//
// It is not the SDK, and nothing outside stashgen's tests imports it.
package encrypt

import (
	"context"
	"encoding/json"
	"time"
)

// Cipher is a keyset with any extension of the context.
type Cipher struct{ _ struct{} }

// Client decrypts under the keyset that sealed each value.
type Client struct{ _ struct{} }

// Decrypter is what Decrypt takes: a *Client or a *Cipher. The real
// interface's method takes the module's internal record types; the stub's
// is a placeholder, and the agreement test compares interfaces by presence.
type Decrypter interface{ decrypter() }

func (*Cipher) decrypter() {}
func (*Client) decrypter() {}

// Ciphertext is a sealed value in separate columns.
type Ciphertext []byte

// The term types, one for each index.
type (
	EqualityTerm []byte
	MatchTerm    []byte
	OreTerm      []byte
	OpeTerm      []byte
	JSONTerm     []byte
)

// Range is a between query on an order index: two terms.
type Range[T OreTerm | OpeTerm] struct {
	Low  T
	High T
}

// MatchQuery is a matches query on a match index.
type MatchQuery[T ~string] struct{ _ T }

// EQLMatchQuery is a matches query on an EQL type with a match index.
type EQLMatchQuery[Q ~[]byte, T ~string] struct {
	_ Q
	_ T
}

// Index is one index on a field, as generated code names it in a declaration.
type Index interface {
	Output() string
	String() string
}

type namedIndex string

func (n namedIndex) Output() string { return string(n) }
func (n namedIndex) String() string { return string(n) }

// The indexes. Equality, Ore and Ope take no options; Match and JSON do.
var (
	Equality Index = namedIndex("equality")
	Ore      Index = namedIndex("ore")
	Ope      Index = namedIndex("ope")
)

// MatchOption is an option of the match index.
type MatchOption interface{ matchOption() }

// Match is the match index with its options.
func Match(...MatchOption) Index { return namedIndex("match") }

// JSONOption is an option of the json index.
type JSONOption interface{ jsonOption() }

// JSON is the json index with its options.
func JSON(...JSONOption) Index { return namedIndex("json") }

// KeysetName names a keyset.
type KeysetName string

// Keyset returns the cipher for a keyset.
func (*Client) Keyset(KeysetName) *Cipher { return nil }

// Extend returns a cipher that appends to every field's context.
func (c *Cipher) Extend(string) *Cipher { return c }

// NewClient opens a client.
func NewClient(context.Context, ...ClientOption) (*Client, error) { return nil, nil }

// ClientOption configures a client.
type ClientOption func(*clientOptions)

type clientOptions struct{}

// Close closes the client.
func (*Client) Close() error { return nil }

// The value types a field can hold beside Go's own. The real ones are
// aliases of vitaminc's vcvalue types; the generator recognises them by
// their name in this package.
type (
	Date struct {
		Year  int
		Month time.Month
		Day   int
	}
	Int128  [16]byte
	Uint128 [16]byte
	Decimal struct {
		Coefficient [12]byte
		Scale       uint8
		Negative    bool
	}
)

// JSONSelector is the selector `col -> $1::text` binds.
type JSONSelector string

// JSONToken is one node's token.
type JSONToken string

// JSONTokens are a subtree read's tokens.
type JSONTokens []string

// JSONValue is one value a read reached, or none.
type JSONValue struct {
	Found bool
	JSON  []byte
}

// DecodeJSON reads JSON text a read opened into a value of type T.
func DecodeJSON[T any](json.RawMessage) (T, error) { var z T; return z, nil }

// JSONReadOptions are a subtree read's options.
type JSONReadOptions struct{ WildcardBound uint32 }

// JSONRange is both bounds of a between at a path.
type JSONRange[Q ~[]byte] struct{ Low, High Q }

// JSONSelection is a prepared `->` on a JSONSearch field.
type JSONSelection[E ~[]byte] struct{ _ E }

func (JSONSelection[E]) Selector() JSONSelector                          { return "" }
func (JSONSelection[E]) Open(context.Context, []*E) ([]JSONValue, error) { return nil, nil }

// JSONRead is a prepared subtree read on a JSONSearch field.
type JSONRead[E ~[]byte] struct{ _ E }

func (JSONRead[E]) Tokens() JSONTokens                              { return nil }
func (JSONRead[E]) OpenOne(context.Context, []E) (JSONValue, error) { return JSONValue{}, nil }
