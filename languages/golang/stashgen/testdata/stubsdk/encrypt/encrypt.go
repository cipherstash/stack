// Package encrypt is a TEST STUB of the Stack Encrypt Go SDK, signatures
// only. The generator's tests compile generated code against it, so a change
// that emits uncompilable Go fails here. Every symbol it declares is one the
// generated code names; the SDK must declare each with these shapes.
//
// It is not the SDK, and nothing outside stashgen's tests imports it.
package encrypt

import "context"

// Cipher is a keyset with any extension of the context.
type Cipher struct{ _ struct{} }

// Client decrypts under the keyset that sealed each value.
type Client struct{ _ struct{} }

// Decrypter is what Decrypt takes: a *Client or a *Cipher.
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

// Index is one index on a field, as generated code names it in a declaration.
type Index interface{ index() }

type namedIndex string

func (namedIndex) index() {}

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
func NewClient(context.Context, ...Option) (*Client, error) { return nil, nil }

// Option configures a client.
type Option interface{ option() }

// Close closes the client.
func (*Client) Close() error { return nil }
