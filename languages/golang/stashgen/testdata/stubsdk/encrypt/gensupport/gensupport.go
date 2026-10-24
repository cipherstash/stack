// Package gensupport is a TEST STUB of encrypt/gensupport, signatures only,
// for compiling generated code in the generator's tests. The real package
// lives at languages/golang/encrypt/gensupport; today it holds the version
// constant, Redacted, RedactedLog and the notices, and the integration step
// adds the rest of what is declared here.
package gensupport

import (
	"context"
	"log/slog"

	"github.com/cipherstash/stack/languages/golang/encrypt"
)

type generatedVersion uint8

// GeneratedVersion1 is the layout of files stashgen writes today.
const GeneratedVersion1 generatedVersion = 1

// OpaqueField is the one field of an opaque declaration.
const OpaqueField = "value"

// Kind is a field's wire type.
type Kind string

// The kinds.
const (
	Untyped   Kind = ""
	Bool      Kind = "bool"
	Int8      Kind = "int8"
	Int16     Kind = "int16"
	Int32     Kind = "int32"
	Int64     Kind = "int64"
	Int128    Kind = "int128"
	Uint8     Kind = "uint8"
	Uint16    Kind = "uint16"
	Uint32    Kind = "uint32"
	Uint64    Kind = "uint64"
	Uint128   Kind = "uint128"
	Float32   Kind = "float32"
	Float64   Kind = "float64"
	Decimal   Kind = "decimal"
	Date      Kind = "date"
	Timestamp Kind = "timestamp"
	String    Kind = "string"
	Bytes     Kind = "bytes"
)

// Redacted formats a value with its sealed fields hidden.
func Redacted(typeName string, shown map[string]any, hidden ...string) string { return "" }

// RedactedLog is Redacted for slog.
func RedactedLog(shown map[string]any, hidden ...string) slog.Value { return slog.Value{} }

// Values are a struct's field values by declared name.
type Values map[string]any

// Output is what the engine returned for one field.
type Output struct {
	Value      any
	Ciphertext encrypt.Ciphertext
	Equality   encrypt.EqualityTerm
	Match      encrypt.MatchTerm
	Ore        encrypt.OreTerm
	Ope        encrypt.OpeTerm
	JSON       encrypt.JSONTerm
	EQL        []byte
}

// Record is the engine's output for a struct, by declared name.
type Record map[string]Output

// Declaration is the data form of a struct's tags.
type Declaration struct{ _ struct{} }

// Declare starts a declaration with its context.
func Declare(context string) Declaration { return Declaration{} }

// DeclareOpaque declares a struct sealed as one value.
func DeclareOpaque(context string) Declaration { return Declaration{} }

// DeclareContextField starts a declaration whose context is a field.
func DeclareContextField(name string) Declaration { return Declaration{} }

func (d Declaration) Passthrough(name string) Declaration                                   { return d }
func (d Declaration) Encrypt(name string, kind Kind) Declaration                            { return d }
func (d Declaration) EncryptIndex(name string, kind Kind, idx ...encrypt.Index) Declaration { return d }
func (d Declaration) Index(name string, kind Kind, idx ...encrypt.Index) Declaration        { return d }
func (d Declaration) EncryptInto(name string, kind Kind, eqlType string) Declaration        { return d }
func (d Declaration) Omit(name string) Declaration                                          { return d }
func (d Declaration) Err() error                                                            { return nil }

// Generated is what a generated file gives the library for one type.
type Generated[P, E any] struct {
	TypeName        string
	Declaration     Declaration
	PrintsPlaintext bool
	Unexported      []string
	Source          func(P) Values
	Seal            func(Record) (E, error)
	Open            func(E) Record
	Value           func(E, Values) (P, error)
}

// Codec encrypts and decrypts one type.
type Codec[P, E any] struct{ _ struct{} }

// New builds the codec for a generated type.
func New[P, E any](Generated[P, E]) *Codec[P, E] { return nil }

func (*Codec[P, E]) Encrypt(context.Context, *encrypt.Cipher, []P) ([]E, error) { return nil, nil }
func (*Codec[P, E]) Decrypt(context.Context, encrypt.Decrypter, []E) ([]P, error) {
	return nil, nil
}

// Passthrough reads a passthrough field from a record.
func Passthrough[T any](Record, string) (T, error) { var z T; return z, nil }

// Get reads one value.
func Get[T any](Values, string) (T, error) { var z T; return z, nil }

// Opaque reads an opened opaque value into the generated shape struct.
func Opaque[T any](Values, *T) error { return nil }

// Field is one sealed field's entry.
type Field[T any] struct{ _ struct{} }

// NewField makes the entry for one field of a declaration.
func NewField[T any](Declaration, string) Field[T] { return Field[T]{} }

func (Field[T]) Encrypt(context.Context, *encrypt.Cipher, T) (Output, error)      { return Output{}, nil }
func (Field[T]) Term(context.Context, *encrypt.Cipher, string, T) ([]byte, error) { return nil, nil }
func (Field[T]) Range(context.Context, *encrypt.Cipher, string, T, T) ([]byte, []byte, error) {
	return nil, nil, nil
}

// Matches derives a matches query.
func Matches[T ~string](context.Context, Field[T], *encrypt.Cipher, T) (encrypt.MatchQuery[T], error) {
	return encrypt.MatchQuery[T]{}, nil
}

// EQLMatches derives the matches query on an EQL type with a match index.
func EQLMatches[Q ~[]byte, T ~string](context.Context, Field[T], *encrypt.Cipher, T) (encrypt.EQLMatchQuery[Q, T], error) {
	return encrypt.EQLMatchQuery[Q, T]{}, nil
}

// RecordsCodec encrypts into and decrypts from a model.
type RecordsCodec[P, R any] struct{ _ struct{} }

// Records wraps a codec with a model's conversions.
func Records[P, E, R any](*Codec[P, E], func(E) R, func(R) E) *RecordsCodec[P, R] { return nil }

func (*RecordsCodec[P, R]) Encrypt(context.Context, *encrypt.Cipher, []P) ([]R, error) {
	return nil, nil
}
func (*RecordsCodec[P, R]) Decrypt(context.Context, encrypt.Decrypter, []R) ([]P, error) {
	return nil, nil
}

// NoticeUntagged and NoticePrintsPlaintext are the running program's
// notices; the real New calls them once for each type.
func NoticeUntagged(typeName string, fields []string) {}
func NoticePrintsPlaintext(typeName string)           {}

// Identity gives a field a context part other than its name.
func (d Declaration) Identity(name, identity string) Declaration { return d }

// NullMode is how a sealed field declared over a pointer stores nil.
type NullMode string

const (
	NullSealed NullMode = "sealed"
	NullSQL    NullMode = "sql"
)

// Null says how the named field, declared over a pointer, stores nil.
func (d Declaration) Null(name string, mode NullMode) Declaration { return d }

// Deref is a field declared over a pointer as Source gives it.
func Deref[T any](p *T) any {
	if p == nil {
		return nil
	}
	return *p
}

// EncryptNull seals nil for a field that stores it as a sealed null.
func (f Field[T]) EncryptNull(context.Context, *encrypt.Cipher) (Output, error) {
	return Output{}, nil
}

// NullTerm derives an exact operator's term for nil.
func (f Field[T]) NullTerm(context.Context, *encrypt.Cipher, string) ([]byte, error) {
	return nil, nil
}

// GetPtr reads one opened field declared over a pointer.
func GetPtr[T any](Values, string) (*T, error) { return nil, nil }
