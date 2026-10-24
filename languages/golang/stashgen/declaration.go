package stashgen

import (
	"fmt"
	"strings"
)

// Declaration is how each field of one struct is encrypted: the context of
// the struct, and the verb, indexes and EQL type of each field. The generator
// builds it from the stash tags, the engine checks it, and the generated file
// holds it as data that only generated code uses.
type Declaration struct {
	// Type is the Go type the declaration is for, as the generator prints it
	// in an error: "User" or "crm.Contact".
	Type string
	// Context is the context of every field, from the `context=` tag; ""
	// when ContextField is set.
	Context string
	// ContextField is the declaration name of the field whose value is the
	// context of every other field, from the `context_field` tag; "" when
	// the context comes from Context. The field is a string, stored as it
	// is, in the clear and unauthenticated like a passthrough.
	ContextField string
	// Opaque seals the whole struct as one value. The fields then carry no
	// tags and no indexes.
	Opaque bool
	// Fields are the struct's fields in declared order, omitted ones included.
	Fields []Field
}

// Field is one field of a declaration.
type Field struct {
	// Name is the field's name in the declaration, which is its column name.
	// An omitted field's Name is its Go name in snake case.
	Name string
	// GoName is the field's name in the Go struct.
	GoName string
	// GoType is the field's Go type, for the engine's checks.
	GoType GoType
	// Verb says what happens to the field.
	Verb Verb
	// Indexes are the indexes the tag names, for EncryptIndex and Index.
	Indexes []Index
	// EQLType is the EQL type an EncryptInto field seals into.
	EQLType string
	// Identity is the field's part of its context when it differs from Name:
	// a column that was renamed keeps the identity it was first written
	// under. "" means Name. Only a policy sets it.
	Identity string
	// Null is how a sealed field declared over a pointer stores nil; NotNull
	// for every other field. GoType is then the type the pointer points to.
	Null Null
}

// Null is how a sealed field declared over a pointer (*T) stores nil: the
// `null=` tag, or the generator's choice where the tag is left out.
type Null string

const (
	// NotNull is a field that is not a pointer: it is never nil.
	NotNull Null = ""
	// NullSealed seals nil like a value, as long as one, so the stored
	// field does not show that the value is absent. Its equality term is the
	// one every nil shares, and the generated EqNull queries it. The default
	// for a field whose only index, if any, is equality and whose type has a
	// fixed width: a bool, a number, encrypt.Date, time.Time,
	// encrypt.Decimal, encrypt.Int128 or encrypt.Uint128.
	NullSealed Null = "sealed"
	// NullSQL stores nothing for nil: the field's columns hold SQL NULL,
	// which shows that the value is absent. A field with an index other than
	// equality, or of text or bytes, says so with `null=sql`: its absence
	// would show anyway.
	NullSQL Null = "sql"
)

// fixedWidth reports whether a scalar kind seals at one length whatever its
// value, so that a sealed nil can be as long as a value.
func (k Kind) fixedWidth() bool {
	switch k {
	case KindBool, KindInt, KindUint, KindFloat, KindInt128, KindUint128,
		KindDate, KindTimestamp, KindDecimal:
		return true
	}
	return false
}

// Verb is what happens to a field.
type Verb uint8

const (
	// VerbOmit leaves the field out: it does not cross the binding.
	VerbOmit Verb = iota
	// VerbPassthrough stores the field as it is.
	VerbPassthrough
	// VerbEncrypt seals the field with no index.
	VerbEncrypt
	// VerbEncryptIndex seals the field and derives each index beside it.
	VerbEncryptIndex
	// VerbIndex derives the indexes alone, with no ciphertext.
	VerbIndex
	// VerbEncryptInto seals the field into one EQL value.
	VerbEncryptInto
	// VerbContextField stores the field as it is, and its value is the
	// context every other field is sealed under.
	VerbContextField
)

// String returns the tag word for the verb.
func (v Verb) String() string {
	switch v {
	case VerbOmit:
		return "-"
	case VerbPassthrough:
		return "passthrough"
	case VerbEncrypt:
		return "encrypt"
	case VerbEncryptIndex:
		return "encrypt,index"
	case VerbIndex:
		return "index"
	case VerbEncryptInto:
		return "encrypt_into"
	case VerbContextField:
		return "context_field"
	}
	return fmt.Sprintf("Verb(%d)", uint8(v))
}

// Stored reports whether the field is stored as it is: a passthrough, or
// the context field.
func (f Field) Stored() bool {
	return f.Verb == VerbPassthrough || f.Verb == VerbContextField
}

// Sealed reports whether the field has a ciphertext or a term: every verb
// but omit and passthrough.
func (f Field) Sealed() bool {
	switch f.Verb {
	case VerbEncrypt, VerbEncryptIndex, VerbIndex, VerbEncryptInto:
		return true
	}
	return false
}

// HasCiphertext reports whether the field's outputs include a ciphertext.
func (f Field) HasCiphertext() bool {
	return f.Verb == VerbEncrypt || f.Verb == VerbEncryptIndex
}

// Index is one index on a field, with its options.
type Index struct {
	Name    IndexName
	Options []Option
}

// String spells the index as the tag does: `match` or `match(k=3)`.
func (i Index) String() string {
	if len(i.Options) == 0 {
		return string(i.Name)
	}
	opts := make([]string, len(i.Options))
	for n, o := range i.Options {
		opts[n] = o.String()
	}
	return string(i.Name) + "(" + strings.Join(opts, ",") + ")"
}

// Option is one option of an index, from the parentheses after its name.
type Option struct {
	Key   string
	Value string
}

// String spells the option as the tag does.
func (o Option) String() string {
	if o.Value == "" {
		return o.Key
	}
	return o.Key + "=" + o.Value
}

// IndexName is the tag word for an index. The words are the Rust API's.
type IndexName string

// The index names.
const (
	IndexEquality IndexName = "equality"
	IndexMatch    IndexName = "match"
	IndexOre      IndexName = "ore"
	IndexOpe      IndexName = "ope"
	IndexJSON     IndexName = "json"
	// IndexOreBlock is block ORE (ore-rs's 6-bit schemes): the index of an
	// EQL type's ORE term (`ob`), TextOrdOre's and IntegerOrdOre's. It is
	// not a tag word: a field reaches it by naming such an EQL type
	// (encrypt_into=), and indexNames leaves it out.
	IndexOreBlock IndexName = "ore_block"
)

// indexNames lists every index, in the order the generated type lists their
// outputs.
var indexNames = []IndexName{IndexEquality, IndexMatch, IndexOre, IndexOpe, IndexJSON}

// GoName is the index's name in generated code: the field of the output
// struct that holds its term, and the query method of the field entry.
func (n IndexName) GoName() string {
	switch n {
	case IndexEquality:
		return "Equality"
	case IndexMatch:
		return "Match"
	case IndexOre:
		return "Ore"
	case IndexOpe:
		return "Ope"
	case IndexOreBlock:
		return "OreBlock"
	case IndexJSON:
		return "JSON"
	}
	return string(n)
}

// GoType describes a field's Go type to the engine without go/types.
type GoType struct {
	// Name is the type as Go source in the field's package: "string",
	// "int64", "[]string", "time.Time", "crm.Address".
	Name string
	// Kind is the type's underlying kind.
	Kind Kind
	// Basic is the underlying basic type's name for a scalar kind — "uint8",
	// "int", "string" — which decides the wire type the field seals as. It is
	// "" for a value type the generator knows by name (time.Time,
	// encrypt.Date, encrypt.Int128, encrypt.Uint128, encrypt.Decimal), whose
	// kind says all there is.
	Basic string
	// Elem is the element type of a slice, map or pointer, and nil otherwise.
	Elem *GoType
	// Fields are the fields of a struct kind, in declared order.
	Fields []GoType
}

// String returns the type as Go source.
func (t GoType) String() string { return t.Name }

// Kind is the underlying kind of a Go type, as far as the engine needs it.
type Kind uint8

const (
	// KindOther is a kind the engine cannot seal: a channel, a function, an
	// interface, a complex number, or a struct with an unexported field.
	KindOther Kind = iota
	KindString
	KindBool
	KindInt
	KindUint
	KindFloat
	// KindBytes is []byte.
	KindBytes
	KindSlice
	KindMap
	KindPointer
	// KindStruct is a struct whose fields are all exported.
	KindStruct
	// KindInt128 and KindUint128 are encrypt.Int128 and encrypt.Uint128.
	KindInt128
	KindUint128
	// KindDate is encrypt.Date, a calendar date.
	KindDate
	// KindTimestamp is time.Time, an instant.
	KindTimestamp
	// KindDecimal is encrypt.Decimal.
	KindDecimal
)

var kindNames = [...]string{
	KindOther:     "other",
	KindString:    "string",
	KindBool:      "bool",
	KindInt:       "int",
	KindUint:      "uint",
	KindFloat:     "float",
	KindBytes:     "bytes",
	KindSlice:     "slice",
	KindMap:       "map",
	KindPointer:   "pointer",
	KindStruct:    "struct",
	KindInt128:    "int128",
	KindUint128:   "uint128",
	KindDate:      "date",
	KindTimestamp: "timestamp",
	KindDecimal:   "decimal",
}

// String returns the kind's name.
func (k Kind) String() string {
	if int(k) < len(kindNames) {
		return kindNames[k]
	}
	return fmt.Sprintf("Kind(%d)", uint8(k))
}

// Scalar reports whether the kind is one value an index can take.
func (k Kind) Scalar() bool {
	switch k {
	case KindString, KindBool, KindInt, KindUint, KindFloat, KindBytes,
		KindInt128, KindUint128, KindDate, KindTimestamp, KindDecimal:
		return true
	}
	return false
}
