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
	// Context is the context of every field, from the `context=` tag.
	Context string
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
	}
	return fmt.Sprintf("Verb(%d)", uint8(v))
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
	// "int", "string" — which decides the wire type the field seals as.
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
)

var kindNames = [...]string{
	KindOther:   "other",
	KindString:  "string",
	KindBool:    "bool",
	KindInt:     "int",
	KindUint:    "uint",
	KindFloat:   "float",
	KindBytes:   "bytes",
	KindSlice:   "slice",
	KindMap:     "map",
	KindPointer: "pointer",
	KindStruct:  "struct",
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
	case KindString, KindBool, KindInt, KindUint, KindFloat, KindBytes:
		return true
	}
	return false
}
