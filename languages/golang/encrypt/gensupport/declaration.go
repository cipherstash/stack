package gensupport

import (
	"errors"
	"fmt"
	"slices"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/internal/record"
)

// Kind is a field's wire type: the data form of the Rust chain's `::<F>`,
// chosen by stashgen from the field's Go type. It decides the terms a field
// derives; every field seals as vitaminc's tagged leaf whatever its kind,
// which a Rust record opens when its field is a Value. Every sealed field has a
// scalar kind: stashgen refuses a struct, slice or map outside an opaque
// struct, and an opaque struct seals as Bytes (one JSON document). Untyped
// names a field with no declared type and is not what generated code writes.
type Kind string

// The kinds. int8, int16 and int32 are Int32; int and int64 are Int64;
// uint8, uint16 and uint32 are UInt32; uint and uint64 are UInt64; []byte is
// Bytes. A type defined over one of these has its underlying kind.
const (
	Untyped Kind = ""
	Bool    Kind = "bool"
	Int32   Kind = "int32"
	Int64   Kind = "int64"
	UInt32  Kind = "uint32"
	UInt64  Kind = "uint64"
	Float32 Kind = "float32"
	Float64 Kind = "float64"
	String  Kind = "string"
	Bytes   Kind = "bytes"
)

// OpaqueField is the one field of an opaque declaration: the whole struct,
// sealed as one value under <context>/value. The struct crosses the binding
// as one JSON document — the engine seals a composite value as a tree of
// leaves, and an opaque struct is one column — so its field types are what
// JSON carries: scalars, []byte (base64), slices and maps of them.
const OpaqueField = "value"

type verb uint8

const (
	verbPassthrough verb = iota + 1
	verbOmit
	verbEncrypt
	verbEncryptIndex
	verbIndex
	verbEncryptInto
)

type field struct {
	name     string
	identity string
	kind     Kind
	verb     verb
	indexes  []encrypt.Index
	eqlType  string
}

// Declaration is a generated struct's declaration as data: its context and,
// for each field, what happens to it. Only generated code builds one, from
// the struct's stash tags, and only generated code reads it. A mistake in a
// declaration is found by stashgen; this type still refuses one, since no
// function in this package panics, and the error comes back from the first
// call through the codec.
type Declaration struct {
	context []string
	opaque  bool
	fields  []field
	err     error
}

// Declare starts a declaration with the struct's context: the `context=`
// tag, segments separated by '/'.
func Declare(context string) Declaration {
	segments, err := record.ParseContext(context)
	if err != nil {
		return Declaration{err: fmt.Errorf("gensupport: %v", err)}
	}
	return Declaration{context: segments}
}

// DeclareOpaque declares a struct sealed as one value: one field,
// [OpaqueField], encrypted as bytes.
func DeclareOpaque(context string) Declaration {
	d := Declare(context)
	d.opaque = true
	return d.add(field{name: OpaqueField, kind: Bytes, verb: verbEncrypt})
}

// Passthrough stores the field as it is. It stays on the host: see the
// record package.
func (d Declaration) Passthrough(name string) Declaration {
	return d.add(field{name: name, verb: verbPassthrough})
}

// Encrypt seals the field with no index.
func (d Declaration) Encrypt(name string, kind Kind) Declaration {
	return d.add(field{name: name, kind: kind, verb: verbEncrypt})
}

// EncryptIndex seals the field and derives each index beside it.
func (d Declaration) EncryptIndex(name string, kind Kind, indexes ...encrypt.Index) Declaration {
	return d.add(field{name: name, kind: kind, verb: verbEncryptIndex, indexes: indexes})
}

// Index derives the indexes alone, with no ciphertext.
func (d Declaration) Index(name string, kind Kind, indexes ...encrypt.Index) Declaration {
	return d.add(field{name: name, kind: kind, verb: verbIndex, indexes: indexes})
}

// EncryptInto seals the field into one EQL value of the named type.
func (d Declaration) EncryptInto(name string, kind Kind, eqlType string) Declaration {
	return d.add(field{name: name, kind: kind, verb: verbEncryptInto, eqlType: eqlType})
}

// Omit leaves the field out: it does not cross the binding and is not
// stored. The declaration lists it so a reader sees the choice.
func (d Declaration) Omit(name string) Declaration {
	return d.add(field{name: name, verb: verbOmit})
}

// Identity gives the named field a context part other than its name: a
// column that was renamed keeps the identity it was first written under,
// so data written before the change still decrypts.
func (d Declaration) Identity(name, identity string) Declaration {
	if d.err != nil {
		return d
	}
	for i := range d.fields {
		if d.fields[i].name == name {
			// A copy, so the receiver's fields are not changed under it.
			d.fields = slices.Clone(d.fields)
			d.fields[i].identity = identity
			return d
		}
	}
	d.err = fmt.Errorf("gensupport: Identity(%q): no such field", name)
	return d
}

func (d Declaration) add(f field) Declaration {
	if d.err != nil {
		return d
	}
	if d.opaque && f.name != OpaqueField {
		d.err = fmt.Errorf("gensupport: an opaque declaration has one field, not %q", f.name)
		return d
	}
	if f.name == "" {
		d.err = errors.New("gensupport: a field has no name")
		return d
	}
	for _, prior := range d.fields {
		if prior.name == f.name {
			d.err = fmt.Errorf("gensupport: field %q is declared twice", f.name)
			return d
		}
	}
	if (f.verb == verbEncryptIndex || f.verb == verbIndex) && len(f.indexes) == 0 {
		d.err = fmt.Errorf("gensupport: field %q: an indexed field names at least one index", f.name)
		return d
	}
	// Clip, so the append copies and never writes into an array that an
	// earlier Declaration shares.
	d.fields = append(slices.Clip(d.fields), f)
	return d
}

// Err is the declaration's mistake, if any.
func (d Declaration) Err() error { return d.err }

// sealed reports whether a field crosses the binding.
func (f field) sealed() bool {
	switch f.verb {
	case verbEncrypt, verbEncryptIndex, verbIndex, verbEncryptInto:
		return true
	}
	return false
}

// plan lowers the declaration to what the engine reads: the sealed fields,
// each with its label, outputs and type.
func (d Declaration) plan() (*record.Plan, error) {
	if d.err != nil {
		return nil, d.err
	}
	p := &record.Plan{Context: d.context}
	for _, f := range d.fields {
		if !f.sealed() {
			continue
		}
		rf := record.Field{Name: f.name, Identity: f.identity, Kind: record.Kind(f.kind)}
		switch f.verb {
		case verbEncryptInto:
			// The next build of the engine lists its EQL types through
			// se_targets; until then no declaration can seal into one.
			return nil, fmt.Errorf("gensupport: field %q: EQL types are not available yet", f.name)
		case verbEncrypt:
			rf.Outputs = []record.Output{record.Ciphertext}
		case verbEncryptIndex:
			rf.Outputs = []record.Output{record.Ciphertext}
		}
		for _, idx := range f.indexes {
			out := idx.Output()
			if _, ok := termOutputs[out]; !ok {
				return nil, fmt.Errorf("gensupport: field %q: the engine does not derive the %s index yet", f.name, idx)
			}
			rf.Outputs = append(rf.Outputs, out)
		}
		p.Fields = append(p.Fields, rf)
	}
	if len(p.Fields) == 0 {
		return nil, errors.New("gensupport: the declaration seals no field")
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("gensupport: %v", err)
	}
	return p, nil
}

// termOutputs are the indexes the engine derives.
var termOutputs = map[record.Output]struct{}{
	record.Equality: {}, record.Match: {}, record.Ore: {}, record.Ope: {},
}
