// Package fakeengine is a static stand-in for the Rust engine in the
// generator's tests. It knows what the engine produces today: the EQL type
// TextEq, and the four indexes with the Go kinds each applies to.
//
// It is a test double, not a copy of the rules the SDK ships: the SDK's
// generator asks the embedded guest. When the engine learns a type or an
// index, update this file and the tests that read it.
package fakeengine

import (
	"context"
	"fmt"

	"github.com/cipherstash/stack/languages/golang/stashgen"
)

// Engine is the static fake. The zero value is ready to use.
type Engine struct{}

var _ stashgen.Engine = Engine{}

// EQLTypes returns TextEq, the one EQL type the engine produces today.
func (Engine) EQLTypes(context.Context) ([]stashgen.EQLType, error) {
	return []stashgen.EQLType{
		{Name: "TextEq", Plaintext: stashgen.KindString, Indexes: []stashgen.IndexName{stashgen.IndexEquality}, Query: "TextEqQuery"},
	}, nil
}

// Check applies the engine's rules as they stand today.
func (e Engine) Check(ctx context.Context, d stashgen.Declaration) error {
	eqlTypes, _ := e.EQLTypes(ctx)
	for _, f := range d.Fields {
		if f.Verb == stashgen.VerbOmit {
			continue
		}
		if d.Opaque || f.Sealed() {
			if !sealable(f.GoType) {
				return &stashgen.FieldError{Type: d.Type, Field: f.GoName, Reason: fmt.Sprintf("the engine cannot seal a value of type %s", f.GoType)}
			}
		}
		if f.Verb == stashgen.VerbEncryptInto {
			var found *stashgen.EQLType
			for i := range eqlTypes {
				if eqlTypes[i].Name == f.EQLType {
					found = &eqlTypes[i]
				}
			}
			if found == nil {
				return &stashgen.FieldError{Type: d.Type, Field: f.GoName, Reason: fmt.Sprintf("the engine cannot produce the EQL type %s yet; it produces TextEq", f.EQLType)}
			}
			if found.Plaintext != f.GoType.Kind {
				return &stashgen.FieldError{Type: d.Type, Field: f.GoName, Reason: fmt.Sprintf("%s seals a %s, and %s is %s", f.EQLType, found.Plaintext, f.GoType, f.GoType.Kind)}
			}
		}
		for _, idx := range f.Indexes {
			if len(idx.Options) > 0 {
				return &stashgen.FieldError{Type: d.Type, Field: f.GoName, Reason: fmt.Sprintf("index %s: the engine cannot carry index options yet", idx)}
			}
			if err := indexApplies(idx.Name, f.GoType); err != nil {
				return &stashgen.FieldError{Type: d.Type, Field: f.GoName, Reason: err.Error()}
			}
		}
	}
	return nil
}

// indexApplies mirrors the Index<S> impls in stack-encrypt's target/index.rs:
// Equality for every PRF value, Match for text, Ore and Ope for what cllw-ore
// implements (text, bytes, bool, integers and floats). The JSON index is not
// in the engine yet.
func indexApplies(name stashgen.IndexName, t stashgen.GoType) error {
	switch name {
	case stashgen.IndexEquality:
		if t.Kind.Scalar() {
			return nil
		}
	case stashgen.IndexMatch:
		if t.Kind == stashgen.KindString {
			return nil
		}
		return fmt.Errorf("match applies to a string, not to %s", t)
	case stashgen.IndexOre, stashgen.IndexOpe:
		if t.Kind.Scalar() {
			return nil
		}
	case stashgen.IndexJSON:
		return fmt.Errorf("the engine cannot derive the json index yet")
	}
	return fmt.Errorf("%s does not apply to %s", name, t)
}

// sealable reports whether the engine can seal a value of the type: a scalar,
// or a slice, map, pointer or all-exported struct of sealable types.
func sealable(t stashgen.GoType) bool {
	switch t.Kind {
	case stashgen.KindString, stashgen.KindBool, stashgen.KindInt, stashgen.KindUint, stashgen.KindFloat, stashgen.KindBytes:
		return true
	case stashgen.KindSlice, stashgen.KindPointer:
		return t.Elem != nil && sealable(*t.Elem)
	case stashgen.KindMap:
		return t.Elem != nil && sealable(*t.Elem)
	case stashgen.KindStruct:
		for _, f := range t.Fields {
			if !sealable(f) {
				return false
			}
		}
		return true
	}
	return false
}
