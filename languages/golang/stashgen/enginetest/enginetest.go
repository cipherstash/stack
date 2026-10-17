// Package enginetest is a static stand-in for the Rust engine in the
// generator's tests. It knows what the engine produces today: the EQL types
// in eqlTypes, each with the width of value it seals, the four indexes with
// the Go kinds each applies to, and the operators each answers.
//
// It is a test double, not a copy of the rules the SDK ships: the SDK's
// generator asks the embedded guest. When the engine learns a type or an
// index, update this file and the tests that read it.
package enginetest

import (
	"context"
	"fmt"
	"strings"

	"github.com/cipherstash/stack/languages/golang/stashgen"
)

// Static is the fake engine. The zero value is ready to use.
type Static struct{}

var _ stashgen.Engine = Static{}

// eqlTypes are the EQL types the engine produces today, with the width of
// value each seals ("" when the kind has no width), mirroring the producible
// rows of encrypt/eql's Types.
var eqlTypes = []struct {
	stashgen.EQLType
	seals string
}{
	{stashgen.EQLType{Name: "Integer", Plaintext: stashgen.KindInt, Producible: true}, "int32"},
	{stashgen.EQLType{Name: "Bigint", Plaintext: stashgen.KindInt, Producible: true}, "int64"},
	{stashgen.EQLType{Name: "Text", Plaintext: stashgen.KindString, Producible: true}, ""},
	{stashgen.EQLType{Name: "TextEq", Plaintext: stashgen.KindString, Indexes: []stashgen.IndexName{stashgen.IndexEquality}, Query: "TextEqQuery", Producible: true}, ""},
	{stashgen.EQLType{Name: "TextMatch", Plaintext: stashgen.KindString, Indexes: []stashgen.IndexName{stashgen.IndexMatch}, Query: "TextMatchQuery", Producible: true}, ""},
	{stashgen.EQLType{Name: "Boolean", Plaintext: stashgen.KindBool, Producible: true}, ""},
	{stashgen.EQLType{Name: "Real", Plaintext: stashgen.KindFloat, Producible: true}, "float32"},
	{stashgen.EQLType{Name: "Double", Plaintext: stashgen.KindFloat, Producible: true}, "float64"},
}

// EQLTypes returns the EQL types the engine produces today.
func (Static) EQLTypes(context.Context) ([]stashgen.EQLType, error) {
	out := make([]stashgen.EQLType, len(eqlTypes))
	for i, t := range eqlTypes {
		out[i] = t.EQLType
	}
	return out, nil
}

// sealsAs is the width the generated code seals a Go integer or float as:
// int8, int16 and int32 as int32, int and int64 as int64.
func sealsAs(t stashgen.GoType) string {
	switch t.Basic {
	case "int8", "int16", "int32":
		return "int32"
	case "int", "int64":
		return "int64"
	case "float32", "float64":
		return t.Basic
	}
	return ""
}

// Check applies the engine's rules as they stand today, then its table of
// the operators each sealed field answers.
func (e Static) Check(ctx context.Context, d stashgen.Declaration) (map[string][]stashgen.Operator, error) {
	if err := e.check(ctx, d); err != nil {
		return nil, err
	}
	return e.operators(ctx, d)
}

func (e Static) check(ctx context.Context, d stashgen.Declaration) error {
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
			var names []string
			found := -1
			for i, t := range eqlTypes {
				names = append(names, t.Name)
				if t.Name == f.EQLType {
					found = i
				}
			}
			if found < 0 {
				return &stashgen.FieldError{Type: d.Type, Field: f.GoName, Reason: fmt.Sprintf("the engine cannot produce the EQL type %s yet; it produces %s", f.EQLType, strings.Join(names, ", "))}
			}
			t := eqlTypes[found]
			if t.Plaintext != f.GoType.Kind {
				return &stashgen.FieldError{Type: d.Type, Field: f.GoName, Reason: fmt.Sprintf("%s seals a %s, and %s is %s", f.EQLType, t.Plaintext, f.GoType, f.GoType.Kind)}
			}
			if t.seals != "" && sealsAs(f.GoType) != t.seals {
				return &stashgen.FieldError{Type: d.Type, Field: f.GoName, Reason: fmt.Sprintf("%s seals %s, and %s seals as %s", f.EQLType, t.seals, f.GoType, sealsAs(f.GoType))}
			}
		}
		for _, idx := range f.Indexes {
			if len(idx.Options) > 0 {
				return &stashgen.FieldError{Type: d.Type, Field: f.GoName, Reason: fmt.Sprintf("index %s: a query term uses only the default index options, so this build refuses options", idx)}
			}
			if err := indexApplies(idx.Name, f.GoType); err != nil {
				return &stashgen.FieldError{Type: d.Type, Field: f.GoName, Reason: err.Error()}
			}
		}
	}
	return nil
}

// operatorNames are the operators, in the engine's order (OpSpec::ALL).
var operatorNames = []string{"eq", "lt", "lte", "gt", "gte", "between", "matches"}

// operators applies the engine's table as it stands today: OpSpec::answered_by
// for a field with indexes, and for an EQL type the operators of one value
// its indexes answer (matches included).
func (e Static) operators(ctx context.Context, d stashgen.Declaration) (map[string][]stashgen.Operator, error) {
	out := map[string][]stashgen.Operator{}
	if d.Opaque {
		return out, nil
	}
	eqlTypes, _ := e.EQLTypes(ctx)
	for _, f := range d.Fields {
		if !f.Sealed() {
			continue
		}
		indexes := make([]stashgen.IndexName, 0, len(f.Indexes))
		for _, idx := range f.Indexes {
			indexes = append(indexes, idx.Name)
		}
		target := false
		if f.Verb == stashgen.VerbEncryptInto {
			target = true
			indexes = nil
			for _, t := range eqlTypes {
				if t.Name == f.EQLType {
					indexes = t.Indexes
				}
			}
		}
		ops := []stashgen.Operator{}
		for _, name := range operatorNames {
			op := stashgen.Operator{Name: name, Probabilistic: name == "matches", Pair: name == "between"}
			// A twin is one value, so an EQL type answers no range; it
			// answers matches through its match index, whose options the
			// engine holds for every EQL type with one.
			if target && op.Pair {
				continue
			}
			if index, ok := answeredBy(name, f.GoType, indexes); ok {
				op.Index = index
				ops = append(ops, op)
			}
		}
		out[f.Name] = ops
	}
	return out, nil
}

// answeredBy mirrors OpSpec::answered_by in stack-encrypt: eq through an
// equality index, matches through a match index, and the orderings through
// ORE, or OPE when there is no ORE, over an integer alone; each only where
// the index applies to the type.
func answeredBy(operator string, t stashgen.GoType, indexes []stashgen.IndexName) (stashgen.IndexName, bool) {
	declared := func(want stashgen.IndexName) bool {
		for _, idx := range indexes {
			if idx == want {
				return indexApplies(want, t) == nil
			}
		}
		return false
	}
	switch operator {
	case "eq":
		return stashgen.IndexEquality, declared(stashgen.IndexEquality)
	case "matches":
		return stashgen.IndexMatch, declared(stashgen.IndexMatch)
	}
	if t.Kind != stashgen.KindInt && t.Kind != stashgen.KindUint {
		return "", false
	}
	if declared(stashgen.IndexOre) {
		return stashgen.IndexOre, true
	}
	return stashgen.IndexOpe, declared(stashgen.IndexOpe)
}

// indexApplies mirrors dynamic::admits in stack-encrypt: equality over
// integers, floats, text and bytes (the kinds vitaminc gives an equality
// domain; a boolean has none), match over text alone, ORE and OPE over
// every scalar but a boolean, whose order term would reveal which rows are
// true. The JSON index is not in the engine yet.
func indexApplies(name stashgen.IndexName, t stashgen.GoType) error {
	switch name {
	case stashgen.IndexEquality:
		switch t.Kind {
		case stashgen.KindString, stashgen.KindBytes, stashgen.KindInt, stashgen.KindUint, stashgen.KindFloat:
			return nil
		}
	case stashgen.IndexMatch:
		if t.Kind == stashgen.KindString {
			return nil
		}
		return fmt.Errorf("match applies to a string, not to %s", t)
	case stashgen.IndexOre, stashgen.IndexOpe:
		if t.Kind.Scalar() && t.Kind != stashgen.KindBool {
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
