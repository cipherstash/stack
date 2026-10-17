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
// its own.
func sealsAs(t stashgen.GoType) string {
	switch t.Basic {
	case "int":
		return "int64"
	case "uint", "uintptr":
		return "uint64"
	case "byte":
		return "uint8"
	case "rune":
		return "int32"
	}
	switch t.Kind {
	case stashgen.KindInt128:
		return "int128"
	case stashgen.KindUint128:
		return "uint128"
	}
	return t.Basic
}

// widths are the integer widths, signed and unsigned, for the widening
// rule of an EQL integer type (ADR-0002).
var widths = map[string]struct {
	signed bool
	bits   int
}{
	"int8": {true, 8}, "int16": {true, 16}, "int32": {true, 32}, "int64": {true, 64}, "int128": {true, 128},
	"uint8": {false, 8}, "uint16": {false, 16}, "uint32": {false, 32}, "uint64": {false, 64}, "uint128": {false, 128},
}

// fits reports whether every value of a Go integer that seals as from fits
// the integer kind to.
func fits(from, to string) bool {
	f, okFrom := widths[from]
	t, okTo := widths[to]
	if !okFrom || !okTo {
		return false
	}
	return (f.signed == t.signed && t.bits >= f.bits) || (!f.signed && t.signed && t.bits > f.bits)
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
			_, integerType := widths[t.seals]
			switch {
			case integerType && integer(f.GoType):
				// ADR-0002: any integer whose every value fits.
				if !fits(sealsAs(f.GoType), t.seals) {
					return &stashgen.FieldError{Type: d.Type, Field: f.GoName, Reason: fmt.Sprintf("%s seals %s, and not every %s fits it", f.EQLType, t.seals, f.GoType)}
				}
			case t.Plaintext != f.GoType.Kind:
				return &stashgen.FieldError{Type: d.Type, Field: f.GoName, Reason: fmt.Sprintf("%s seals a %s, and %s is %s", f.EQLType, t.Plaintext, f.GoType, f.GoType.Kind)}
			case t.seals != "" && sealsAs(f.GoType) != t.seals:
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
	if !integer(t) {
		return "", false
	}
	if declared(stashgen.IndexOre) {
		return stashgen.IndexOre, true
	}
	return stashgen.IndexOpe, declared(stashgen.IndexOpe)
}

// integer reports whether the type is an integer of any width.
func integer(t stashgen.GoType) bool {
	switch t.Kind {
	case stashgen.KindInt, stashgen.KindUint, stashgen.KindInt128, stashgen.KindUint128:
		return true
	}
	return false
}

// indexApplies mirrors dynamic::admits in stack-encrypt: equality over
// every kind vitaminc gives an equality domain (integers of every width,
// floats, decimals, dates, timestamps, text and bytes; a boolean has none),
// match over text alone, ORE and OPE over integers of every width, floats,
// text and bytes. Not over a boolean, whose order term would reveal which
// rows are true, and not yet over a decimal, date or timestamp, whose order
// terms wait for new cllw-ore and ore-rs releases (#1236). The JSON index is
// not in the engine yet.
func indexApplies(name stashgen.IndexName, t stashgen.GoType) error {
	switch name {
	case stashgen.IndexEquality:
		switch t.Kind {
		case stashgen.KindString, stashgen.KindBytes, stashgen.KindFloat, stashgen.KindDecimal, stashgen.KindDate, stashgen.KindTimestamp:
			return nil
		}
		if integer(t) {
			return nil
		}
	case stashgen.IndexMatch:
		if t.Kind == stashgen.KindString {
			return nil
		}
		return fmt.Errorf("match applies to a string, not to %s", t)
	case stashgen.IndexOre, stashgen.IndexOpe:
		switch t.Kind {
		case stashgen.KindString, stashgen.KindBytes, stashgen.KindFloat:
			return nil
		case stashgen.KindDecimal, stashgen.KindDate, stashgen.KindTimestamp:
			return fmt.Errorf("an order index on a decimal, date or timestamp waits for new cllw-ore and ore-rs releases (#1236)")
		}
		if integer(t) {
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
	case stashgen.KindString, stashgen.KindBool, stashgen.KindInt, stashgen.KindUint, stashgen.KindFloat, stashgen.KindBytes,
		stashgen.KindInt128, stashgen.KindUint128, stashgen.KindDecimal, stashgen.KindDate, stashgen.KindTimestamp:
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
