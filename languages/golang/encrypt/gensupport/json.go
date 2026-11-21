package gensupport

import (
	"bytes"
	"context"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/internal/record"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// The operators of a field stored as a JSONSearch document, for the
// generated methods of its Fields entry. Each sends the operator's named
// inputs, JSON values as their JSON text ([JSONText]), and checks the
// engine answered in the encoding and with the number of parts the method
// returns.

// JSONText is a Go value as the JSON text the engine reads: a
// json.RawMessage is JSON text already and crosses as it is (the engine
// parses it, and refuses one that is not JSON); any other value is
// marshalled with encoding/json, explicitly and once, so a declared integer
// field is written as its exact digits and a float64 as the shortest text
// that reads back to it. A plain []byte is refused: encoding/json would
// write it as a base64 string, which is never what JSON text in a []byte
// means; convert it, json.RawMessage(b).
//
// The []byte rule is by kind: a value of a type whose kind is a slice of a
// byte-kind element, or a pointer to one, is refused unless the value's
// own type writes itself (json.Marshaler or encoding.TextMarshaler). So a
// []B is refused even when B or *B has MarshalJSON, though encoding/json
// would then write an array: refusing it is safe, and telling the two
// apart would mean asking for the element's methods.
//
// An error wraps encrypt.ErrEncoding and names a Go type, never the value:
// encoding/json's own text quotes a NaN, and a MarshalJSON's error may hold
// anything.
func JSONText(v any) ([]byte, error) {
	if raw, ok := v.(json.RawMessage); ok {
		return raw, nil
	}
	if t := throughPointer(v); writesItself(v) == "" && t != nil && t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Uint8 {
		// A []byte, or a type defined over one (type Doc []byte, or
		// json.RawMessage redefined, which drops its MarshalJSON), or a
		// pointer to either, which encoding/json writes as what it
		// points to.
		return nil, fmt.Errorf("%w: a %T is not JSON text to encoding/json, which writes it as a base64 string; convert JSON text to json.RawMessage", encrypt.ErrEncoding, v)
	}
	text, err := json.Marshal(v)
	if err == nil {
		return text, nil
	}
	var typeErr *json.UnsupportedTypeError
	var valueErr *json.UnsupportedValueError
	var marshalerErr *json.MarshalerError
	switch {
	case errors.As(err, &typeErr):
		return nil, fmt.Errorf("%w: encoding/json cannot write a %s, in a %T", encrypt.ErrEncoding, typeErr.Type, v)
	case errors.As(err, &valueErr):
		return nil, fmt.Errorf("%w: a %T holds a value encoding/json cannot write: a NaN, an infinity, or a cycle", encrypt.ErrEncoding, v)
	case errors.As(err, &marshalerErr):
		return nil, fmt.Errorf("%w: the MarshalJSON or MarshalText of %s failed, in a %T", encrypt.ErrEncoding, marshalerErr.Type, v)
	}
	return nil, fmt.Errorf("%w: a %T does not write as JSON", encrypt.ErrEncoding, v)
}

// isGoString reports whether v is a Go string, a type defined over one, or
// a pointer to either, that encoding/json writes as one JSON string: one
// with no MarshalJSON or MarshalText of its own. A containment needle and
// Match's vars refuse it, since JSON text in a Go string is the likely
// mistake.
func isGoString(v any) bool {
	t := throughPointer(v)
	return t != nil && t.Kind() == reflect.String && writesItself(v) == ""
}

// writesItself names the encoding/json interface v implements to write
// itself, or "" for none.
func writesItself(v any) string {
	switch v.(type) {
	case json.Marshaler:
		return "json.Marshaler"
	case encoding.TextMarshaler:
		return "encoding.TextMarshaler"
	}
	return ""
}

// throughPointer is v's dynamic type, or what it points to when it is a
// pointer, or nil for nil: the one place the JSON operands look at a type
// by kind, since a type switch cannot name every type defined over []byte
// or string. encoding/json writes a non-nil pointer as the value it points
// to, so a *string is one JSON string as a string is. Only the type is
// read, never the value.
func throughPointer(v any) reflect.Type {
	t := reflect.TypeOf(v)
	if t != nil && t.Kind() == reflect.Pointer {
		return t.Elem()
	}
	return t
}

// GetDocument reads one opened document field into the Go type T the struct
// declares, with [encrypt.DecodeJSON]: the explicit encoding/json read that
// mirrors the write [JSONText] made. A json.RawMessage field is read with
// [Get] instead, as the text it is.
func GetDocument[T any](vals Values, name string) (T, error) {
	var out T
	v, ok := vals[name]
	if !ok {
		return out, fmt.Errorf("gensupport: the opened value has no field %q", name)
	}
	text, ok := v.([]byte)
	if !ok {
		return out, fmt.Errorf("gensupport: field %q: %w: the document opened as %T, not its JSON text", name, encrypt.ErrEncoding, v)
	}
	out, err := encrypt.DecodeJSON[T](text)
	if err != nil {
		return out, fmt.Errorf("gensupport: field %q: %w", name, err)
	}
	return out, nil
}

// GetDocumentPtr reads one opened document field declared over a pointer
// (null=sql): nil for a field that opened as nil, the SQL NULL it was
// stored as, else a pointer to the value as [GetDocument] reads it.
func GetDocumentPtr[T any](vals Values, name string) (*T, error) {
	v, ok := vals[name]
	if !ok {
		return nil, fmt.Errorf("gensupport: the opened value has no field %q", name)
	}
	if v == nil {
		return nil, nil
	}
	out, err := GetDocument[T](vals, name)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// jsonTerm derives one JSON operator's term on the field: an exact term in
// encoding, of parts byte strings ("eql") or texts ("text"); parts 0 takes
// any number of texts ("text_array").
func (f Field[T]) jsonTerm(ctx context.Context, c *encrypt.Cipher, operator, encoding string, parts int, input vcvalue.Object) (encrypt.QueryTerm, error) {
	if f.err != nil {
		return encrypt.QueryTerm{}, f.err
	}
	if c == nil {
		return encrypt.QueryTerm{}, fmt.Errorf("%w: gensupport: %s: a query needs a cipher", encrypt.ErrEncoding, f.name)
	}
	term, err := c.QueryTerm(ctx, f.plan, f.name, operator, input)
	if err != nil {
		return encrypt.QueryTerm{}, err
	}
	got := len(term.Terms)
	if encoding == "text" || encoding == "text_array" {
		got = len(term.Text)
	}
	if term.Encoding != encoding || term.Fidelity != record.Exact || (parts != 0 && got != parts) {
		return encrypt.QueryTerm{}, fmt.Errorf("gensupport: %s: %s came back as a %s %s term of %d parts, not an exact %s one of %d", f.name, operator, term.Fidelity, term.Encoding, got, encoding, parts)
	}
	return term, nil
}

// jsonOperand is one JSON operand as its text ([JSONText]), with the
// field's name on an error.
func (f Field[T]) jsonOperand(v any) ([]byte, error) {
	text, err := JSONText(v)
	if err != nil {
		return nil, fmt.Errorf("gensupport: %s: %w", f.name, err)
	}
	return text, nil
}

// JSONQuery derives a containment operator's query on a JSON field
// (contains, contained_by): the needle's projection, Q. The needle is any
// value [JSONText] writes, other than a string or a pointer to one, which
// is refused: one JSON string is never what a containment needle means,
// and JSON text in a Go string is the likely mistake. A needle that writes
// JSON null (nil, or a nil pointer, map or slice) is refused too: it
// matches only a document that is itself null. Contains on a field of
// [NewDocumentField] refuses a needle of the field's own type, T or *T:
// its zero-valued fields would narrow the query.
func JSONQuery[Q ~[]byte, T any](ctx context.Context, f Field[T], c *encrypt.Cipher, operator string, needle any) (Q, error) {
	// A Go string is one JSON string, and a document of members never
	// contains one: it is almost always JSON text meant as the needle.
	if isGoString(needle) {
		return nil, fmt.Errorf("%w: gensupport: %s: a %T needle is one JSON string, not JSON text; pass JSON text as json.RawMessage, or a map or struct", encrypt.ErrEncoding, f.name, needle)
	}
	if needle == nil {
		return nil, fmt.Errorf("%w: gensupport: %s: a nil needle is JSON null, which only a null document contains; pass a map, a struct or JSON text", encrypt.ErrEncoding, f.name)
	}
	if f.holdsStruct && operator == "contains" {
		switch needle.(type) {
		case T, *T:
			return nil, fmt.Errorf("%w: gensupport: %s: Contains takes a needle, not the field's own type %T: encoding/json writes each of its struct fields that has no omitempty, and a zero one narrows the query to documents holding that zero. Use a map, or a needle type whose fields are pointers or carry omitempty", encrypt.ErrEncoding, f.name, needle)
		}
	}
	text, err := f.jsonOperand(needle)
	if err != nil {
		return nil, err
	}
	// A nil pointer, map or slice: the text says so without a look at the
	// value.
	if bytes.Equal(text, []byte("null")) {
		return nil, fmt.Errorf("%w: gensupport: %s: a %T needle that writes JSON null (a nil one) matches only a null document; pass a map, a struct or JSON text", encrypt.ErrEncoding, f.name, needle)
	}
	term, err := f.jsonTerm(ctx, c, operator, "eql", 1, vcvalue.Object{{Key: "json", Value: text}})
	if err != nil {
		return nil, err
	}
	return Q(term.Terms[0]), nil
}

// JSONQueryAt derives an operator at a path on a JSON field (eq_at, lt_at,
// lte_at, gt_at, gte_at): Q is the needle for eq_at and the leaf operand
// for the orderings. v is any value [JSONText] writes: a string, a number,
// a bool, nil for JSON null, or a json.RawMessage.
func JSONQueryAt[Q ~[]byte, T any](ctx context.Context, f Field[T], c *encrypt.Cipher, operator, path string, v any) (Q, error) {
	text, err := f.jsonOperand(v)
	if err != nil {
		return nil, err
	}
	term, err := f.jsonTerm(ctx, c, operator, "eql", 1, vcvalue.Object{{Key: "path", Value: path}, {Key: "json", Value: text}})
	if err != nil {
		return nil, err
	}
	return Q(term.Terms[0]), nil
}

// JSONBetweenAt derives between_at on a JSON field: the two leaf operands,
// low then high, inclusive, each any value [JSONText] writes.
func JSONBetweenAt[Q ~[]byte, T any](ctx context.Context, f Field[T], c *encrypt.Cipher, path string, lo, hi any) (encrypt.JSONRange[Q], error) {
	low, err := f.jsonOperand(lo)
	if err != nil {
		return encrypt.JSONRange[Q]{}, err
	}
	high, err := f.jsonOperand(hi)
	if err != nil {
		return encrypt.JSONRange[Q]{}, err
	}
	term, err := f.jsonTerm(ctx, c, "between_at", "eql", 2, vcvalue.Object{{Key: "path", Value: path}, {Key: "low", Value: low}, {Key: "high", Value: high}})
	if err != nil {
		return encrypt.JSONRange[Q]{}, err
	}
	return encrypt.JSONRange[Q]{Low: Q(term.Terms[0]), High: Q(term.Terms[1])}, nil
}

// JSONElementMatch derives element_match on a JSON field: the one operand
// eql_v4.json_tree_element_match takes, which is true of a row where some
// element of the array at path passes every predicate. path is an array
// through its last wildcard ($.contacts[*]) that the field orders members
// beneath ([record.TargetOptions.ElementArrays]).
//
// Refused before the engine is asked, each wrapping the sentinel the
// engine's own refusal would: no predicates, a zero ElementPredicate, or a
// predicate on the zero Path, which names no member
// ([encrypt.ErrEncoding]); a member with a wildcard ([encrypt.ErrEncoding]);
// a member whose full path the field does not order ([encrypt.ErrTerm]),
// naming the member, the array and the members it orders. A member read
// from the generated Paths is one the field orders; a member named at run
// time, through the array accessor's Member, may not be. A value is
// written as [JSONText] writes it. What the engine refuses past these, a
// value that is not a number or a string say, is its [encrypt.Diagnostic].
// opts.WildcardBound 0 sends no bound, and the engine's default, 64,
// applies.
func JSONElementMatch[Q ~[]byte, T, E any](ctx context.Context, f Field[T], c *encrypt.Cipher, path string, opts encrypt.JSONReadOptions, predicates []encrypt.ElementPredicate[E]) (Q, error) {
	if f.err != nil {
		return nil, f.err
	}
	if len(predicates) == 0 {
		return nil, fmt.Errorf("%w: gensupport: %s: Match at %s needs at least one predicate: with none it is true of every row with an element", encrypt.ErrEncoding, f.name, path)
	}
	members := f.elementMembers(path)
	list := make([]any, len(predicates))
	for i, p := range predicates {
		member, op, values := p.Member(), p.Op(), p.Values()
		if op == "" {
			return nil, fmt.Errorf("%w: gensupport: %s: Match at %s: predicate %d is a zero ElementPredicate; make one with encrypt.AtPath and a path from the generated Paths, or with the array's Member", encrypt.ErrEncoding, f.name, path, i)
		}
		if member == "" {
			return nil, fmt.Errorf("%w: gensupport: %s: Match at %s: predicate %d names no member, as a zero encrypt.Path does; read the path from the generated Paths (%s)", encrypt.ErrEncoding, f.name, path, i, orderedMembers(members))
		}
		if strings.Contains(member, "[*]") {
			return nil, fmt.Errorf("%w: gensupport: %s: Match at %s: the member %q has a wildcard; a member names one field of each element (%s)", encrypt.ErrEncoding, f.name, path, member, orderedMembers(members))
		}
		if !slices.Contains(members, member) {
			return nil, fmt.Errorf("%w: gensupport: %s: Match at %s: the member %q is not ordered, so no element carries a term to compare (%s); order its full path in the field's tag, ordered=", encrypt.ErrTerm, f.name, path, member, orderedMembers(members))
		}
		entry := vcvalue.Object{{Key: "member", Value: member}, {Key: "op", Value: op}}
		// Each comparison gives its op its values: between the low and
		// the high, every other op one.
		keys := []string{"json"}
		if op == "between" {
			keys = []string{"low", "high"}
		}
		for j, key := range keys {
			text, err := f.jsonOperand(values[j])
			if err != nil {
				return nil, err
			}
			entry = append(entry, vcvalue.Field{Key: key, Value: text})
		}
		list[i] = entry
	}
	input := vcvalue.Object{{Key: "path", Value: path}}
	if opts.WildcardBound != 0 {
		input = append(input, vcvalue.Field{Key: "wildcard_bound", Value: opts.WildcardBound})
	}
	input = append(input, vcvalue.Field{Key: "predicates", Value: list})
	term, err := f.jsonTerm(ctx, c, "element_match", "eql", 1, input)
	if err != nil {
		return nil, err
	}
	return Q(term.Terms[0]), nil
}

// JSONMatch derives match on a JSON field: the one operand
// eql_v4.json_tree_match and `@@` take, a jsonpath predicate compiled into
// a boolean tree of the other operators' operands. The predicate crosses
// as it is: the engine parses and compiles it, and nothing here reads it.
//
// vars are the predicate's variables ($name), the jsonb that
// jsonb_path_match takes third: any value [JSONText] writes as a JSON
// object, such as a map, a struct or a json.RawMessage of one. They answer
// as the same Go value bound as jsonb_path_match's vars through pgx or
// database/sql answers over plaintext:
//
//   - A nil value (nil, or a nil map, slice, pointer or json.RawMessage)
//     is SQL NULL there, and jsonb_path_match is NULL for every row. Match
//     returns an empty operand, which binds as NULL, so `@@` and
//     json_tree_match are NULL for every row too. The predicate is still
//     compiled, so text the grammar does not read is still refused; a
//     variable it names is not, as plaintext does not look for one.
//   - A value that writes the JSON null (a json.RawMessage of null, or a
//     pointer to a nil map) is refused as not an object, as plaintext
//     refuses "vars" that are not an object.
//   - Any other json.RawMessage crosses as it is, so an empty or
//     whitespace-only one is refused by the engine as not JSON, as "{" is.
//
// A Go string or a non-nil pointer to one is refused, as [JSONQuery]
// refuses a needle: it writes one JSON string, and JSON text in a Go string
// is the likely mistake.
//
// What the engine refuses (text it does not read, a construct the index
// cannot answer, a variable vars do not hold, vars that are not an
// object, an ordering at a path the field does not order) is its
// [encrypt.Diagnostic]. opts.WildcardBound 0 sends no bound, and the
// engine's default, 64, applies.
func JSONMatch[Q ~[]byte, T any](ctx context.Context, f Field[T], c *encrypt.Cipher, predicate string, vars any, opts encrypt.JSONReadOptions) (Q, error) {
	if f.err != nil {
		return nil, f.err
	}
	input := vcvalue.Object{{Key: "predicate", Value: predicate}}
	if opts.WildcardBound != 0 {
		input = append(input, vcvalue.Field{Key: "wildcard_bound", Value: opts.WildcardBound})
	}
	if isNilValue(vars) {
		// SQL NULL vars: compile with none for what plaintext refuses
		// before it reads vars, and answer with the empty operand.
		if _, err := f.jsonTerm(ctx, c, "match", "eql", 1, input); err != nil && !isUnknownVariable(err) {
			return nil, err
		}
		return nil, nil
	}
	if isGoString(vars) {
		return nil, fmt.Errorf("%w: gensupport: %s: Match takes vars as a JSON object, and a %T is one JSON string; pass JSON text as json.RawMessage, or a map or struct", encrypt.ErrEncoding, f.name, vars)
	}
	text, err := f.jsonOperand(vars)
	if err != nil {
		return nil, err
	}
	input = append(input, vcvalue.Field{Key: "vars", Value: text})
	term, err := f.jsonTerm(ctx, c, "match", "eql", 1, input)
	if err != nil {
		return nil, err
	}
	return Q(term.Terms[0]), nil
}

// isNilValue reports whether v is nil, or a nil map, slice, pointer or
// interface value: what database/sql and pgx bind as SQL NULL.
func isNilValue(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Map, reflect.Slice, reflect.Pointer, reflect.Interface:
		return rv.IsNil()
	}
	return false
}

// isUnknownVariable reports whether err is the engine's refusal of a
// $name that vars do not hold.
func isUnknownVariable(err error) bool {
	var d *encrypt.Diagnostic
	return errors.As(err, &d) && d.Reason() == "json_predicate_unknown_variable"
}

// orderedMembers says which members of an array's elements the field
// orders.
func orderedMembers(members []string) string {
	if len(members) == 0 {
		return "the field orders no member beneath this array"
	}
	return "the field orders " + strings.Join(members, ", ") + " beneath this array"
}

// elementMembers are the members the field orders beneath the array at
// path, as its declaration's ordered paths give them.
func (f Field[T]) elementMembers(path string) []string {
	if f.plan == nil {
		return nil
	}
	if pf := f.plan.Field(f.name); pf != nil {
		for _, a := range pf.TargetOptions.ElementArrays() {
			if a.Path == path {
				return a.Members
			}
		}
	}
	return nil
}

// JSONSelect prepares `->` at a path on a JSON field: the selector to
// bind, and what opens the entries it returns. E is the field's entry type.
func JSONSelect[E ~[]byte, T any](ctx context.Context, f Field[T], c *encrypt.Cipher, path string) (encrypt.JSONSelection[E], error) {
	term, err := f.jsonTerm(ctx, c, "selector", "text", 1, vcvalue.Object{{Key: "path", Value: path}})
	if err != nil {
		return encrypt.JSONSelection[E]{}, err
	}
	return encrypt.NewJSONSelection[E](c, f.plan, f.name, path, term.Text[0]), nil
}

// JSONSubtree prepares a subtree read at a path on a JSON field: the
// tokens to bind, and what opens the rows they return. The request is
// built once, here, and the read keeps it: opening sends the engine the
// same request the tokens were derived from.
func JSONSubtree[E ~[]byte, T any](ctx context.Context, f Field[T], c *encrypt.Cipher, path string, opts encrypt.JSONReadOptions) (encrypt.JSONRead[E], error) {
	input := vcvalue.Object{{Key: "path", Value: path}}
	if opts.WildcardBound != 0 {
		input = append(input, vcvalue.Field{Key: "wildcard_bound", Value: opts.WildcardBound})
	}
	term, err := f.jsonTerm(ctx, c, "subtree", "text_array", 0, input)
	if err != nil {
		return encrypt.JSONRead[E]{}, err
	}
	return encrypt.NewJSONRead[E](c, f.plan, f.name, input, term.Text), nil
}

// JSONNodeToken derives the token of the node at a path with no wildcard
// (children, child_count), which json_tree_children and
// json_tree_child_count take.
func JSONNodeToken[T any](ctx context.Context, f Field[T], c *encrypt.Cipher, operator, path string) (encrypt.JSONToken, error) {
	term, err := f.jsonTerm(ctx, c, operator, "text", 1, vcvalue.Object{{Key: "path", Value: path}})
	if err != nil {
		return "", err
	}
	return encrypt.JSONToken(term.Text[0]), nil
}
