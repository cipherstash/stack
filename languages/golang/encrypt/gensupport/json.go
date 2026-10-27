package gensupport

import (
	"bytes"
	"context"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

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
	if t := throughPointer(needle); t != nil && t.Kind() == reflect.String && writesItself(needle) == "" {
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
