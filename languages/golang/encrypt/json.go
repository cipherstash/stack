package encrypt

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/cipherstash/stack/languages/golang/internal/record"
	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// JSONOpen opens the rows a read of a field that stores a JSON document
// returned (the guest's se_json_open), against the request that prepared
// the read: {"operation": "selector" | "subtree", "path", "wildcard_bound"}.
// rows holds one group per database row: for selector, the entry col ->
// selector returned, or none for SQL NULL; for subtree, the rows
// eql_v4.json_tree_subtree returned. Each entry is the
// public.eql_v4_json_entry JSON the database sent.
//
// The engine derives the selector or the read's key again from the request,
// the field's declaration and this cipher's keyset, and checks every row
// against it; the rows never say which path they are for. A row that is not
// one the read asked for is [ErrEncoding]; a wildcard read of an array
// longer than its bound is too, and so is a selector entry that does not
// open alone: a container with members, whose entry commits to children
// col -> does not return, or an altered entry, which the client cannot
// tell apart (code stack_encrypt::json_not_a_leaf). Read a container with a
// subtree read. What comes back is, per group, the JSON
// text of each value the read reached, in document order: plaintext, which
// the caller owns. One ZeroKMS request for every group. For generated code.
//
// Opening does not prove the database returned every row the read asked
// for, or rows of the database row the caller meant: see the EQL json_tree
// leakage reference.
func (cph *Cipher) JSONOpen(ctx context.Context, plan *record.Plan, field string, request vcvalue.Object, rows [][][]byte) ([][][]byte, error) {
	p, err := cph.queryPlan(plan, field)
	if err != nil {
		return nil, err
	}
	groups := make([]any, len(rows))
	for i, group := range rows {
		entries := make([]any, len(group))
		for j, entry := range group {
			entries[j] = entry
		}
		groups[i] = entries
	}
	encodedRows, err := vcffi.Marshal(groups)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	encodedRequest, err := vcffi.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	encodedPlan, err := vcffi.Marshal(p.Wire())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	opts, err := vcffi.Marshal(options(cph.keyset, ""))
	if err != nil {
		return nil, err
	}
	out, err := cph.client.callKMS(ctx, func(ctx context.Context, inst *instance) ([]byte, error) {
		return inst.call(ctx, inst.jsonOpen, buf(encodedRows), buf(encodedPlan), buf([]byte(field)), buf(encodedRequest), buf(opts))
	})
	if err != nil {
		return nil, err
	}
	// The output is plaintext: wiped once it is decoded into the caller's
	// slices.
	defer wipe(out)
	decoded, err := vcffi.Unmarshal(out)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInternal, err)
	}
	list, ok := decoded.([]any)
	if !ok || len(list) != len(rows) {
		return nil, fmt.Errorf("%w: se_json_open returned %T for %d groups", ErrInternal, decoded, len(rows))
	}
	opened := make([][][]byte, len(list))
	for i, item := range list {
		values, ok := item.([]any)
		if !ok {
			return nil, fmt.Errorf("%w: se_json_open group %d is %T", ErrInternal, i, item)
		}
		opened[i] = make([][]byte, len(values))
		for j, v := range values {
			text, ok := v.([]byte)
			if !ok {
				return nil, fmt.Errorf("%w: se_json_open value %d.%d is %T", ErrInternal, i, j, v)
			}
			opened[i][j] = text
		}
	}
	return opened, nil
}

// JSONSelector is a JSON path's selector: what `->`, `->>` and the path
// functions of a JSONSearch column take. It binds as SQL text; cast it,
// `col -> $1::text`, so PostgreSQL picks EQL's operator and not jsonb's.
// It is column-wide: the same path has the same selector in every row.
type JSONSelector string

// Value binds the selector as text. A zero JSONSelector (one never
// prepared) is refused rather than bound as ”, which matches no row.
func (s JSONSelector) Value() (driver.Value, error) {
	if s == "" {
		return nil, fmt.Errorf("%w: an empty JSONSelector: prepare one with the field's Selector", ErrEncoding)
	}
	return string(s), nil
}

// JSONToken is one node's token: what eql_v4.json_tree_children and
// eql_v4.json_tree_child_count take. It binds as SQL text. A token is a
// capability over the node's subtree in every row of the column: send it
// to the database for a query, and nowhere else. It prints and logs
// redacted.
type JSONToken string

// Value binds the token as text. A zero JSONToken is refused, as a zero
// JSONSelector is.
func (t JSONToken) Value() (driver.Value, error) {
	if t == "" {
		return nil, fmt.Errorf("%w: an empty JSONToken: derive one with the field's Children or ChildCount", ErrEncoding)
	}
	return string(t), nil
}

// redacted stands in for a token, a selector or a path in what the JSON
// read types print and log.
const redacted = "[redacted]"

// String hides the token: it is a capability, so it does not print.
func (t JSONToken) String() string {
	if t == "" {
		return "encrypt.JSONToken{}"
	}
	return "encrypt.JSONToken{" + redacted + "}"
}

// GoString is what %#v prints: [JSONToken.String].
func (t JSONToken) GoString() string { return t.String() }

// Format prints [JSONToken.String] for every verb fmt hands it.
func (t JSONToken) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, t.String()) }

// LogValue is what slog records: [redacted], never the token.
func (t JSONToken) LogValue() slog.Value { return slog.StringValue(redacted) }

// JSONTokens are a subtree read's tokens: what eql_v4.json_tree_subtree
// takes. They bind as a PostgreSQL text[] literal; cast the parameter,
// `$2::text[]`. Like a [JSONToken], each is a capability, and they print
// and log redacted.
type JSONTokens []string

// Value binds the tokens as a text[] literal. A token is base64, so it
// needs no escape inside the quotes. Empty JSONTokens (a zero JSONRead's)
// are refused, as a zero [JSONToken] is: bound as {}, they would read
// nothing from every row.
func (t JSONTokens) Value() (driver.Value, error) {
	if len(t) == 0 {
		return nil, fmt.Errorf("%w: empty JSONTokens: prepare a read with the field's Subtree", ErrEncoding)
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, token := range t {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('"')
		b.WriteString(token)
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String(), nil
}

// String counts the tokens and hides them: each is a capability.
func (t JSONTokens) String() string {
	return fmt.Sprintf("encrypt.JSONTokens{%d tokens: %s}", len(t), redacted)
}

// GoString is what %#v prints: [JSONTokens.String].
func (t JSONTokens) GoString() string { return t.String() }

// Format prints [JSONTokens.String] for every verb fmt hands it.
func (t JSONTokens) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, t.String()) }

// LogValue is what slog records: how many tokens, never the tokens.
func (t JSONTokens) LogValue() slog.Value {
	return slog.GroupValue(slog.Int("tokens", len(t)))
}

// JSONValue is one value a read reached, or none. Found is false for no
// value at the path (the row has no node there, or SQL NULL); a JSON null
// that is there is Found, with JSON "null". JSON is the value's JSON text:
// plaintext, which the caller owns. JSONValue prints its JSON in the
// clear: it has no String or LogValue method, so do not log one.
type JSONValue struct {
	Found bool
	JSON  json.RawMessage
}

// JSONReadOptions are a subtree read's options.
type JSONReadOptions struct {
	// WildcardBound is how many elements each [*] in the path is expanded
	// to; 0 is the engine's default, 64. A read of an array longer than the
	// bound fails rather than open to part of it ([ErrEncoding], with the
	// diagnostic code stack_encrypt::json_wildcard_truncated). Two wildcard
	// levels send bound² + bound + 1 tokens, and the engine refuses a read
	// past 8,192.
	WildcardBound uint32
}

// JSONRange is both bounds of a between at a path, each an ordering
// operand Q, low then high, inclusive.
type JSONRange[Q ~[]byte] struct {
	Low  Q
	High Q
}

// JSONSelection is a prepared `->` on a JSONSearch field: the selector
// to bind, and what opens the entries the database returns for it. It keeps
// the request it was prepared from (the field's declaration, the path and
// the cipher's keyset), so the entries open only as answers to it: the
// engine derives the selector again and refuses an entry that does not
// carry it. E is the column's entry type, eql.JSONEntry.
type JSONSelection[E ~[]byte] struct {
	cipher   *Cipher
	plan     *record.Plan
	field    string
	path     string
	selector JSONSelector
}

// NewJSONSelection is a selection prepared by [Cipher.QueryTerm]'s
// selector operator on field of the record type that declaration
// declares, at path. For generated code.
func NewJSONSelection[E ~[]byte](c *Cipher, declaration *record.Plan, field, path, selector string) JSONSelection[E] {
	return JSONSelection[E]{cipher: c, plan: declaration, field: field, path: path, selector: JSONSelector(selector)}
}

// Selector is the selector to bind: `col -> $1::text`.
func (s JSONSelection[E]) Selector() JSONSelector { return s.selector }

// String names the field and hides the path and the selector: a path's
// keys can be a customer's data.
func (s JSONSelection[E]) String() string {
	if s.cipher == nil {
		return "encrypt.JSONSelection{}"
	}
	return fmt.Sprintf("encrypt.JSONSelection{field: %q, path: %s, selector: %s}", s.field, redacted, redacted)
}

// GoString is what %#v prints: [JSONSelection.String].
func (s JSONSelection[E]) GoString() string { return s.String() }

// Format prints [JSONSelection.String] for every verb fmt hands it.
func (s JSONSelection[E]) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }

// LogValue is what slog records: the field, and [redacted] for the path
// and the selector.
func (s JSONSelection[E]) LogValue() slog.Value {
	if s.cipher == nil {
		return slog.GroupValue()
	}
	return slog.GroupValue(slog.String("field", s.field), slog.String("path", redacted), slog.String("selector", redacted))
}

// Open opens the entries `col -> selector` returned, one per database row,
// nil for a row where it returned SQL NULL, with one ZeroKMS request. Each
// opens to the scalar it holds (Found), or for the sealed root at "$" the
// whole document; a nil opens to no value. A container's entry is refused:
// read a container with a subtree read. An entry that is not the selector's
// is [ErrEncoding].
func (s JSONSelection[E]) Open(ctx context.Context, rows []*E) ([]JSONValue, error) {
	if s.cipher == nil {
		return nil, fmt.Errorf("%w: a zero JSONSelection has no request to open against", ErrEncoding)
	}
	groups := make([][][]byte, len(rows))
	entries := false
	for i, row := range rows {
		if row != nil {
			groups[i] = [][]byte{[]byte(*row)}
			entries = true
		}
	}
	// No row has an entry: nothing to open, and no key to ask for.
	if !entries {
		return make([]JSONValue, len(rows)), nil
	}
	opened, err := s.cipher.JSONOpen(ctx, s.plan, s.field, vcvalue.Object{{Key: "operation", Value: "selector"}, {Key: "path", Value: s.path}}, groups)
	if err != nil {
		return nil, err
	}
	out := make([]JSONValue, len(opened))
	for i, values := range opened {
		switch len(values) {
		case 0:
		case 1:
			out[i] = JSONValue{Found: true, JSON: values[0]}
		default:
			return nil, fmt.Errorf("%w: se_json_open opened %d values for row %d of a selector read", ErrInternal, len(values), i)
		}
	}
	return out, nil
}

// JSONRead is a prepared subtree read of a JSONSearch field: the tokens
// to bind, and what opens the rows eql_v4.json_tree_subtree returns for
// them. It keeps the request it was prepared from (the field's declaration,
// the path, the bound and the cipher's keyset); the engine derives the read
// again from it, and checks every row against it. E is the column's entry
// type, eql.JSONEntry.
type JSONRead[E ~[]byte] struct {
	cipher *Cipher
	plan   *record.Plan
	field  string
	// input is the subtree operator's input the tokens were derived from;
	// opening sends it back as the read's request, unchanged.
	input  vcvalue.Object
	tokens JSONTokens
}

// NewJSONRead is a read prepared by [Cipher.QueryTerm]'s subtree operator
// on field of the record type that declaration declares, from input, its
// {"path", "wildcard_bound"?} object. For generated code.
func NewJSONRead[E ~[]byte](c *Cipher, declaration *record.Plan, field string, input vcvalue.Object, tokens []string) JSONRead[E] {
	return JSONRead[E]{cipher: c, plan: declaration, field: field, input: input, tokens: JSONTokens(tokens)}
}

// Tokens are the tokens to bind:
// `eql_v4.json_tree_subtree(col, $1::text[], 64)`.
func (r JSONRead[E]) Tokens() JSONTokens { return r.tokens }

// String names the field and counts the tokens, and hides the path and
// the tokens: a path's keys can be a customer's data, and a token is a
// capability.
func (r JSONRead[E]) String() string {
	if r.cipher == nil {
		return "encrypt.JSONRead{}"
	}
	return fmt.Sprintf("encrypt.JSONRead{field: %q, path: %s, tokens: %d}", r.field, redacted, len(r.tokens))
}

// GoString is what %#v prints: [JSONRead.String].
func (r JSONRead[E]) GoString() string { return r.String() }

// Format prints [JSONRead.String] for every verb fmt hands it.
func (r JSONRead[E]) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, r.String()) }

// LogValue is what slog records: the field, [redacted] for the path, and
// how many tokens.
func (r JSONRead[E]) LogValue() slog.Value {
	if r.cipher == nil {
		return slog.GroupValue()
	}
	return slog.GroupValue(slog.String("field", r.field), slog.String("path", redacted), slog.Int("tokens", len(r.tokens)))
}

// Open opens the rows the read returned, one group per database row, with
// one ZeroKMS request: per row, the value at each concrete path the read
// named that the row has, in document order. A row with no node there
// opens to no value. Past its walk budget the database returns the sealed
// root instead, and the read's paths are evaluated over the whole document
// to the same values; only those values come back. A row that is not one
// the read asked for, or a wildcard read of an array longer than the bound,
// is [ErrEncoding].
//
// Opening checks each row against the read, not that the database
// returned every row it should have, nor that the rows came from the row
// the caller meant.
func (r JSONRead[E]) Open(ctx context.Context, rows [][]E) ([][]json.RawMessage, error) {
	if r.cipher == nil {
		return nil, fmt.Errorf("%w: a zero JSONRead has no request to open against", ErrEncoding)
	}
	groups := make([][][]byte, len(rows))
	for i, row := range rows {
		groups[i] = make([][]byte, len(row))
		for j, entry := range row {
			groups[i][j] = []byte(entry)
		}
	}
	request := append(vcvalue.Object{{Key: "operation", Value: "subtree"}}, r.input...)
	opened, err := r.cipher.JSONOpen(ctx, r.plan, r.field, request, groups)
	if err != nil {
		return nil, err
	}
	out := make([][]json.RawMessage, len(opened))
	for i, values := range opened {
		out[i] = make([]json.RawMessage, len(values))
		for j, v := range values {
			out[i][j] = v
		}
	}
	return out, nil
}

// OpenOne opens one database row's entries to the one value at the read's
// path: Found with its JSON, or not Found where the row has no node there.
// A read that reaches more than one value (a wildcard) is [ErrEncoding];
// open it with [JSONRead.Open].
func (r JSONRead[E]) OpenOne(ctx context.Context, entries []E) (JSONValue, error) {
	// The engine derives one token for a path that names one node, and for
	// a wildcard one per element below the bound plus a probe at it: two
	// or more at any bound of 1 or more. The generated Subtree never sends
	// a bound of 0 (WildcardBound 0 sends none, and the engine's default
	// is 64). So the count is the engine's own answer to whether the path
	// names one node: a quoted key that spells [*] is one member. A
	// wildcard is refused here, before anything is opened, not only for
	// the rows that happen to hold two values. A read prepared with a
	// bound of 0 expands a wildcard to the probe alone and passes this
	// check, but it reaches no value: a row with an element there is
	// refused as truncated, and any other opens to none.
	if r.cipher != nil && len(r.tokens) != 1 {
		return JSONValue{}, fmt.Errorf("%w: OpenOne reads one value, and this read's path has a wildcard; open it with Open", ErrEncoding)
	}
	opened, err := r.Open(ctx, [][]E{entries})
	if err != nil {
		return JSONValue{}, err
	}
	switch values := opened[0]; len(values) {
	case 0:
		return JSONValue{}, nil
	case 1:
		return JSONValue{Found: true, JSON: values[0]}, nil
	default:
		return JSONValue{}, fmt.Errorf("%w: the read reached %d values, not one; open it with Open", ErrEncoding, len(values))
	}
}

// DecodeJSON reads JSON text a read opened, a [JSONValue]'s JSON or one
// value of [JSONRead.Open], into a value of the caller's type T, with
// encoding/json's rules: a number reads into a declared integer field
// exactly, int64 and uint64 included, and into an interface (any) as a
// json.Number, never a float64 that rounds it. A member T does not declare
// is skipped, as encoding/json skips it. Text that is not one JSON value
// (empty, as an unfound JSONValue's is, or followed by more) is refused.
//
// An error wraps [ErrEncoding] and names T and the kind of JSON value that
// did not fit, never the value: what a read opened is plaintext.
func DecodeJSON[T any](text json.RawMessage) (T, error) {
	var out T
	dec := json.NewDecoder(bytes.NewReader(text))
	dec.UseNumber()
	if err := dec.Decode(&out); err != nil {
		var zero T
		return zero, decodeError(err, typeName[T]())
	}
	// One value, and nothing after it: Decode reads the first of a stream.
	switch _, err := dec.Token(); {
	case errors.Is(err, io.EOF):
		return out, nil
	case err == nil:
		var zero T
		return zero, fmt.Errorf("%w: the JSON text holds more than one value, and reads into one %s", ErrEncoding, typeName[T]())
	default:
		var zero T
		return zero, fmt.Errorf("%w: the text after its first JSON value is not JSON, and reads into no %s", ErrEncoding, typeName[T]())
	}
}

// typeName is T as Go source, an interface type included: %T of a T
// holding nil prints <nil>, and a *T names its element.
func typeName[T any]() string {
	return strings.TrimPrefix(fmt.Sprintf("%T", (*T)(nil)), "*")
}

// decodeError is encoding/json's decode error without the text it quotes:
// a SyntaxError names the character it met and an UnmarshalTypeError the
// number it could not store, both plaintext. It keeps the kind of JSON value
// and the Go type that did not fit.
func decodeError(err error, out string) error {
	var typeErr *json.UnmarshalTypeError
	switch {
	case errors.As(err, &typeErr):
		// Value is "number", "number 1.5", "string", "bool", "array" or
		// "object": its first word is the kind, the rest the value.
		kind, _, _ := strings.Cut(typeErr.Value, " ")
		return fmt.Errorf("%w: a JSON %s does not read into the Go type %s, in a %s", ErrEncoding, kind, typeErr.Type, out)
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return fmt.Errorf("%w: no JSON value to read into a %s (an unfound JSONValue holds none: check Found)", ErrEncoding, out)
	}
	var syntax *json.SyntaxError
	if errors.As(err, &syntax) {
		return fmt.Errorf("%w: the text is not JSON (at byte %d), and reads into no %s", ErrEncoding, syntax.Offset, out)
	}
	// An UnmarshalJSON or UnmarshalText of the caller's type failed, or
	// encoding/json refused the target (a non-pointer, say): its text may
	// hold the value, so only the type is named.
	return fmt.Errorf("%w: the JSON text does not read into a %s", ErrEncoding, out)
}
