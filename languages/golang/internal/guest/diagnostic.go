package guest

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
	"github.com/tetratelabs/wazero/api"
)

// Diagnostic is the full error behind a guest's status: the error the Rust
// code raised, as the guest's se_last_error hands it over. Every failure a
// guest reports comes back as one, wrapping the sentinel its status maps
// to, so a caller checks the kind with errors.Is and reads the detail with
// errors.As:
//
//	if errors.Is(err, encrypt.ErrForeignKeyset) { ... }
//	var d *encrypt.Diagnostic
//	if errors.As(err, &d) { log.Print(d.Code, d.Help) }
//
// What it may carry is the rule written on stack-profile's ErrorPayload:
// keyset ids and names, field names, counts, index kinds, ZeroKMS request
// kinds and HTTP statuses, workspace ids, CRNs and regions, profile file
// paths. Never plaintext, key material, tokens, ciphertext or term bytes,
// or a context's values: a stored context's length and parts at most.
//
// A guest built before se_last_error, or one whose error does not decode,
// returns the bare sentinel instead: the detail is never allowed to hide
// the failure.
type Diagnostic struct {
	// Code is the error's code, "crate::name": "stack_encrypt::foreign_keyset",
	// "stack_kms::keyset_not_found", "stack_profile::not_found". Stable, so
	// a caller may branch on it; the sentinel Unwrap returns is the coarser
	// kind.
	Code string
	// Message is the Rust error's one-line message. Error returns it after
	// the sentinel's text.
	Message string
	// Help says what to do about it, where the error knows.
	Help string
	// URL points at documentation for the error, where it has one.
	URL string
	// Severity is "error", "warning" or "advice".
	Severity string
	// Fields are the error's structured fields, by name: a foreign
	// keyset's "expected" and "found", a refused plan's "field" and
	// "reason", a ZeroKMS failure's "request_kind". Each value is a string,
	// bool, uint64, int64, float64, nil, []any or map[string]any.
	Fields map[string]any
	// Causes are the errors behind this one, outermost first.
	Causes []Cause

	kind error
}

// Cause is one error in a Diagnostic's cause chain. A cause from one of the
// stack crates has a Code; one from another library has none, and its
// Message is a description the guest vouches for, never that library's own
// text.
type Cause struct {
	Code    string
	Message string
}

// Error returns the sentinel's text, then the Rust error's message:
// "cipherstash: auth transport failed: Server error: 403", so a log line
// still says which package and which kind of failure it was.
func (d *Diagnostic) Error() string {
	if d.kind == nil {
		return d.Message
	}
	return d.kind.Error() + ": " + d.Message
}

// Unwrap returns the sentinel the guest's status maps to, so errors.Is
// matches the same kinds it matched before the detail existed.
func (d *Diagnostic) Unwrap() error { return d.kind }

// The code a foreign-keyset refusal carries, the one error whose keysets
// have accessors.
const codeForeignKeyset = "stack_encrypt::foreign_keyset"

// ExpectedKeyset is the keyset a foreign-keyset refusal expected: the one
// the cipher is bound to. ok is false for any other error. The id is an
// encrypt.KeysetID's bytes: it compares with one as is.
func (d *Diagnostic) ExpectedKeyset() (id [16]byte, ok bool) {
	return d.foreignKeyset("expected")
}

// FoundKeyset is the keyset a foreign-keyset refusal found: the one the
// ciphertext was sealed under. ok is false for any other error.
func (d *Diagnostic) FoundKeyset() (id [16]byte, ok bool) {
	return d.foreignKeyset("found")
}

func (d *Diagnostic) foreignKeyset(key string) ([16]byte, bool) {
	if d.Code != codeForeignKeyset {
		return [16]byte{}, false
	}
	text, _ := d.Fields[key].(string)
	return parseUUID(text)
}

// Field is the field of a plan, record or value the error is about, or ""
// when it names none.
func (d *Diagnostic) Field() string {
	field, _ := d.Fields["field"].(string)
	return field
}

// Reason is what was wrong with a plan, context, value or stored record, as
// the snake_case name stack-encrypt's dynamic::Reason gives it
// ("field_missing", "unknown_key", "field_type", ...), or "" for an error
// that gives none. New reasons may appear: keep a fallback.
func (d *Diagnostic) Reason() string {
	reason, _ := d.Fields["reason"].(string)
	return reason
}

// parseUUID parses a canonical hyphenated UUID.
func parseUUID(text string) ([16]byte, bool) {
	var id [16]byte
	if len(text) != 36 || text[8] != '-' || text[13] != '-' || text[18] != '-' || text[23] != '-' {
		return id, false
	}
	hexed := text[:8] + text[9:13] + text[14:18] + text[19:23] + text[24:]
	if _, err := hex.Decode(id[:], []byte(hexed)); err != nil {
		return [16]byte{}, false
	}
	return id, true
}

// diagnose returns the full error behind kind, the sentinel a non-zero
// status decoded to: a *Diagnostic wrapping kind, fetched through the
// guest's se_last_error and wiped, host copy and guest buffer both, once
// decoded. It returns kind itself when there is no detail to give: the
// guest has no se_last_error (one built before it), recorded nothing, or
// handed over bytes that do not decode into an error with a message.
//
// A trap in se_last_error leaves the guest in an unknown state, so the
// error then also wraps ErrTrap, for the caller to close the instance as
// it would after any trap; it still matches kind.
func (e Exports) diagnose(ctx context.Context, m api.Module, kind error) error {
	if e.LastError == nil {
		return kind
	}
	// Under a context that cannot be cancelled, as the frees are: the
	// guest has returned, and a deadline that expires now must not cost
	// the caller the detail of a failure already in hand.
	res, err := e.LastError.Call(context.WithoutCancel(ctx))
	if err != nil {
		return fmt.Errorf("%w; %w: fetching the error's detail: %w", kind, ErrTrap, err)
	}
	if len(res) == 0 || res[0]>>32 == 0 {
		return kind
	}
	out := Buf{Ptr: uint32(res[0] >> 32), Len: uint32(res[0])} //nolint:gosec // splits the packed u64 into its two u32 halves
	defer e.Free(ctx, out)
	view, ok := m.Memory().Read(out.Ptr, out.Len)
	if !ok {
		return kind
	}
	raw := make([]byte, len(view))
	copy(raw, view)
	defer Wipe(raw)
	d, ok := decodeDiagnostic(raw)
	if !ok {
		return kind
	}
	d.kind = kind
	return d
}

// LastErrorExport is the module's se_last_error when it has the ABI's type,
// () -> i64, and nil otherwise, as for a guest built before it: the
// failure is then reported by its status alone.
func LastErrorExport(m api.Module) api.Function {
	fn := m.ExportedFunction("se_last_error")
	if fn == nil {
		return nil
	}
	def := fn.Definition()
	if len(def.ParamTypes()) != 0 || len(def.ResultTypes()) != 1 || def.ResultTypes()[0] != api.ValueTypeI64 {
		return nil
	}
	return fn
}

// decodeDiagnostic reads the object se_last_error encodes: code, message,
// help, url, severity, fields and causes. An error with no message is not
// one: ok is false, and the caller falls back to the sentinel.
func decodeDiagnostic(raw []byte) (*Diagnostic, bool) {
	value, err := vcffi.Unmarshal(raw)
	if err != nil {
		return nil, false
	}
	object, ok := value.(vcvalue.Object)
	if !ok {
		return nil, false
	}
	d := &Diagnostic{Severity: "error", Fields: map[string]any{}}
	text := map[string]*string{
		"code":     &d.Code,
		"message":  &d.Message,
		"help":     &d.Help,
		"url":      &d.URL,
		"severity": &d.Severity,
	}
	for _, entry := range object {
		if slot, isText := text[entry.Key]; isText {
			if s, isString := entry.Value.(string); isString {
				*slot = s
			}
			continue
		}
		switch entry.Key {
		case "fields":
			if fields, isObject := entry.Value.(vcvalue.Object); isObject {
				d.Fields = objectMap(fields)
			}
		case "causes":
			d.Causes = causes(entry.Value)
		}
	}
	if d.Message == "" {
		return nil, false
	}
	return d, true
}

// causes reads a list of {code?, message} objects, skipping anything else.
func causes(value any) []Cause {
	items, _ := value.([]any)
	var out []Cause
	for _, item := range items {
		entry, ok := item.(vcvalue.Object)
		if !ok {
			continue
		}
		fields := objectMap(entry)
		code, _ := fields["code"].(string)
		message, _ := fields["message"].(string)
		out = append(out, Cause{Code: code, Message: message})
	}
	return out
}

// objectMap turns a decoded object into a map, and every object or list
// inside it likewise, so Fields holds only plain Go values.
func objectMap(object vcvalue.Object) map[string]any {
	out := make(map[string]any, len(object))
	for _, entry := range object {
		out[entry.Key] = plain(entry.Value)
	}
	return out
}

func plain(value any) any {
	switch v := value.(type) {
	case vcvalue.Object:
		return objectMap(v)
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = plain(item)
		}
		return out
	default:
		return v
	}
}
