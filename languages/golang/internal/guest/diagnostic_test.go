package guest_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/internal/guest"
	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/experimental"
)

// The fetch, decode and wipe of a guest's detail, against a hand-assembled
// guest whose se_last_error hands over fixed bytes, so each way the detail
// can be missing or broken is reachable. What the real guests record is
// tested where they are embedded (encrypt's and auth's error tests).

// detailAt is where the stub guest keeps the bytes se_last_error hands over.
const detailAt = 1024

// lastErrorMode is what the stub guest's se_last_error does.
type lastErrorMode int

const (
	withLastError lastErrorMode = iota
	noLastError
	trappingLastError
	// outOfRangeLastError hands over a buffer that starts at the end of the
	// stub's one page of memory.
	outOfRangeLastError
	// mistypedLastError exports se_last_error with se_dealloc's type,
	// (i32, i32) -> (), which is not the ABI's.
	mistypedLastError
)

// stubGuest assembles a guest with the exports guest.Call drives, and a
// failing export:
//
//	(module
//	  (memory (export "memory") 1)
//	  (func (export "se_alloc") (param i32) (result i32) i32.const 4096)
//	  (func (export "se_dealloc") (param i32 i32)
//	    local.get 0 i32.const 0 local.get 1 memory.fill)
//	  (func (export "fail") (param i32 i32) (result i64) i64.const <status>)
//	  (func (export "se_last_error") (result i64) i64.const <detailAt<<32 | len>)
//	  (data (i32.const 1024) "<detail>"))
//
// se_dealloc zeroes, as the real guests' does, so a test can see the detail
// was released. With no detail, se_last_error returns zero (nothing
// recorded); under noLastError it is not exported at all, as in a guest
// built before it, and under trappingLastError its body is unreachable.
func stubGuest(status uint32, detail []byte, mode lastErrorMode) []byte {
	packed := int64(0)
	if len(detail) > 0 {
		packed = int64(detailAt)<<32 | int64(len(detail))
	}
	if mode == outOfRangeLastError {
		packed = int64(1<<16)<<32 | 16 // starts at the end of the one-page memory
	}
	types := vec(
		[]byte{0x60, 0x01, 0x7f, 0x01, 0x7f},       // (i32) -> i32
		[]byte{0x60, 0x02, 0x7f, 0x7f, 0x00},       // (i32, i32) -> ()
		[]byte{0x60, 0x00, 0x01, 0x7e},             // () -> i64
		[]byte{0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7e}, // (i32, i32) -> i64
	)
	funcs := vec([]byte{0}, []byte{1}, []byte{3}, []byte{2})
	memory := vec([]byte{0x00, 0x01}) // min 1 page, no max
	exports := [][]byte{
		export("memory", 0x02, 0),
		export("se_alloc", 0x00, 0),
		export("se_dealloc", 0x00, 1),
		export("fail", 0x00, 2),
	}
	switch mode {
	case noLastError:
	case mistypedLastError:
		exports = append(exports, export("se_last_error", 0x00, 1))
	default:
		exports = append(exports, export("se_last_error", 0x00, 3))
	}
	lastError := body(append([]byte{0x42}, sleb(packed)...)...)
	if mode == trappingLastError {
		lastError = body(0x00) // unreachable
	}
	code := vec(
		body(append([]byte{0x41}, sleb(4096)...)...),
		body(0x20, 0x00, 0x41, 0x00, 0x20, 0x01, 0xfc, 0x0b, 0x00),
		body(append([]byte{0x42}, sleb(int64(status))...)...),
		lastError,
	)
	segment := append([]byte{0x00, 0x41}, sleb(detailAt)...)
	segment = append(segment, 0x0b)
	segment = append(segment, uleb(uint64(len(detail)))...)
	segment = append(segment, detail...)
	module := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	for _, s := range []struct {
		id   byte
		body []byte
	}{
		{1, types}, {3, funcs}, {5, memory}, {7, vec(exports...)}, {10, code}, {11, vec(segment)},
	} {
		module = append(module, s.id)
		module = append(module, uleb(uint64(len(s.body)))...)
		module = append(module, s.body...)
	}
	return module
}

func uleb(v uint64) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v == 0 {
			return append(out, b)
		}
		out = append(out, b|0x80)
	}
}

func sleb(v int64) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if (v == 0 && b&0x40 == 0) || (v == -1 && b&0x40 != 0) {
			return append(out, b)
		}
		out = append(out, b|0x80)
	}
}

func vec(items ...[]byte) []byte {
	out := uleb(uint64(len(items)))
	for _, item := range items {
		out = append(out, item...)
	}
	return out
}

func export(name string, kind byte, index byte) []byte {
	out := append(uleb(uint64(len(name))), name...)
	return append(out, kind, index)
}

// body is a function body with no locals.
func body(code ...byte) []byte {
	b := append([]byte{0x00}, code...)
	b = append(b, 0x0b)
	return append(uleb(uint64(len(b))), b...)
}

// callStub instantiates a stub guest, calls its failing export through
// guest.Call, and returns the detail's bytes as guest memory holds them
// afterwards, and the error.
func callStub(t *testing.T, status uint32, detail []byte, mode lastErrorMode) ([]byte, error) {
	t.Helper()
	ctx := context.Background()
	rt := wazero.NewRuntime(ctx)
	defer func() { _ = rt.Close(ctx) }()
	alloc := guest.NewAllocator(guest.BestEffort)
	m, err := rt.InstantiateWithConfig(experimental.WithMemoryAllocator(ctx, alloc), stubGuest(status, detail, mode), wazero.NewModuleConfig())
	if err != nil {
		t.Fatalf("instantiating the stub guest: %v", err)
	}
	exports := guest.Exports{
		Alloc:     m.ExportedFunction("se_alloc"),
		Dealloc:   m.ExportedFunction("se_dealloc"),
		LastError: guest.LastErrorExport(m),
	}
	if (mode != noLastError && mode != mistypedLastError) != (exports.LastError != nil) {
		t.Fatalf("se_last_error exported = %v under mode %d", exports.LastError != nil, mode)
	}
	_, callErr := guest.Call(ctx, alloc, m, exports, m.ExportedFunction("fail"), guest.BufArg([]byte("input")))
	left, ok := m.Memory().Read(detailAt, uint32(len(detail))) //nolint:gosec // a test detail is small
	if !ok {
		t.Fatal("reading the stub's memory")
	}
	return bytes.Clone(left), callErr
}

func encode(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := vcffi.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A failure with detail is a *Diagnostic: the sentinel still matches, the
// message is the Rust one, every field decodes, and the detail is wiped
// from guest memory once read.
func TestAFailureCarriesItsDiagnostic(t *testing.T) {
	expected := "00000000-0000-0000-0000-000000000001"
	found := "00000000-0000-0000-0000-0000000000ff"
	detail := encode(t, map[string]any{
		"code":     "stack_encrypt::foreign_keyset",
		"message":  "ciphertext was sealed under another keyset",
		"help":     "Open it through the client.",
		"url":      "https://example.com/errors/foreign_keyset",
		"severity": "warning",
		"fields": map[string]any{
			"expected": expected,
			"found":    found,
			"field":    "email",
			"reason":   "field_missing",
			"count":    uint64(3),
			"nested":   map[string]any{"list": []any{"a", uint64(1)}},
		},
		"causes": []any{
			map[string]any{"code": "stack_kms::keyset_not_found", "message": "inner"},
			map[string]any{"message": "an error from another library"},
			"not a cause",
		},
	})
	left, err := callStub(t, guest.StatusForeignKeyset, detail, withLastError)
	if !errors.Is(err, guest.ErrForeignKeyset) {
		t.Fatalf("err = %v, want it to match ErrForeignKeyset", err)
	}
	var d *guest.Diagnostic
	if !errors.As(err, &d) {
		t.Fatalf("err = %#v, want a *Diagnostic", err)
	}
	if want := guest.ErrForeignKeyset.Error() + ": ciphertext was sealed under another keyset"; err.Error() != want {
		t.Errorf("Error() = %q, want %q: the sentinel's text, then the Rust message", err.Error(), want)
	}
	if d.Code != "stack_encrypt::foreign_keyset" || d.Help != "Open it through the client." ||
		d.URL != "https://example.com/errors/foreign_keyset" || d.Severity != "warning" {
		t.Errorf("decoded %+v", d)
	}
	var wantExpected, wantFound [16]byte
	wantExpected[15], wantFound[15] = 0x01, 0xff
	if got, ok := d.ExpectedKeyset(); !ok || got != wantExpected {
		t.Errorf("ExpectedKeyset() = %x, %v; want %x", got, ok, wantExpected)
	}
	if got, ok := d.FoundKeyset(); !ok || got != wantFound {
		t.Errorf("FoundKeyset() = %x, %v; want %x", got, ok, wantFound)
	}
	if d.Field() != "email" || d.Reason() != "field_missing" {
		t.Errorf("Field() = %q, Reason() = %q", d.Field(), d.Reason())
	}
	if d.Fields["count"] != uint64(3) {
		t.Errorf("Fields[count] = %#v", d.Fields["count"])
	}
	nested, _ := d.Fields["nested"].(map[string]any)
	if list, _ := nested["list"].([]any); len(list) != 2 || list[0] != "a" || list[1] != uint64(1) {
		t.Errorf("Fields[nested] = %#v, want plain Go values all the way down", d.Fields["nested"])
	}
	want := []guest.Cause{
		{Code: "stack_kms::keyset_not_found", Message: "inner"},
		{Message: "an error from another library"},
	}
	if len(d.Causes) != len(want) || d.Causes[0] != want[0] || d.Causes[1] != want[1] {
		t.Errorf("Causes = %+v, want %+v", d.Causes, want)
	}
	if !bytes.Equal(left, make([]byte, len(detail))) {
		t.Error("the detail was not wiped from guest memory")
	}
}

// The keyset accessors answer only for a foreign-keyset refusal, and only
// with an id that parses.
func TestKeysetAccessorsAnswerOnlyForAForeignKeyset(t *testing.T) {
	other := &guest.Diagnostic{Code: "stack_encrypt::keyset_mismatch", Fields: map[string]any{
		"expected": "00000000-0000-0000-0000-000000000001",
	}}
	if _, ok := other.ExpectedKeyset(); ok {
		t.Error("ExpectedKeyset answered for another code")
	}
	for _, bad := range []any{"not a uuid", "00000000x0000-0000-0000-000000000001", "0000000g-0000-0000-0000-000000000001", uint64(1), nil} {
		d := &guest.Diagnostic{Code: "stack_encrypt::foreign_keyset", Fields: map[string]any{"found": bad}}
		if _, ok := d.FoundKeyset(); ok {
			t.Errorf("FoundKeyset parsed %#v", bad)
		}
	}
	none := &guest.Diagnostic{Fields: map[string]any{}}
	if none.Field() != "" || none.Reason() != "" {
		t.Error("Field or Reason answered for an error that gives none")
	}
}

// With no detail to give, the failure is the bare sentinel, exactly as
// before the detail existed: a missing explanation never hides the failure.
func TestWithoutDetailTheFailureIsTheBareSentinel(t *testing.T) {
	good := encode(t, map[string]any{"code": "stack_guest_abi::status", "message": "failed"})
	cases := []struct {
		name   string
		detail []byte
		mode   lastErrorMode
	}{
		{"a guest built before se_last_error", good, noLastError},
		{"nothing recorded", nil, withLastError},
		{"bytes that are not the codec", []byte{0xff, 0x01}, withLastError},
		{"a value that is not an object", encode(t, "a string"), withLastError},
		{"an object with no message", encode(t, map[string]any{"code": "x::y"}), withLastError},
		{"a message that is not a string", encode(t, map[string]any{"message": uint64(1)}), withLastError},
		{"a buffer past the end of guest memory", good, outOfRangeLastError},
		{"an se_last_error without the ABI's type", good, mistypedLastError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			left, err := callStub(t, guest.StatusEncoding, c.detail, c.mode)
			if err != guest.ErrEncoding {
				t.Fatalf("err = %#v, want the bare ErrEncoding", err)
			}
			if c.mode == withLastError && !bytes.Equal(left, make([]byte, len(c.detail))) {
				t.Error("a detail that did not decode was not wiped")
			}
		})
	}
}

// An unknown status keeps its number, with or without detail behind it:
// a newer guest's own message for a status it added does not name it.
func TestAnUnknownStatusIsStillInternal(t *testing.T) {
	detail := encode(t, map[string]any{"code": "stack_encrypt::new_kind", "message": "a new kind of failure"})
	for _, c := range []struct {
		name   string
		detail []byte
	}{{"with detail", detail}, {"without detail", nil}} {
		t.Run(c.name, func(t *testing.T) {
			_, err := callStub(t, 99, c.detail, withLastError)
			if !errors.Is(err, guest.ErrInternal) {
				t.Fatalf("err = %#v, want it to match ErrInternal", err)
			}
			if !strings.Contains(err.Error(), "99") {
				t.Errorf("err = %q, want the status number in it", err)
			}
			var d *guest.Diagnostic
			if found := errors.As(err, &d); found != (c.detail != nil) {
				t.Fatalf("errors.As found a Diagnostic = %v, want %v", found, c.detail != nil)
			}
			if d != nil && (d.Code != "stack_encrypt::new_kind" || !strings.Contains(err.Error(), d.Message)) {
				t.Errorf("err = %q, Code = %q", err, d.Code)
			}
		})
	}
}

// A detail with only some of its keys decodes with the defaults: Severity
// "error", Fields empty and not nil, and a key of the wrong type ignored.
func TestAPartialDetailDecodesWithDefaults(t *testing.T) {
	detail := encode(t, map[string]any{
		"message": "failed",
		"code":    uint64(7),
		"fields":  "not an object",
	})
	_, err := callStub(t, guest.StatusEncoding, detail, withLastError)
	var d *guest.Diagnostic
	if !errors.As(err, &d) {
		t.Fatalf("err = %#v, want a *Diagnostic", err)
	}
	if d.Severity != "error" || d.Code != "" || d.Fields == nil || len(d.Fields) != 0 || d.Causes != nil {
		t.Errorf("decoded %+v", d)
	}
}

// A guest that aborts handing over its detail is in an unknown state: the
// error says it trapped, for the caller to close the instance, and still
// matches the failure it was reporting.
func TestATrapFetchingTheDetailIsATrap(t *testing.T) {
	detail := encode(t, map[string]any{"message": "never read"})
	_, err := callStub(t, guest.StatusEncoding, detail, trappingLastError)
	if !errors.Is(err, guest.ErrEncoding) || !errors.Is(err, guest.ErrTrap) {
		t.Fatalf("err = %v, want it to match ErrEncoding and ErrTrap", err)
	}
}
