package encrypt_test

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
)

func TestDecodeJSONReadsTheCallersType(t *testing.T) {
	type visit struct {
		At    uint64 `json:"at"`
		Place string `json:"place"`
	}
	v, err := encrypt.DecodeJSON[visit](json.RawMessage(`{"at":18446744073709551615,"place":"home","extra":true}`))
	if err != nil || v != (visit{At: math.MaxUint64, Place: "home"}) {
		t.Fatalf("a struct: %+v %v", v, err)
	}
	// A scalar, as a selector read opens one.
	if n, err := encrypt.DecodeJSON[int64](json.RawMessage(`-9223372036854775808`)); err != nil || n != math.MinInt64 {
		t.Fatalf("an int64: %d %v", n, err)
	}
	if f, err := encrypt.DecodeJSON[float64](json.RawMessage(`0.30000000000000004`)); err != nil || f != math.Nextafter(0.3, 1) {
		t.Fatalf("a float64: %v %v", f, err)
	}
	// An interface reads a number as a json.Number, never a float64 that
	// would round it.
	m, err := encrypt.DecodeJSON[map[string]any](json.RawMessage(`{"big":9007199254740993}`))
	if err != nil || m["big"] != json.Number("9007199254740993") {
		t.Fatalf("an interface: %#v %v", m, err)
	}
	// A JSON null that is there reads as the zero value.
	if p, err := encrypt.DecodeJSON[*visit](json.RawMessage(`null`)); err != nil || p != nil {
		t.Fatalf("null: %v %v", p, err)
	}
	// Trailing text that is not JSON is told apart from a second value, and
	// an interface type is named.
	if _, err := encrypt.DecodeJSON[map[string]int](json.RawMessage(`{"a":1}}`)); err == nil || strings.Contains(err.Error(), "more than one") {
		t.Fatalf("trailing junk: %v", err)
	}
	if _, err := encrypt.DecodeJSON[any](json.RawMessage(``)); err == nil || !strings.Contains(err.Error(), "interface {}") {
		t.Fatalf("an interface type is not named: %v", err)
	}
	for name, text := range map[string]string{
		"an unfound value":      ``,
		"not JSON":              `{"secret-value"`,
		"two values":            `1 2`,
		"a mismatched number":   `"secret-value"`,
		"a number too big":      `123456789012345678901234567890`,
		"a fraction for an int": `1.5`,
	} {
		_, err := encrypt.DecodeJSON[int64](json.RawMessage(text))
		if !errors.Is(err, encrypt.ErrEncoding) {
			t.Errorf("%s: %v, want ErrEncoding", name, err)
			continue
		}
		// The error names the Go type and a JSON kind, never the value.
		if msg := err.Error(); strings.Contains(msg, "secret") || strings.Contains(msg, "1234567890") || strings.Contains(msg, "1.5") {
			t.Errorf("%s: the error shows the value: %s", name, msg)
		}
	}
}
