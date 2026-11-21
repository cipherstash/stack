package gensupport

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/cipherstash/stack/languages/golang/encrypt"
)

// numbers holds the values a float64 would round: the 64-bit integer
// extremes and a float that needs 17 significant digits.
type numbers struct {
	Min   int64   `json:"min"`
	Max   int64   `json:"max"`
	UMax  uint64  `json:"umax"`
	Float float64 `json:"float"`
}

var extremes = numbers{Min: math.MinInt64, Max: math.MaxInt64, UMax: math.MaxUint64, Float: 0.30000000000000004} // the float64 after 0.3: 17 digits

// failingMarshaler's MarshalJSON fails with an error that holds a value.
type failingMarshaler struct{}

func (failingMarshaler) MarshalJSON() ([]byte, error) { return nil, errors.New("secret-value") }

func TestJSONTextWritesExactNumbersAndRefusesWhatIsNotJSON(t *testing.T) {
	text, err := JSONText(extremes)
	if err != nil {
		t.Fatal(err)
	}
	// encoding/json writes integers as their digits and a float64 as the
	// shortest text that reads back to it: 0.30000000000000004, 17 digits.
	want := `{"min":-9223372036854775808,"max":9223372036854775807,"umax":18446744073709551615,"float":0.30000000000000004}`
	if string(text) != want {
		t.Fatalf("JSONText = %s, want %s", text, want)
	}
	// A json.RawMessage is JSON text already: it crosses unchanged, spacing
	// and all, so a RawMessage needle sends what it sent before.
	raw := json.RawMessage(`{ "a" : 1 }`)
	if text, err := JSONText(raw); err != nil || string(text) != string(raw) {
		t.Fatalf("a RawMessage: %s %v", text, err)
	}
	// Scalars for the path operators, and nil for JSON null.
	for v, want := range map[any]string{"Alice": `"Alice"`, int64(40): `40`, true: `true`, nil: `null`} {
		if text, err := JSONText(v); err != nil || string(text) != want {
			t.Errorf("JSONText(%v) = %s %v, want %s", v, text, err, want)
		}
	}
	for name, v := range map[string]any{
		"[]byte":      []byte(`{"secret-value":1}`),
		"NaN":         math.NaN(),
		"infinity":    map[string]float64{"x": math.Inf(1)},
		"channel":     make(chan int),
		"MarshalJSON": failingMarshaler{},
	} {
		_, err := JSONText(v)
		if !errors.Is(err, encrypt.ErrEncoding) {
			t.Errorf("%s: %v, want ErrEncoding", name, err)
			continue
		}
		// The error names a type, never the value: encoding/json's own
		// text would say "unsupported value: NaN" or "+Inf".
		if msg := err.Error(); strings.Contains(msg, "secret-value") || strings.Contains(msg, "unsupported value") || strings.Contains(msg, "+Inf") {
			t.Errorf("%s: the error shows the value: %s", name, msg)
		}
	}
}

func TestGetDocumentReadsTheDeclaredType(t *testing.T) {
	text, err := JSONText(extremes)
	if err != nil {
		t.Fatal(err)
	}
	vals := Values{"doc": text, "none": nil, "wrong": "text"}
	got, err := GetDocument[numbers](vals, "doc")
	if err != nil || got != extremes {
		t.Fatalf("GetDocument = %+v %v, want %+v", got, err, extremes)
	}
	ptr, err := GetDocumentPtr[numbers](vals, "doc")
	if err != nil || ptr == nil || *ptr != extremes {
		t.Fatalf("GetDocumentPtr = %v %v", ptr, err)
	}
	// A null=sql field that was nil opened as nil, and reads as nil.
	if ptr, err := GetDocumentPtr[numbers](vals, "none"); err != nil || ptr != nil {
		t.Fatalf("a nil document: %v %v", ptr, err)
	}
	if _, err := GetDocument[numbers](vals, "missing"); err == nil {
		t.Fatal("a field the opened value lacks reads")
	}
	if _, err := GetDocument[numbers](vals, "wrong"); !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("a document that opened as a string: %v", err)
	}
	// A document that does not fit the type is refused, naming the type
	// and the field, not the value.
	vals["doc"] = []byte(`{"max":"secret-value"}`)
	_, err = GetDocument[numbers](vals, "doc")
	if !errors.Is(err, encrypt.ErrEncoding) || strings.Contains(err.Error(), "secret-value") || !strings.Contains(err.Error(), `"doc"`) {
		t.Fatalf("a mismatched document: %v", err)
	}
}

// code writes and reads itself, MarshalJSON on the value and UnmarshalJSON
// on the pointer, as json.RawMessage and time.Time do.
type code struct{ v string }

func (c code) MarshalJSON() ([]byte, error) { return json.Marshal("code:" + c.v) }

func (c *code) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	c.v = strings.TrimPrefix(s, "code:")
	return nil
}

// pointers holds a pointer to each kind of codec type stashgen accepts in a
// document: the codec runs through the pointer both ways.
type pointers struct {
	At   *time.Time       `json:"at"`
	Raw  *json.RawMessage `json:"raw"`
	Code *code            `json:"code"`
	None *time.Time       `json:"none"`
}

func TestPointersToCodecTypesRoundTrip(t *testing.T) {
	at := time.Date(2026, 10, 26, 10, 0, 0, 500, time.UTC)
	raw := json.RawMessage(`{"a":[1,2]}`)
	in := pointers{At: &at, Raw: &raw, Code: &code{v: "x"}}
	text, err := JSONText(in)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"at":"2026-10-26T10:00:00.0000005Z","raw":{"a":[1,2]},"code":"code:x","none":null}`; string(text) != want {
		t.Fatalf("JSONText = %s, want %s", text, want)
	}
	out, err := GetDocument[pointers](Values{"doc": text}, "doc")
	if err != nil {
		t.Fatal(err)
	}
	if out.At == nil || !out.At.Equal(at) || out.Raw == nil || string(*out.Raw) != string(raw) || out.Code == nil || out.Code.v != "x" || out.None != nil {
		t.Fatalf("read back %+v", out)
	}
}

func TestJSONQueryRefusesAStringOrNullNeedle(t *testing.T) {
	f := Field[map[string]string]{name: "labels"}
	s, n := `{"team":"secret-value"}`, json.Number("1")
	var nilPtr *numbers
	var nilMap map[string]string
	var nilSlice []string
	b := []byte(`{"team":"secret-value"}`)
	for name, c := range map[string]struct {
		needle any
		want   string
	}{
		"*string":        {&s, "one JSON string"},
		"*json.Number":   {&n, "one JSON string"},
		"nil":            {nil, "nil needle"},
		"a nil pointer":  {nilPtr, "writes JSON null"},
		"a nil map":      {nilMap, "writes JSON null"},
		"a nil slice":    {nilSlice, "writes JSON null"},
		"null JSON text": {json.RawMessage(`null`), "writes JSON null"},
		"*[]byte":        {&b, "base64"},
	} {
		for _, operator := range []string{"contains", "contained_by"} {
			_, err := JSONQuery[[]byte](context.Background(), f, nil, operator, c.needle)
			if !errors.Is(err, encrypt.ErrEncoding) || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), "secret-value") {
				t.Errorf("%s %s: %v, want %q", operator, name, err, c.want)
			}
		}
	}
	// A needle that writes itself, a pointer to one included, and an empty
	// map pass the checks and reach the cipher, which this test has none of.
	raw := json.RawMessage(`{"team":"red"}`)
	for name, needle := range map[string]any{"*json.RawMessage": &raw, "an empty map": map[string]string{}, "a map": map[string]string{"team": "red"}} {
		if _, err := JSONQuery[[]byte](context.Background(), f, nil, "contains", needle); err == nil || !strings.Contains(err.Error(), "needs a cipher") {
			t.Errorf("%s: %v, want it to reach the cipher", name, err)
		}
	}
}
