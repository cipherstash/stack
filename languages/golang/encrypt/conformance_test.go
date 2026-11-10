package encrypt_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/internal/record"
	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
)

// This runner tests the record interface used by generated SDK code. Generated
// declarations have separate tests; this is not a substitute for SDK conformance.
const conformanceProfile = "record-scalars-v1"

type conformanceCorpus struct {
	Version              int               `json:"version"`
	Profile              string            `json:"profile"`
	Seed                 string            `json:"seed"`
	Context              []string          `json:"context"`
	Field                string            `json:"field"`
	RequiredCapabilities []string          `json:"required_capabilities"`
	Cases                []conformanceCase `json:"cases"`
}

type conformanceCase struct {
	ID            string           `json:"id"`
	Kind          string           `json:"kind"`
	Input         conformanceInput `json:"input"`
	ExpectedError *struct {
		Code   string `json:"code"`
		Reason string `json:"reason"`
	} `json:"expected_error"`
}

type conformanceArtifact struct {
	Frame      string `json:"frame"`
	Ciphertext string `json:"ciphertext"`
	Equality   string `json:"equality"`
}

type conformanceArtifacts struct {
	Version  int                            `json:"version"`
	Profile  string                         `json:"profile"`
	Producer string                         `json:"producer"`
	Cases    map[string]conformanceArtifact `json:"cases"`
}

func readConformanceJSON(t *testing.T, path string, out any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	d.UseNumber()
	if err := d.Decode(out); err != nil {
		t.Fatal(err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		t.Fatalf("%s: trailing JSON or invalid suffix: %v", path, err)
	}
}

type conformanceInput struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// conformanceValue is the typed Go value an input names: every integer at
// its own width, the SDK's Int128, Uint128, Date and Decimal, a time.Time
// for a timestamp, and bytes from hex. A text the type cannot carry fails
// the test; nothing is rounded.
func conformanceValue(t testing.TB, input conformanceInput) any {
	t.Helper()
	signed := func(bits int) int64 {
		n, err := strconv.ParseInt(input.Text, 10, bits)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	unsigned := func(bits int) uint64 {
		n, err := strconv.ParseUint(input.Text, 10, bits)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	float := func(bits int) float64 {
		n, err := conformanceFloat(input.Text, bits)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	switch input.Type {
	case "int8":
		return int8(signed(8))
	case "int16":
		return int16(signed(16))
	case "int32":
		return int32(signed(32))
	case "int64":
		return signed(64)
	case "int128":
		n, err := encrypt.ParseInt128(input.Text)
		if err != nil {
			t.Fatal(err)
		}
		return n
	case "uint8":
		return uint8(unsigned(8))
	case "uint16":
		return uint16(unsigned(16))
	case "uint32":
		return uint32(unsigned(32))
	case "uint64":
		return unsigned(64)
	case "uint128":
		n, err := encrypt.ParseUint128(input.Text)
		if err != nil {
			t.Fatal(err)
		}
		return n
	case "float32":
		return float32(float(32))
	case "float64":
		return float(64)
	case "bytes":
		b, err := hex.DecodeString(input.Text)
		if err != nil {
			t.Fatal(err)
		}
		return b
	case "date":
		d, err := time.Parse(time.DateOnly, input.Text)
		if err != nil {
			t.Fatal(err)
		}
		return encrypt.DateOf(d)
	case "timestamp":
		at, err := time.Parse(time.RFC3339Nano, input.Text)
		if err != nil {
			t.Fatal(err)
		}
		return at
	case "decimal":
		d, err := encrypt.ParseDecimal(input.Text)
		if err != nil {
			t.Fatal(err)
		}
		return d
	case "bool":
		if input.Text != "true" && input.Text != "false" {
			t.Fatal("bool must be true or false")
		}
		return input.Text == "true"
	case "string":
		return input.Text
	case "null":
		if input.Text != "" {
			t.Fatal("null has empty text")
		}
		return nil
	default:
		t.Fatalf("unsupported input type %q", input.Type)
		return nil
	}
}

func TestStackConformance(t *testing.T) {
	root := filepath.Join("..", "..", "..", "conformance", "stack-encrypt", "v1")
	var corpus conformanceCorpus
	readConformanceJSON(t, filepath.Join(root, "record-scalars-v1.cases.json"), &corpus)
	if corpus.Version != 1 || corpus.Profile != conformanceProfile || len(corpus.Cases) == 0 {
		t.Fatal("unsupported or empty conformance corpus")
	}
	if !reflect.DeepEqual(corpus.RequiredCapabilities, []string{"records", "equality", "context-binding", "query-errors"}) {
		t.Fatal("unsupported required capabilities")
	}
	seen := make(map[string]bool)
	positive := make(map[string]bool)
	for _, c := range corpus.Cases {
		if c.ID == "" || seen[c.ID] {
			t.Fatalf("empty or duplicate case ID %q", c.ID)
		}
		seen[c.ID] = true
		if c.ExpectedError == nil {
			positive[c.ID] = true
		}
	}
	var native conformanceArtifacts
	readConformanceJSON(t, filepath.Join(root, "record-scalars-v1.expected.rust-native.json"), &native)
	if native.Version != 1 || native.Profile != conformanceProfile || native.Producer == "" || len(native.Cases) != len(positive) || len(positive) == 0 {
		t.Fatal("artifact profile or case set differs from the corpus")
	}
	for id := range native.Cases {
		if !positive[id] {
			t.Fatalf("unexpected artifact %q", id)
		}
	}
	seed, err := hex.DecodeString(corpus.Seed)
	if err != nil || len(seed) != 32 {
		t.Fatal("expected 32-byte deterministic test seed")
	}
	ctx := context.Background()
	client, err := encrypt.NewDeterministicClient(ctx, [32]byte(seed))
	skipMissingConformanceGuest(t, err)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	cipher := client.DefaultKeyset()
	output := conformanceArtifacts{Version: 1, Profile: conformanceProfile, Producer: "go-wasi", Cases: make(map[string]conformanceArtifact)}
	for _, c := range corpus.Cases {
		t.Run(c.ID, func(t *testing.T) {
			plan := &record.Plan{Context: corpus.Context, Fields: []record.Field{{
				Name: corpus.Field, Kind: record.Kind(c.Kind), Outputs: []record.Output{record.Ciphertext, record.Equality},
			}}}
			input := conformanceValue(t, c.Input)
			query, err := cipher.QueryTerm(ctx, plan, corpus.Field, "eq", input)
			if c.ExpectedError != nil {
				assertConformanceDiagnostic(t, err, c.ExpectedError.Code, c.ExpectedError.Reason, corpus.Field)
				return
			}
			if c.Kind != c.Input.Type {
				t.Fatal("positive case must use its declared type")
			}
			if err != nil {
				t.Fatal(err)
			}
			if query.Operator != "eq" || query.Index != record.Equality || query.Fidelity != record.Exact || query.Encoding != "bytes" || query.Domain != "" || len(query.Terms) != 1 {
				t.Fatal("unexpected equality operand metadata")
			}
			want := native.Cases[c.ID]
			encoded, err := vcffi.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(encoded) != want.Frame || hex.EncodeToString(query.Terms[0]) != want.Equality {
				t.Fatal("typed frame or equality bytes disagree with the native vector")
			}
			decode := func(text string) []byte {
				t.Helper()
				b, err := hex.DecodeString(text)
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
			source := []record.Source{{corpus.Field: input}}
			fresh, err := cipher.Seal(ctx, plan, source)
			if err != nil {
				t.Fatal(err)
			}
			if len(fresh) != 1 || !bytes.Equal(fresh[0][corpus.Field].Terms[record.Equality], query.Terms[0]) {
				t.Fatal("stored equality differs from query equality")
			}
			frozen := []record.Sealed{{corpus.Field: {Ciphertext: decode(want.Ciphertext), Terms: map[record.Output][]byte{record.Equality: decode(want.Equality)}}}}
			for name, rows := range map[string][]record.Sealed{"native": frozen, "go": fresh} {
				opened, err := cipher.Open(ctx, plan, rows)
				if err != nil || !reflect.DeepEqual(opened, source) {
					t.Fatalf("%s cross-open: err=%v; typed value mismatch=%v", name, err, !reflect.DeepEqual(opened, source))
				}
			}
			wrong := *plan
			wrong.Context = append(append([]string{}, corpus.Context...), "wrong")
			if _, err := cipher.Open(ctx, &wrong, frozen); !errors.Is(err, encrypt.ErrForbidden) {
				t.Fatalf("wrong context: expected forbidden key retrieval, got %v", err)
			}
			output.Cases[c.ID] = conformanceArtifact{Frame: hex.EncodeToString(encoded), Ciphertext: hex.EncodeToString(fresh[0][corpus.Field].Ciphertext), Equality: hex.EncodeToString(query.Terms[0])}
		})
	}
	if t.Failed() {
		return
	}
	if path := os.Getenv("STACK_CONFORMANCE_OUTPUT"); path != "" {
		data, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func assertConformanceDiagnostic(t *testing.T, err error, code, reason, field string) {
	t.Helper()
	var diagnostic *encrypt.Diagnostic
	if !errors.Is(err, encrypt.ErrEncoding) || !errors.As(err, &diagnostic) {
		t.Fatalf("expected encoding diagnostic, got %v", err)
	}
	if diagnostic.Code != code || diagnostic.Reason() != reason || diagnostic.Field() != field {
		t.Fatalf("unexpected diagnostic: %s reason=%s field=%s", diagnostic.Code, diagnostic.Reason(), diagnostic.Field())
	}
}

// conformanceFloat reads a float from its canonical spelling
// (canonicalFloat). Any other text that parses, such as 1.00, 1e+3, 1E3,
// +1 or a rounded decimal, is a corpus error, so every runner reads one
// spelling alike.
func conformanceFloat(text string, bits int) (float64, error) {
	n, err := strconv.ParseFloat(text, bits)
	if err != nil {
		return 0, err
	}
	if canonical, ok := canonicalFloat(n, bits); !ok || canonical != text {
		return 0, fmt.Errorf("%s: not the shortest spelling of a representable value", text)
	}
	return n, nil
}

// canonicalFloat is a float's canonical spelling: of its positional
// spelling (34, -0, 0.5) and its scientific spelling (1e3, 3.4028235e38,
// 5e-324; no plus sign or leading zero in the exponent), both of the
// shortest digits that round-trip, the shorter, and the positional one on a
// tie (100, not 1e2). The infinities are inf and -inf; NaN has none. It is
// the text Rust's canonical_float derives from its {} and {:e} formats.
func canonicalFloat(n float64, bits int) (string, bool) {
	switch {
	case math.IsNaN(n):
		return "", false
	case math.IsInf(n, 1):
		return "inf", true
	case math.IsInf(n, -1):
		return "-inf", true
	}
	positional := strconv.FormatFloat(n, 'f', -1, bits)
	mantissa, exponent, _ := strings.Cut(strconv.FormatFloat(n, 'e', -1, bits), "e")
	sign, digits := "", strings.TrimPrefix(exponent, "+")
	if strings.HasPrefix(digits, "-") {
		sign, digits = "-", digits[1:]
	}
	if digits = strings.TrimLeft(digits, "0"); digits == "" {
		digits = "0"
	}
	if scientific := mantissa + "e" + sign + digits; len(scientific) < len(positional) {
		return scientific, true
	}
	return positional, true
}

// TestConformanceFloatSpelling holds the float reader to the lists Rust's
// the_float_reader_accepts_only_the_canonical_spelling uses.
func TestConformanceFloatSpelling(t *testing.T) {
	canonical := []struct {
		bits int
		text string
	}{
		{64, "100"}, {64, "12000"}, {64, "1e3"}, {64, "34"}, {64, "-0"},
		{64, "1.5"}, {64, "0.5"}, {64, "1e-3"}, {64, "9007199254740992"},
		{64, "1.7976931348623157e308"}, {64, "5e-324"}, {64, "inf"}, {64, "-inf"},
		{32, "1e-45"}, {32, "3.4028235e38"},
	}
	for _, c := range canonical {
		if _, err := conformanceFloat(c.text, c.bits); err != nil {
			t.Errorf("float%d %q: %v", c.bits, c.text, err)
		}
	}
	nonCanonical := []struct {
		bits int
		text string
	}{
		{64, "1.00"}, {64, "1.0"}, {64, "1e0"}, {64, "1.5e0"}, {64, "1000"},
		{64, "1e2"}, {64, "1e+3"}, {64, "1E3"}, {64, "10e2"}, {64, "01"},
		{64, "+1"}, {64, ".5"}, {64, "5."}, {64, "-0.0"}, {64, "0.001"},
		{64, "0.1000000000000000001"}, {64, "Inf"}, {64, "infinity"}, {64, "NaN"},
		{32, "1.4e-45"}, {32, "3.4028234664e38"},
	}
	for _, c := range nonCanonical {
		if _, err := strconv.ParseFloat(c.text, c.bits); err != nil {
			t.Fatalf("float%d %q does not parse: %v", c.bits, c.text, err)
		}
		if n, err := conformanceFloat(c.text, c.bits); err == nil {
			t.Errorf("float%d %q: read as %v, want a corpus error", c.bits, c.text, n)
		}
	}
}
