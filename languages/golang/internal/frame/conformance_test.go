package vcffi

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// isoDate and rfc3339ish match the corpus date and timestamp spellings,
// including a negative year as a sign and six digits, which time.Parse
// cannot read.
var (
	isoDate    = regexp.MustCompile(`^([+-]\d{6}|\d{4})-(\d{2})-(\d{2})$`)
	rfc3339ish = regexp.MustCompile(`^([+-]\d{6}|\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$`)
)

// expected builds the Go value a vector's kind and value fields describe,
// without the transport decoder, so a bug that decodes and encodes
// symmetrically wrong cannot pass.
func expected(kind string, raw json.RawMessage) (any, error) {
	if kind == "unknown" {
		// A logical id this build does not know: the id, the parameter and
		// the physical scalar, which round-trips as a vcvalue.Tagged.
		var inner struct {
			ID, Param uint8
			Kind      string
			Value     json.RawMessage
		}
		if err := json.Unmarshal(raw, &inner); err != nil {
			return nil, err
		}
		v, err := expected(inner.Kind, inner.Value)
		if err != nil {
			return nil, err
		}
		return vcvalue.Tagged{ID: inner.ID, Param: inner.Param, V: v}, nil
	}
	var text string
	_ = json.Unmarshal(raw, &text)
	integer := func(bits int) (int64, error) { return strconv.ParseInt(text, 10, bits) }
	natural := func(bits int) (uint64, error) { return strconv.ParseUint(text, 10, bits) }
	switch kind {
	case "null", "undefined":
		return nil, nil
	case "bool":
		var v bool
		return v, json.Unmarshal(raw, &v)
	case "int8":
		v, err := integer(8)
		return int8(v), err
	case "uint8":
		v, err := natural(8)
		return uint8(v), err
	case "int16":
		v, err := integer(16)
		return int16(v), err
	case "uint16":
		v, err := natural(16)
		return uint16(v), err
	case "int32":
		v, err := integer(32)
		return int32(v), err
	case "uint32":
		v, err := natural(32)
		return uint32(v), err
	case "int64":
		return integer(64)
	case "uint64":
		return natural(64)
	case "int128":
		return vcvalue.ParseInt128(text)
	case "uint128":
		return vcvalue.ParseUint128(text)
	case "float32":
		var v float32
		return v, json.Unmarshal(raw, &v)
	case "float64":
		var v float64
		return v, json.Unmarshal(raw, &v)
	case "string":
		return text, nil
	case "bytes":
		return hex.DecodeString(text)
	case "date":
		m := isoDate.FindStringSubmatch(text)
		if m == nil {
			return nil, fmt.Errorf("unparseable date %q", text)
		}
		n := make([]int, 3)
		for i := range n {
			v, err := strconv.Atoi(m[i+1])
			if err != nil {
				return nil, err
			}
			n[i] = v
		}
		return vcvalue.Date{Year: n[0], Month: time.Month(n[1]), Day: n[2]}, nil
	case "timestamp":
		return timestamp(text)
	case "decimal":
		return vcvalue.ParseDecimal(text)
	case "uuid":
		return vcvalue.ParseUUID(text)
	case "array":
		if string(raw) == "[]" {
			return []any{}, nil
		}
	case "object":
		if string(raw) == "{}" {
			return vcvalue.Object{}, nil
		}
	}
	return nil, fmt.Errorf("teach expected() the %s vector %s", kind, raw)
}

func timestamp(text string) (any, error) {
	m := rfc3339ish.FindStringSubmatch(text)
	if m == nil {
		return nil, fmt.Errorf("unparseable timestamp %q", text)
	}
	n := make([]int, 6)
	for i := range n {
		v, err := strconv.Atoi(m[i+1])
		if err != nil {
			return nil, err
		}
		n[i] = v
	}
	nanos, err := strconv.Atoi((m[7] + "000000000")[:9])
	if err != nil {
		return nil, err
	}
	return time.Date(n[0], time.Month(n[1]), n[2], n[3], n[4], n[5], nanos, time.UTC), nil
}

func sameValue(got, want any) bool {
	if want, ok := want.(time.Time); ok {
		got, ok := got.(time.Time)
		return ok && got.Equal(want)
	}
	return reflect.DeepEqual(got, want)
}

func TestSharedValueConformance(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/value-conformance.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Vectors []struct {
			Name, Kind, Transport string
			Value                 json.RawMessage
			GoReencode            string `json:"go_reencode"`
		}
		Normalized []struct {
			Name, Kind, Transport, Reencode string
			Value                           json.RawMessage
			ReencodeValue                   json.RawMessage `json:"reencode_value"`
		}
		Malformed           []struct{ Name, Transport string }
		CiphertextMalformed []struct{ Name, Transport string } `json:"ciphertext_malformed"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, row := range corpus.Vectors {
		t.Run(row.Name, func(t *testing.T) {
			raw, err := hex.DecodeString(row.Transport)
			if err != nil {
				t.Fatal(err)
			}
			value, err := Unmarshal(raw)
			if err != nil {
				t.Fatal(err)
			}
			expect, err := expected(row.Kind, row.Value)
			if err != nil {
				t.Fatal(err)
			}
			if !sameValue(value, expect) {
				t.Fatalf("decoded %#v, want %#v", value, expect)
			}
			want := row.Transport
			if row.GoReencode != "" {
				want = row.GoReencode
			}
			// Encode the decoded value and, independently, the expected one.
			for _, v := range []any{value, expect} {
				encoded, err := Marshal(v)
				if err != nil {
					t.Fatal(err)
				}
				if hex.EncodeToString(encoded) != want {
					t.Fatalf("got %x, want %s (%#v)", encoded, want, v)
				}
			}
		})
	}
	// A normalized vector reads, and writes back as its canonical bytes:
	// from the decoded value, and from either spelling built independently.
	if len(corpus.Normalized) == 0 {
		t.Fatal("the corpus has no normalized vectors")
	}
	for _, row := range corpus.Normalized {
		t.Run(row.Name, func(t *testing.T) {
			raw, err := hex.DecodeString(row.Transport)
			if err != nil {
				t.Fatal(err)
			}
			value, err := Unmarshal(raw)
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := expected(row.Kind, row.ReencodeValue)
			if err != nil {
				t.Fatal(err)
			}
			if !sameValue(value, canonical) {
				t.Fatalf("decoded %#v, want %#v", value, canonical)
			}
			given, err := expected(row.Kind, row.Value)
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range []any{value, canonical, given} {
				encoded, err := Marshal(v)
				if err != nil {
					t.Fatal(err)
				}
				if hex.EncodeToString(encoded) != row.Reencode {
					t.Fatalf("got %x, want %s (%#v)", encoded, row.Reencode, v)
				}
			}
		})
	}
	for _, row := range corpus.Malformed {
		t.Run(row.Name, func(t *testing.T) {
			raw, err := hex.DecodeString(row.Transport)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Unmarshal(raw); err != ErrMalformed {
				t.Fatalf("got %v, want ErrMalformed", err)
			}
		})
	}
	if len(corpus.CiphertextMalformed) == 0 {
		t.Fatal("the corpus has no malformed ciphertexts")
	}
	for _, row := range corpus.CiphertextMalformed {
		t.Run(row.Name, func(t *testing.T) {
			raw, err := hex.DecodeString(row.Transport)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := UnmarshalCipherText(VCValueLeaves(), raw); err != ErrMalformed {
				t.Fatalf("got %v, want ErrMalformed", err)
			}
		})
	}
}
