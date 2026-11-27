package vcffi

import (
	"encoding/hex"
	"errors"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestScalarHostEncoding(t *testing.T) {
	signed, err := vcvalue.ParseInt128("-170141183460469231731687303715884105728")
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := vcvalue.ParseUint128("340282366920938463463374607431768211455")
	if err != nil {
		t.Fatal(err)
	}
	decimal, err := vcvalue.ParseDecimal("1.50")
	if err != nil {
		t.Fatal(err)
	}
	uuid, err := vcvalue.ParseUUID("123e4567-e89b-12d3-a456-426614174000")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		value any
		wire  string
	}{
		{int8(-128), "0c80"}, {uint8(255), "0dff"}, {int16(-32768), "0e0080"}, {uint16(65535), "0fffff"},
		{signed, "1000000000000000000000000000000080"}, {unsigned, "11ffffffffffffffffffffffffffffffff"},
		{vcvalue.Date{Year: 1, Month: 1, Day: 1}, "1201000000"},
		{time.Unix(0, 123456789).UTC(), "13000000000000000015cd5b07"},
		{decimal, "1400000200960000000000000000000000"},
		// The 0xF3 envelope: a logical type with no shorthand tag.
		{uuid, "f305000b10000000123e4567e89b12d3a456426614174000"},
		{vcvalue.Tagged{ID: 200, Param: 9, V: uint32(34)}, "f3c8090622000000"},
		{vcvalue.Tagged{ID: 255, Param: 0, V: nil}, "f3ff0000"},
		{vcvalue.Tagged{ID: 6, Param: 1, V: "hi"}, "f306010a020000006869"},
	}
	for _, tc := range cases {
		encoded, err := Marshal(tc.value)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(encoded) != tc.wire {
			t.Fatalf("%T: %x != %s", tc.value, encoded, tc.wire)
		}
		decoded, err := Unmarshal(encoded)
		if err != nil || !reflect.DeepEqual(decoded, tc.value) {
			t.Fatalf("%T: got %#v: %v", tc.value, decoded, err)
		}
		// The intercept also applies through pointers, fields and interfaces.
		nested := struct{ Value any }{Value: &tc.value}
		if _, err := Marshal(nested); err != nil {
			t.Fatal(err)
		}
	}
}

func TestInvalidScalarHostEncoding(t *testing.T) {
	cases := []struct {
		value any
		err   error
	}{
		{vcvalue.Date{Year: 2023, Month: 2, Day: 29}, vcvalue.ErrInvalidDate},
		{vcvalue.Timestamp{Seconds: 0, Nanoseconds: 1000000000}, vcvalue.ErrInvalidTimestamp},
		{time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), vcvalue.ErrInvalidTimestamp},
		{time.Date(-9999, 1, 1, 0, 0, 0, 0, time.UTC), vcvalue.ErrInvalidTimestamp},
		{vcvalue.Decimal{Scale: 29}, vcvalue.ErrInvalidDecimal},
		// A tagged value must be a physical scalar under an unknown id.
		{vcvalue.Tagged{ID: 5, V: []byte{1}}, vcvalue.ErrInvalidTagged},
		{vcvalue.Tagged{ID: 0, V: int8(1)}, vcvalue.ErrInvalidTagged},
		{vcvalue.Tagged{ID: 200, V: []any{int8(1)}}, vcvalue.ErrInvalidTagged},
		{vcvalue.Tagged{ID: 200, V: time.Unix(0, 0)}, vcvalue.ErrInvalidTagged},
	}
	for _, tc := range cases {
		if _, err := Marshal(tc.value); !errors.Is(err, tc.err) {
			t.Fatalf("got %v, want %v", err, tc.err)
		}
	}
}

// The envelope's timestamp units decode to time.Time; the nanosecond unit
// has the shorthand tag and is refused in the envelope, as is every other
// envelope the corpus does not already pin.
func TestEnvelopeTimestampsDecodeToTime(t *testing.T) {
	for _, tc := range []struct {
		wire string
		want time.Time
	}{
		{"f30301057b00000000000000", time.Unix(0, 123_000_000).UTC()},                          // 123 ms
		{"f3030205c8ff ffffffffffff", time.Unix(0, -56_000).UTC()},                             // -56 µs, as an i64
		{"f303000c0a", time.Unix(10, 0).UTC()},                                                 // 10 s, as an i8
		{"f3030210" + "00f1" + "ffffffffffffffffffffffffffff", time.Unix(0, -3_840_000).UTC()}, // -3840 µs, as an i128
		{"f3030005e0d3f2ff3a000000", time.Unix(253402207200, 0).UTC()},                         // the last second the wire admits, as an i64
		{"f30300051fb9060fa8ffffff", time.Unix(-377705023201, 0).UTC()},                        // the first second the wire admits
	} {
		t.Run(tc.wire, func(t *testing.T) {
			raw, err := hex.DecodeString(strings.ReplaceAll(tc.wire, " ", ""))
			if err != nil {
				t.Fatal(err)
			}
			got, err := Unmarshal(raw)
			if err != nil {
				t.Fatal(err)
			}
			if ts, ok := got.(time.Time); !ok || !ts.Equal(tc.want) {
				t.Fatalf("got %#v, want %v", got, tc.want)
			}
		})
	}
	for _, wire := range []string{
		"f3030305" + "0000000000000000",                 // nanoseconds: the shorthand tag exists
		"f3030405" + "0000000000000000",                 // no such unit
		"f303010a" + "00000000",                         // a count that is not an int
		"f3030010" + "0000000000000000000000000000ff7f", // out of the wire's range
		"f3030005" + "e1d3f2ff3a000000",                 // one second past the wire's range, as an i64
		"f3030005" + "1eb9060fa8ffffff",                 // one second before it
		"f3030107" + "18fcffffffffffff",                 // 2^64 - 1000 ms, a u64 above the i64 range
	} {
		t.Run(wire, func(t *testing.T) {
			raw, err := hex.DecodeString(wire)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Unmarshal(raw); err != ErrMalformed {
				t.Fatalf("got %v, want ErrMalformed", err)
			}
		})
	}
}

// Every integer width is a valid count for an envelope timestamp.
func TestEnvelopeTimestampAcceptsEveryIntegerWidth(t *testing.T) {
	i128, err := vcvalue.ParseInt128("1")
	if err != nil {
		t.Fatal(err)
	}
	u128, err := vcvalue.ParseUint128("1")
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{int8(1), int16(1), int32(1), int64(1), uint8(1), uint16(1), uint32(1), uint64(1), i128, u128} {
		got, err := envelopeTimestamp(unitSeconds, value)
		ts, ok := got.(time.Time)
		if err != nil || !ok || !ts.Equal(time.Unix(1, 0).UTC()) {
			t.Errorf("%T: got %#v, err %v", value, got, err)
		}
	}
}

// A decimal negative zero built as a struct literal is written without its
// sign: Go never writes the sign bit of a zero (ADR 0001).
func TestDecimalNegativeZeroIsWrittenUnsigned(t *testing.T) {
	encoded, err := Marshal(vcvalue.Decimal{Negative: true, Scale: 2})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(encoded), "1400000200000000000000000000000000"; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

// Every physical scalar travels under an unknown id and reads back as the
// same Tagged value.
func TestTaggedRoundTripsEveryPhysicalScalar(t *testing.T) {
	i128, err := vcvalue.ParseInt128("-1")
	if err != nil {
		t.Fatal(err)
	}
	u128, err := vcvalue.ParseUint128("1")
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{nil, true, int8(-1), uint8(1), int16(-1), uint16(1), int32(-1), uint32(1), int64(-1), uint64(1), i128, u128, float32(1.5), float64(1.5), "text", []byte{1}} {
		want := vcvalue.Tagged{ID: 200, Param: 9, V: value}
		wire, err := Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Unmarshal(wire)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%T: got %#v, err %v", value, got, err)
		}
	}
}

// A Go int or uint in a Tagged value is written as Int64 or UInt64, as Encode
// writes it everywhere else, and reads back at that width.
func TestTaggedWritesIntAndUintAtSixtyFourBits(t *testing.T) {
	for _, tc := range []struct {
		value any
		wire  string
		back  any
	}{
		{-34, "f3c80905deffffffffffffff", int64(-34)},
		{uint(34), "f3c809072200000000000000", uint64(34)},
	} {
		wire, err := Marshal(vcvalue.Tagged{ID: 200, Param: 9, V: tc.value})
		if err != nil {
			t.Fatalf("%T: %v", tc.value, err)
		}
		if got := hex.EncodeToString(wire); got != tc.wire {
			t.Errorf("%T: got %s, want %s", tc.value, got, tc.wire)
		}
		got, err := Unmarshal(wire)
		if want := (vcvalue.Tagged{ID: 200, Param: 9, V: tc.back}); err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%T: got %#v, err %v", tc.value, got, err)
		}
	}
}
