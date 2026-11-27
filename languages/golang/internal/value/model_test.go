package vcvalue_test

import (
	"database/sql"
	"database/sql/driver"
	"math"
	"reflect"
	"testing"

	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// Every sealed leaf type must survive the database column round trip:
// Value() then Scan() back into the same type.
func TestSealedLeafTypesScanValueRoundTrip(t *testing.T) {
	roundTrip := func(t *testing.T, value driver.Valuer, scan sql.Scanner, got func() []byte, want []byte) {
		t.Helper()
		v, err := value.Value()
		if err != nil {
			t.Fatalf("Value: %v", err)
		}
		if err := scan.Scan(v); err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if !reflect.DeepEqual(got(), want) {
			t.Fatalf("got %#v, want %#v", got(), want)
		}
	}

	leaf := []byte{1, 2, 3}
	var s vcvalue.Sealed
	roundTrip(t, vcvalue.Sealed(leaf), &s, func() []byte { return []byte(s) }, leaf)
	var es vcvalue.SealedEmptySeq
	roundTrip(t, vcvalue.SealedEmptySeq(leaf), &es, func() []byte { return []byte(es) }, leaf)
	var em vcvalue.SealedEmptyMap
	roundTrip(t, vcvalue.SealedEmptyMap(leaf), &em, func() []byte { return []byte(em) }, leaf)

	// Non-byte sources are rejected.
	if err := (&es).Scan("not bytes"); err == nil {
		t.Fatal("scanning a string into SealedEmptySeq must fail")
	}
}

// Every integer kind the encoder accepts must also bind through the driver:
// Plain{V: user.ID} with ID int encodes fine, so Value() must not reject it.
func TestPlainValueBindsEveryEncodableIntegerKind(t *testing.T) {
	cases := []struct {
		in   any
		want driver.Value
	}{
		{int(7), int64(7)},
		{int8(-8), int64(-8)},
		{int16(-16), int64(-16)},
		{int32(-32), int64(-32)},
		{int64(-64), int64(-64)},
		{uint8(8), int64(8)},
		{uint16(16), int64(16)},
		{uint32(32), int64(32)},
		{uint(64), int64(64)},
		{uint64(64), int64(64)},
	}
	for _, c := range cases {
		got, err := vcvalue.Plain{V: c.in}.Value()
		if err != nil {
			t.Fatalf("Value(%T): %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("Value(%T): got %#v, want %#v", c.in, got, c.want)
		}
	}

	// The unsigned kinds that can exceed int64 must fail closed.
	if _, err := (vcvalue.Plain{V: uint64(math.MaxInt64) + 1}).Value(); err == nil {
		t.Fatal("uint64 above MaxInt64 must not bind")
	}
	if uint64(math.MaxUint) > math.MaxInt64 { // uint is 32-bit on GOARCH=386
		if _, err := (vcvalue.Plain{V: uint(math.MaxUint)}).Value(); err == nil {
			t.Fatal("uint above MaxInt64 must not bind")
		}
	}
}

// Plain.Value's driver conversions: width-narrowing, the uint64 overflow
// error, and the container-has-no-column error.
func TestPlainValueConversions(t *testing.T) {
	cases := []struct {
		in   any
		want driver.Value
	}{
		{nil, nil},
		{true, true},
		{int64(7), int64(7)},
		{"s", "s"},
		{[]byte{1}, []byte{1}},
		{int32(-3), int64(-3)},
		{uint32(9), int64(9)},
		{float32(0.5), float64(0.5)},
		{float64(1.5), float64(1.5)},
		{uint64(11), int64(11)},
	}
	for _, c := range cases {
		got, err := vcvalue.Plain{V: c.in}.Value()
		if err != nil {
			t.Fatalf("Value(%#v): %v", c.in, err)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Fatalf("Value(%#v) = %#v, want %#v", c.in, got, c.want)
		}
	}

	if _, err := (vcvalue.Plain{V: uint64(math.MaxInt64) + 1}).Value(); err == nil {
		t.Fatal("uint64 above MaxInt64 must not silently truncate")
	}
	if _, err := (vcvalue.Plain{V: []any{int64(1)}}).Value(); err == nil {
		t.Fatal("a container passthrough has no single-column form")
	}
}

// The remaining Sealed.Scan arms: nil source and the non-byte error arm
// (the byte round trip is covered with the marker types above).
func TestSealedScanNilAndErrorArms(t *testing.T) {
	s := vcvalue.Sealed{1, 2, 3}
	if err := s.Scan(nil); err != nil {
		t.Fatalf("Scan(nil): %v", err)
	}
	if s != nil {
		t.Fatalf("Scan(nil) should clear the leaf, got %#v", s)
	}
	if err := s.Scan("not bytes"); err == nil {
		t.Fatal("scanning a string into Sealed must fail")
	}
}
