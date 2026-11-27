package encrypt_test

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/internal/frame"
)

// Each value type is written as the codec's value type of the same kind,
// byte for byte, and a decoded value comes back as the encrypt type, so a
// field of one needs no conversion either way.
func TestTheValueTypesCrossTheCodecAsThemselves(t *testing.T) {
	id, err := encrypt.ParseUUID("0190c6d2-3a4b-7c5d-8e9f-a0b1c2d3e4f5")
	if err != nil {
		t.Fatal(err)
	}
	big, err := encrypt.ParseInt128("-170141183460469231731687303715884105728")
	if err != nil {
		t.Fatal(err)
	}
	huge, err := encrypt.ParseUint128("340282366920938463463374607431768211455")
	if err != nil {
		t.Fatal(err)
	}
	amount, err := encrypt.ParseDecimal("-1234.5600")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		public, value any
	}{
		{encrypt.Date{Year: -44, Month: time.March, Day: 15}, frame.Date{Year: -44, Month: time.March, Day: 15}},
		{big, frame.Int128(big)},
		{huge, frame.Uint128(huge)},
		{amount, frame.Decimal(amount)},
		{id, frame.UUID(id)},
	} {
		got, err := frame.Marshal(c.public)
		if err != nil {
			t.Fatal(err)
		}
		want, err := frame.Marshal(c.value)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%T writes %x, the codec's type %x", c.public, got, want)
		}
		back, err := frame.Unmarshal(got)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(back, c.public) {
			t.Fatalf("%x decodes as %#v (%T), want %#v", got, back, back, c.public)
		}
	}
}

func TestTheValueTypesSpellThemselves(t *testing.T) {
	for _, c := range []struct{ got, want string }{
		{mustParse(t, encrypt.ParseInt128, "-17").String(), "-17"},
		{mustParse(t, encrypt.ParseUint128, "17").String(), "17"},
		{mustParse(t, encrypt.ParseDecimal, "-0.50").String(), "-0.50"},
		{mustParse(t, encrypt.ParseUUID, "0190C6D2-3A4B-7C5D-8E9F-A0B1C2D3E4F5").String(), "0190c6d2-3a4b-7c5d-8e9f-a0b1c2d3e4f5"},
	} {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
	if _, err := encrypt.ParseDecimal("NaN"); !errors.Is(err, encrypt.ErrNonFiniteDecimal) {
		t.Errorf("ParseDecimal(NaN): %v", err)
	}
	if !mustParse(t, encrypt.ParseDecimal, "0.000").IsZero() {
		t.Error("0.000 is not zero")
	}
	if (encrypt.Decimal{Scale: 29}).Validate() == nil {
		t.Error("a scale of 29 is valid")
	}
	if (encrypt.Date{Year: 2023, Month: time.February, Day: 29}).Validate() == nil {
		t.Error("2023-02-29 is valid")
	}
	for _, bad := range []string{"", "0190c6d2-3a4b-7c5d-8e9f", "0190c6d2x3a4b-7c5d-8e9f-a0b1c2d3e4f5"} {
		if _, err := encrypt.ParseUUID(bad); err == nil {
			t.Errorf("ParseUUID(%q) succeeded", bad)
		}
	}
}

func mustParse[T any](t *testing.T, parse func(string) (T, error), s string) T {
	t.Helper()
	v, err := parse(s)
	if err != nil {
		t.Fatalf("%q: %v", s, err)
	}
	return v
}

// writesWith is an Encryptable that writes itself with one Encoder method.
type writesWith func(encrypt.Encoder)

func (w writesWith) EncryptValue(enc encrypt.Encoder) error {
	w(enc)
	return nil
}

// Each Encoder method writes what the codec writes for a value of its type.
func TestEachEncoderMethodWritesItsType(t *testing.T) {
	when := time.Unix(1_700_000_000, 5).UTC()
	for _, c := range []struct {
		write writesWith
		want  any
	}{
		{func(e encrypt.Encoder) { e.Null() }, nil},
		{func(e encrypt.Encoder) { e.Bool(true) }, true},
		{func(e encrypt.Encoder) { e.Int8(-8) }, int8(-8)},
		{func(e encrypt.Encoder) { e.Int16(-16) }, int16(-16)},
		{func(e encrypt.Encoder) { e.Int32(-32) }, int32(-32)},
		{func(e encrypt.Encoder) { e.Int64(-64) }, int64(-64)},
		{func(e encrypt.Encoder) { e.Int128(encrypt.Int128{1}) }, encrypt.Int128{1}},
		{func(e encrypt.Encoder) { e.Uint8(8) }, uint8(8)},
		{func(e encrypt.Encoder) { e.Uint16(16) }, uint16(16)},
		{func(e encrypt.Encoder) { e.Uint32(32) }, uint32(32)},
		{func(e encrypt.Encoder) { e.Uint64(64) }, uint64(64)},
		{func(e encrypt.Encoder) { e.Uint128(encrypt.Uint128{1}) }, encrypt.Uint128{1}},
		{func(e encrypt.Encoder) { e.Float32(1.5) }, float32(1.5)},
		{func(e encrypt.Encoder) { e.Float64(2.5) }, 2.5},
		{func(e encrypt.Encoder) { e.String("text") }, "text"},
		{func(e encrypt.Encoder) { e.Bytes([]byte{1, 2}) }, []byte{1, 2}},
		{func(e encrypt.Encoder) { e.Date(encrypt.Date{Year: 2000, Month: 1, Day: 2}) }, encrypt.Date{Year: 2000, Month: 1, Day: 2}},
		{func(e encrypt.Encoder) { e.Timestamp(when) }, when},
		{func(e encrypt.Encoder) { e.Decimal(encrypt.Decimal{Scale: 1, Coefficient: [12]byte{15}}) }, encrypt.Decimal{Scale: 1, Coefficient: [12]byte{15}}},
		{func(e encrypt.Encoder) { e.UUID(encrypt.UUID{1}) }, encrypt.UUID{1}},
	} {
		got, err := frame.Marshal(c.write)
		if err != nil {
			t.Fatalf("%T: %v", c.want, err)
		}
		want, err := frame.Marshal(c.want)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%T: the Encoder writes %x, the value %x", c.want, got, want)
		}
	}
	// One value, exactly: none, or two, fails the encode, and so does a
	// value the codec refuses.
	for name, write := range map[string]writesWith{
		"no value":   func(encrypt.Encoder) {},
		"two values": func(e encrypt.Encoder) { e.Bool(true); e.Bool(false) },
		"bad UTF-8":  func(e encrypt.Encoder) { e.String(string([]byte{0xff})) },
		"no date":    func(e encrypt.Encoder) { e.Date(encrypt.Date{}) },
	} {
		if _, err := frame.Marshal(write); err == nil {
			t.Errorf("%s: the encode succeeded", name)
		}
	}
	// A nil pointer to an Encryptable is a null, and its method is not run.
	if got, err := frame.Marshal((*writesWith)(nil)); err != nil || !bytes.Equal(got, []byte{0}) {
		t.Errorf("a nil Encryptable writes %x, %v", got, err)
	}
}

// A date or a decimal has no storage form, and the refusal names the type
// the program used, not the codec's.
func TestAStorageRefusalNamesTheEncryptType(t *testing.T) {
	for _, c := range []struct {
		v    any
		name string
	}{
		{encrypt.Decimal{Scale: 2}, "encrypt.Decimal"},
		{struct{ When encrypt.Date }{}, "encrypt.Date"},
	} {
		_, err := frame.MarshalStorage(c.v)
		if !errors.Is(err, frame.ErrUnwritable) || !strings.Contains(err.Error(), c.name+" has no storage form") {
			t.Errorf("%T: %v; want a refusal naming %s", c.v, err, c.name)
		}
		if err != nil && strings.Contains(err.Error(), "frame.") {
			t.Errorf("%T: the refusal names the codec's type: %v", c.v, err)
		}
	}
}
