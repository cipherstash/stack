package vcffi

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// typedNullAnswers pins each FixedType's typed null: the cross-language
// bytes the Rust codec writes for the same type (vitaminc-aead's leaf
// tests), beside a value of the type, which must be as long.
var typedNullAnswers = []struct {
	t       vcvalue.FixedType
	hex     string
	present any
}{
	{vcvalue.TypeInt8, "150c", int8(-1)},
	{vcvalue.TypeInt16, "150e00", int16(-1)},
	{vcvalue.TypeInt32, "1504000000", int32(-1)},
	{vcvalue.TypeInt64, "1505" + zeros(7), int64(-1)},
	{vcvalue.TypeInt128, "1510" + zeros(15), vcvalue.Int128{1}},
	{vcvalue.TypeUint8, "150d", uint8(1)},
	{vcvalue.TypeUint16, "150f00", uint16(1)},
	{vcvalue.TypeUint32, "1506000000", uint32(1)},
	{vcvalue.TypeUint64, "1507" + zeros(7), uint64(1)},
	{vcvalue.TypeUint128, "1511" + zeros(15), vcvalue.Uint128{1}},
	{vcvalue.TypeFloat32, "1508000000", float32(1.5)},
	{vcvalue.TypeFloat64, "1509" + zeros(7), 1.5},
	{vcvalue.TypeDate, "1512000000", vcvalue.Date{Year: 1999, Month: 12, Day: 31}},
	{vcvalue.TypeTimestamp, "1513" + zeros(11), time.Unix(1_700_000_000, 5).UTC()},
	{vcvalue.TypeDecimal, "1514" + zeros(15), vcvalue.Decimal{Scale: 2, Coefficient: [12]byte{150}}},
	{vcvalue.TypeUUID, "15f305000b" + zeros(15), vcvalue.UUID{0xAB}},
}

func zeros(n int) string { return hex.EncodeToString(make([]byte, n)) }

func TestTypedNullKnownAnswers(t *testing.T) {
	for _, row := range typedNullAnswers {
		t.Run(fmt.Sprint(row.t), func(t *testing.T) {
			got, err := Marshal(vcvalue.TypedNull{Type: row.t})
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(got) != row.hex {
				t.Fatalf("got %x, want %s", got, row.hex)
			}
			present, err := Marshal(row.present)
			if err != nil {
				t.Fatal(err)
			}
			// A frame gives bytes a length prefix; a typed null of a UUID
			// has none, because its sealed leaf has none.
			want := len(present)
			if row.t == vcvalue.TypeUUID {
				want -= 4
			}
			if len(got) != want {
				t.Fatalf("typed null is %d bytes, a value %d", len(got), want)
			}
			// It reads back as nil, like every null, and writes back as one.
			v, err := Unmarshal(got)
			if err != nil || v != nil {
				t.Fatalf("decoded %#v, %v", v, err)
			}
		})
	}
	if len(typedNullAnswers) != int(vcvalue.TypeUUID) {
		t.Fatalf("pinned %d of %d types", len(typedNullAnswers), vcvalue.TypeUUID)
	}
}

func TestAnInvalidFixedTypeFailsTheEncode(t *testing.T) {
	for _, ft := range []vcvalue.FixedType{0, vcvalue.TypeUUID + 1, 255} {
		if _, err := Marshal(vcvalue.TypedNull{Type: ft}); !errors.Is(err, vcvalue.ErrInvalidFixedType) {
			t.Fatalf("%v: got %v", ft, err)
		}
	}
}

type selfEncoded int32

func (s selfEncoded) EncryptValue(enc Encoder) error {
	enc.String("custom")
	return nil
}

// An Encryptable with a pointer receiver: only *ptrEncoded implements it.
type ptrEncoded int32

func (p *ptrEncoded) EncryptValue(enc Encoder) error {
	enc.String("custom")
	return nil
}

// A pointer type that points at itself never reaches a non-pointer.
type selfPointer *selfPointer

// A nil pointer to a fixed-width type is a typed null, the Go side of
// Rust's Option<T>; a nil with no fixed-width type to go by is the plain
// null. Each case is encoded twice, since the second encode reads the
// per-type cache.
func TestANilPointerIsATypedNullWhenItsTypeIsFixedWidth(t *testing.T) {
	type age int32
	var missing *int32
	cases := []struct {
		name string
		v    any
		want string
	}{
		{"*int8", (*int8)(nil), "150c"},
		{"*int16", (*int16)(nil), "150e00"},
		{"*int32", (*int32)(nil), "1504000000"},
		{"*int64", (*int64)(nil), "1505" + zeros(7)},
		{"*int", (*int)(nil), "1505" + zeros(7)},
		{"*uint8", (*uint8)(nil), "150d"},
		{"*uint16", (*uint16)(nil), "150f00"},
		{"*uint32", (*uint32)(nil), "1506000000"},
		{"*uint64", (*uint64)(nil), "1507" + zeros(7)},
		{"*uint", (*uint)(nil), "1507" + zeros(7)},
		{"*float32", (*float32)(nil), "1508000000"},
		{"*float64", (*float64)(nil), "1509" + zeros(7)},
		{"*time.Time", (*time.Time)(nil), "1513" + zeros(11)},
		{"*vcvalue.Date", (*vcvalue.Date)(nil), "1512000000"},
		{"*vcvalue.Timestamp", (*vcvalue.Timestamp)(nil), "1513" + zeros(11)},
		{"*vcvalue.Decimal", (*vcvalue.Decimal)(nil), "1514" + zeros(15)},
		{"*vcvalue.UUID", (*vcvalue.UUID)(nil), "15f305000b" + zeros(15)},
		{"*vcvalue.Int128", (*vcvalue.Int128)(nil), "1510" + zeros(15)},
		{"*vcvalue.Uint128", (*vcvalue.Uint128)(nil), "1511" + zeros(15)},
		{"named *age", (*age)(nil), "1504000000"},
		{"**int32", (**int32)(nil), "1504000000"},
		{"&(nil *int32)", &missing, "1504000000"},
		// No fixed width: the plain null.
		{"*bool", (*bool)(nil), "00"},
		{"*string", (*string)(nil), "00"},
		{"*[]byte", (*[]byte)(nil), "00"},
		{"*[16]byte", (*[16]byte)(nil), "00"},
		{"*struct", (*struct{ A int32 })(nil), "00"},
		{"*Encryptable", (*selfEncoded)(nil), "00"},
		{"**Encryptable", (**selfEncoded)(nil), "00"},
		{"*pointer-receiver Encryptable", (*ptrEncoded)(nil), "00"},
		{"**pointer-receiver Encryptable", (**ptrEncoded)(nil), "00"},
		{"*any", (*any)(nil), "00"},
		{"self-pointing type", selfPointer(nil), "00"},
		{"nil", nil, "00"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for range 2 {
				got, err := Marshal(c.v)
				if err != nil {
					t.Fatal(err)
				}
				if hex.EncodeToString(got) != c.want {
					t.Fatalf("got %x, want %s", got, c.want)
				}
			}
		})
	}
}

// An Encryptable that always writes one value of one fixed-width type:
// a FixedWidth, the Go side of Rust's Encrypt::FIXED.
type money struct{ cents int64 }

func (m money) EncryptValue(enc Encoder) error {
	enc.Int64(m.cents)
	return nil
}

func (money) FixedType() vcvalue.FixedType { return vcvalue.TypeInt64 }

// The same, declared on the pointer.
type ptrMoney struct{ cents int64 }

func (m *ptrMoney) EncryptValue(enc Encoder) error {
	enc.Int64(m.cents)
	return nil
}

func (*ptrMoney) FixedType() vcvalue.FixedType { return vcvalue.TypeInt64 }

// A FixedWidth that declares a type that is not one.
type badWidth struct{}

func (badWidth) EncryptValue(enc Encoder) error {
	enc.String("custom")
	return nil
}

func (badWidth) FixedType() vcvalue.FixedType { return 0 }

func TestANilPointerToAFixedWidthEncryptableIsATypedNullOfItsType(t *testing.T) {
	want := "1505" + zeros(7)
	for _, c := range []struct {
		name string
		v    any
	}{
		{"*money", (*money)(nil)},
		{"**money", (**money)(nil)},
		{"*ptrMoney", (*ptrMoney)(nil)},
		{"**ptrMoney", (**ptrMoney)(nil)},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := Marshal(c.v)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(got) != want {
				t.Fatalf("got %x, want %s", got, want)
			}
		})
	}
	// A present value is as long, and still written by EncryptValue.
	present, err := Marshal(&money{cents: 150})
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(present) != "059600000000000000" {
		t.Fatalf("present: got %x", present)
	}
	// Through a struct field, where a nil would otherwise show by length.
	type order struct{ Refund *money }
	absent, err := Marshal(order{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(absent, []byte{tagTypedNull, tagInt64, 0, 0, 0, 0, 0, 0, 0}) {
		t.Fatalf("absent: %x", absent)
	}
	// A declared type that is not a fixed-width type fails the encode, and
	// never writes the plain null in its place. A present value is not
	// asked.
	if _, err := Marshal((*badWidth)(nil)); !errors.Is(err, vcvalue.ErrInvalidFixedType) {
		t.Fatalf("invalid declared type: got %v", err)
	}
	if _, err := Marshal(badWidth{}); err != nil {
		t.Fatalf("present: %v", err)
	}
}

func TestAStructsNilFieldsAreTypedNulls(t *testing.T) {
	type person struct {
		Name string
		Born *vcvalue.Date
		Age  *int32
		Tags []string
		Any  any
	}
	got, err := Marshal(person{Name: "Ada"})
	if err != nil {
		t.Fatal(err)
	}
	v, err := Unmarshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range v.(vcvalue.Object) {
		if (f.Key == "Born" || f.Key == "Age" || f.Key == "Any") && f.Value != nil {
			t.Fatalf("%s decoded %#v", f.Key, f.Value)
		}
	}
	// Born and Age carry their padding; Any has no type to go by, and a nil
	// slice is an empty sequence, as it always was.
	if !bytes.Contains(got, []byte{tagTypedNull, tagDate, 0, 0, 0}) ||
		!bytes.Contains(got, []byte{tagTypedNull, tagInt32, 0, 0, 0}) {
		t.Fatalf("no typed nulls in %x", got)
	}
}

// The explicit channel, for an Encryptable that knows the type.
type maybeAge struct{ v *int32 }

func (m maybeAge) EncryptValue(enc Encoder) error {
	if m.v == nil {
		enc.TypedNull(vcvalue.TypeInt32)
	} else {
		enc.Int32(*m.v)
	}
	return nil
}

func TestTheTypedNullChannel(t *testing.T) {
	got, err := Marshal(maybeAge{})
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != "1504000000" {
		t.Fatalf("got %x", got)
	}
	// It completes exactly one slot, like every terminal.
	enc := func(e Encoder) error {
		s := e.Seq()
		s.Elem().TypedNull(vcvalue.TypeUint8)
		s.Elem().Null()
		return s.End()
	}
	got, err = Marshal(encryptableFunc(enc))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != "f002000000150d00" {
		t.Fatalf("got %x", got)
	}
}

type encryptableFunc func(Encoder) error

func (f encryptableFunc) EncryptValue(e Encoder) error { return f(e) }

// Every absence has one encoding: the decoder refuses anything a writer
// does not write. The shared corpus pins the same refusals for every
// language; these are the Go-specific edges around them.
func TestATypedNullIsReadStrictly(t *testing.T) {
	refused := []string{
		"15", "1504", "15040000", "1504000001", "150400000000",
		"1500", "1502", "150a", "150b" + zeros(15), "1515040000",
		"15f3", "15f303", "15f30301", "15f3030304" + zeros(3), "15f3030409" + zeros(7),
		"15f3050104" + zeros(3), "15f3c8000a", "15f3c8000b" + zeros(15),
		"f0010000001502",
	}
	for _, h := range refused {
		raw, _ := hex.DecodeString(h)
		if _, err := Unmarshal(raw); err != ErrMalformed {
			t.Fatalf("%s: got %v, want ErrMalformed", h, err)
		}
	}
	accepted := []string{
		"15f3030004000000",                    // seconds over an int32
		"15f3030210" + zeros(15),              // microseconds over an int128
		"15f3c8ff09" + zeros(7),               // an unknown id, any parameter, over a float64
		"f0010000001506000000",                // inside an array
		"f2150c",                              // as passthrough
		"f101000000010000006115120000" + "00", // as an object value
	}
	for _, h := range accepted {
		raw, _ := hex.DecodeString(h)
		if _, err := Unmarshal(raw); err != nil {
			t.Fatalf("%s: %v", h, err)
		}
	}
}

// Every fixed-width marker and kind writes its values with the header its
// typed null carries, so the one table cannot pad a type as something it is
// not. A marker added without a sample here fails the test.
func TestEveryFixedTypeIsWrittenWithItsTypedNullsHeader(t *testing.T) {
	samples := map[reflect.Type]any{
		reflect.TypeOf(vcvalue.Int128{}):    vcvalue.Int128{1},
		reflect.TypeOf(vcvalue.Uint128{}):   vcvalue.Uint128{1},
		reflect.TypeOf(vcvalue.Date{}):      vcvalue.Date{Year: 2000, Month: 1, Day: 1},
		reflect.TypeOf(time.Time{}):         time.Unix(7, 0),
		reflect.TypeOf(vcvalue.Timestamp{}): vcvalue.Timestamp{Seconds: 7},
		reflect.TypeOf(vcvalue.Decimal{}):   vcvalue.Decimal{Scale: 1},
		reflect.TypeOf(vcvalue.UUID{}):      vcvalue.UUID{1},
	}
	check := func(name string, ft vcvalue.FixedType, sample any) {
		null, err := Marshal(vcvalue.TypedNull{Type: ft})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		value, err := Marshal(sample)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		// The typed null's header (after its tag) begins the value's.
		header := null[1:]
		for len(header) > 0 && header[len(header)-1] == 0 {
			header = header[:len(header)-1]
		}
		if !bytes.HasPrefix(value, header) {
			t.Fatalf("%s: value %x does not start with its typed null's header %x", name, value, header)
		}
	}
	// Every sample is of a fixed-width marker, so a marker that loses its
	// fixed type is caught, not skipped.
	for typ := range samples {
		if markers[typ].fixed == 0 {
			t.Fatalf("%v has a sample but no typed null", typ)
		}
	}
	for typ, m := range markers {
		if m.fixed == 0 {
			continue
		}
		sample, ok := samples[typ]
		if !ok {
			t.Fatalf("no sample for the fixed-width marker %v", typ)
		}
		check(typ.String(), m.fixed, sample)
	}
	for kind, n := range numericKinds {
		check(kind.String(), n.fixed, reflect.Zero(kindTypes[kind]).Interface())
	}
}

var kindTypes = map[reflect.Kind]reflect.Type{
	reflect.Int8: reflect.TypeOf(int8(0)), reflect.Int16: reflect.TypeOf(int16(0)),
	reflect.Int32: reflect.TypeOf(int32(0)), reflect.Int: reflect.TypeOf(0),
	reflect.Int64: reflect.TypeOf(int64(0)), reflect.Uint8: reflect.TypeOf(uint8(0)),
	reflect.Uint16: reflect.TypeOf(uint16(0)), reflect.Uint32: reflect.TypeOf(uint32(0)),
	reflect.Uint: reflect.TypeOf(uint(0)), reflect.Uint64: reflect.TypeOf(uint64(0)),
	reflect.Uintptr: reflect.TypeOf(uintptr(0)), reflect.Float32: reflect.TypeOf(float32(0)),
	reflect.Float64: reflect.TypeOf(float64(0)),
}
