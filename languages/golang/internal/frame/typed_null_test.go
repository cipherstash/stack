package frame

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
	"time"
)

// typedNullAnswers lists the typed null of each fixed-width type. The
// encoder writes a typed null for a nil pointer to the type. The Rust codec
// writes the same bytes for the same type, and the leaf tests of
// vitaminc-aead check them. Each row also has a value of the type. The typed
// null must be as long as the encoded value.
var typedNullAnswers = []struct {
	name    string
	nilPtr  any
	hex     string
	present any
}{
	{"int8", (*int8)(nil), "150c", int8(-1)},
	{"int16", (*int16)(nil), "150e00", int16(-1)},
	{"int32", (*int32)(nil), "1504000000", int32(-1)},
	{"int64", (*int64)(nil), "1505" + zeros(7), int64(-1)},
	{"int128", (*Int128)(nil), "1510" + zeros(15), Int128{1}},
	{"uint8", (*uint8)(nil), "150d", uint8(1)},
	{"uint16", (*uint16)(nil), "150f00", uint16(1)},
	{"uint32", (*uint32)(nil), "1506000000", uint32(1)},
	{"uint64", (*uint64)(nil), "1507" + zeros(7), uint64(1)},
	{"uint128", (*Uint128)(nil), "1511" + zeros(15), Uint128{1}},
	{"float32", (*float32)(nil), "1508000000", float32(1.5)},
	{"float64", (*float64)(nil), "1509" + zeros(7), 1.5},
	{"date", (*Date)(nil), "1512000000", Date{Year: 1999, Month: 12, Day: 31}},
	{"timestamp", (*time.Time)(nil), "1513" + zeros(11), time.Unix(1_700_000_000, 5).UTC()},
	{"decimal", (*Decimal)(nil), "1514" + zeros(15), Decimal{Scale: 2, Coefficient: [12]byte{150}}},
	{"uuid", (*UUID)(nil), "15f305000b" + zeros(15), UUID{0xAB}},
}

func zeros(n int) string { return hex.EncodeToString(make([]byte, n)) }

func TestTypedNullKnownAnswers(t *testing.T) {
	for _, row := range typedNullAnswers {
		t.Run(row.name, func(t *testing.T) {
			got, err := Marshal(row.nilPtr)
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
			// A frame writes bytes with a length prefix. The typed null of a
			// UUID has no length prefix, because the sealed leaf of a UUID
			// has none.
			want := len(present)
			if row.name == "uuid" {
				want -= 4
			}
			if len(got) != want {
				t.Fatalf("typed null is %d bytes, a value %d", len(got), want)
			}
			// The typed null reads back as nil, as every null does. The nil
			// is then written as a plain null.
			v, err := Unmarshal(got)
			if err != nil || v != nil {
				t.Fatalf("decoded %#v, %v", v, err)
			}
		})
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

// A nil pointer to a fixed-width type is written as a typed null, as Rust
// writes an Option<T>. A nil whose type has no fixed width is written as the
// plain null. Each case is encoded twice, because the second encode reads
// the cache for the type.
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
		{"*Date", (*Date)(nil), "1512000000"},
		{"*Timestamp", (*Timestamp)(nil), "1513" + zeros(11)},
		{"*Decimal", (*Decimal)(nil), "1514" + zeros(15)},
		{"*UUID", (*UUID)(nil), "15f305000b" + zeros(15)},
		{"*Int128", (*Int128)(nil), "1510" + zeros(15)},
		{"*Uint128", (*Uint128)(nil), "1511" + zeros(15)},
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

func TestAStructsNilFieldsAreTypedNulls(t *testing.T) {
	type person struct {
		Name string
		Born *Date
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
	for _, f := range v.(Object) {
		if (f.Key == "Born" || f.Key == "Age" || f.Key == "Any") && f.Value != nil {
			t.Fatalf("%s decoded %#v", f.Key, f.Value)
		}
	}
	// Born and Age are written as typed nulls, with their padding. Any has
	// no type, so it is written as the plain null. A nil slice is written as
	// an empty sequence.
	if !bytes.Contains(got, []byte{tagTypedNull, tagDate, 0, 0, 0}) ||
		!bytes.Contains(got, []byte{tagTypedNull, tagInt32, 0, 0, 0}) {
		t.Fatalf("no typed nulls in %x", got)
	}
}

// An Encryptable in this package calls the method that Encode uses to write
// a typed null.
type maybeAge struct{ v *int32 }

func (m maybeAge) EncryptValue(enc Encoder) error {
	if m.v == nil {
		enc.typedNull(nullOf(tagInt32))
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
	// The typed null counts as exactly one value in its slot, as every
	// scalar does.
	enc := func(e Encoder) error {
		s := e.Seq()
		s.Elem().typedNull(nullOf(tagUint8))
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

// Every absent value has one encoding, so the decoder refuses any bytes that
// no encoder writes. The shared corpus tests the same refusals in every
// language. The cases below are specific to Go.
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

// For every fixed-width type in the markers table and every numeric kind, a
// value starts with the header that its typed null has. The table therefore
// cannot pad a type as if it were a different type. The test fails for a
// type that is added to the markers table with no sample here.
func TestEveryFixedTypeIsWrittenWithItsTypedNullsHeader(t *testing.T) {
	samples := map[reflect.Type]any{
		reflect.TypeOf(Int128{}):    Int128{1},
		reflect.TypeOf(Uint128{}):   Uint128{1},
		reflect.TypeOf(Date{}):      Date{Year: 2000, Month: 1, Day: 1},
		reflect.TypeOf(time.Time{}): time.Unix(7, 0),
		reflect.TypeOf(Timestamp{}): Timestamp{Seconds: 7},
		reflect.TypeOf(Decimal{}):   Decimal{Scale: 1},
		reflect.TypeOf(UUID{}):      UUID{1},
	}
	check := func(name string, null []byte, sample any) {
		value, err := Marshal(sample)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		// The header of the typed null, after its tag, starts the encoded
		// value.
		header := null[1:]
		for len(header) > 0 && header[len(header)-1] == 0 {
			header = header[:len(header)-1]
		}
		if !bytes.HasPrefix(value, header) {
			t.Fatalf("%s: value %x does not start with its typed null's header %x", name, value, header)
		}
	}
	// Every sample is of a fixed-width type in the markers table. The test
	// therefore fails for a type that stops being fixed width, and does not
	// skip it.
	for typ := range samples {
		if markers[typ].null == nil {
			t.Fatalf("%v has a sample but no typed null", typ)
		}
	}
	for typ, m := range markers {
		if m.null == nil {
			continue
		}
		sample, ok := samples[typ]
		if !ok {
			t.Fatalf("no sample for the fixed-width marker %v", typ)
		}
		check(typ.String(), m.null, sample)
	}
	for kind, n := range numericKinds {
		check(kind.String(), n.null, reflect.Zero(kindTypes[kind]).Interface())
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
