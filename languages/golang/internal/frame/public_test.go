package frame

import (
	"bytes"
	"errors"
	"maps"
	"reflect"
	"strings"
	"testing"
	"time"
)

// A caller's own types, each over a value type of this package. Package
// encrypt declares its value types in the same way.
type (
	pubDate struct {
		Year  int
		Month time.Month
		Day   int
	}
	pubInt128 [16]byte
	pubUUID   [16]byte
)

// pubEncryptable and pubEncoder stand for encrypt.Encryptable and
// encrypt.Encoder: an interface the codec cannot name, with an Encoder of
// its own.
type pubEncoder struct{ enc Encoder }

type pubEncryptable interface {
	EncryptValue(enc pubEncoder) error
}

type cents int64

func (c cents) EncryptValue(enc pubEncoder) error {
	enc.enc.Int64(int64(c) * 100)
	return nil
}

// publishForTest publishes the types above for one test, and puts the
// tables back as they were when it ends. The tables are global, so a test
// that calls it must not run in parallel.
func publishForTest(t *testing.T) {
	t.Helper()
	savedPublished, savedPublic, savedExternal := maps.Clone(published), maps.Clone(publicOf), external
	t.Cleanup(func() {
		published, publicOf, external = savedPublished, savedPublic, savedExternal
	})
	// Only one Encryptable is published at a time. The one in these tests
	// takes the place of the one in package encrypt. That interface takes an
	// Encoder type of its own.
	external.iface, external.call = nil, nil
	Publish[pubDate, Date]()
	Publish[pubInt128, Int128]()
	Publish[pubUUID, UUID]()
	PublishEncryptable(func(v pubEncryptable, enc Encoder) error {
		return v.EncryptValue(pubEncoder{enc: enc})
	})
}

func TestAPublishedTypeIsWrittenAndReadAsItsValueType(t *testing.T) {
	publishForTest(t)
	for _, c := range []struct {
		public, value any
	}{
		{pubDate{Year: 2024, Month: 2, Day: 29}, Date{Year: 2024, Month: 2, Day: 29}},
		{pubInt128{1, 2, 3}, Int128{1, 2, 3}},
		{pubUUID{0xAB, 15: 1}, UUID{0xAB, 15: 1}},
	} {
		got, err := Marshal(c.public)
		if err != nil {
			t.Fatal(err)
		}
		want, err := Marshal(c.value)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%T writes %x, its value type %x", c.public, got, want)
		}
		back, err := Unmarshal(got)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(back, c.public) {
			t.Fatalf("%x decodes as %#v, want %#v", got, back, c.public)
		}
	}
	// A value type that is not published still decodes as itself.
	back, err := Unmarshal(mustMarshal(t, Uint128{7}))
	if err != nil || back != (Uint128{7}) {
		t.Fatalf("an unpublished Uint128 decodes as %#v, %v", back, err)
	}
	// Inside a container, and through reflection, as a struct field.
	type row struct {
		When pubDate
		ID   *pubUUID
		Big  *pubInt128
	}
	got := mustMarshal(t, row{When: pubDate{Year: 1, Month: 1, Day: 1}})
	want := mustMarshal(t, struct {
		When Date
		ID   *UUID
		Big  *Int128
	}{When: Date{Year: 1, Month: 1, Day: 1}})
	if !bytes.Equal(got, want) {
		t.Fatalf("a struct of published types writes %x, of value types %x", got, want)
	}
	// The nil pointers are the typed nulls of their value types.
	if !bytes.Contains(got, uuidNull) || !bytes.Contains(got, nullOf(tagInt128)) {
		t.Fatalf("no typed nulls in %x", got)
	}
}

func TestAPublishedEnvelopeScalarReadsAsAnInteger(t *testing.T) {
	publishForTest(t)
	// A timestamp in seconds over an Int128: the physical scalar decodes as
	// the published type, and the timestamp still reads it.
	raw := append([]byte{tagEnvelope, logicalTimestamp, unitSeconds, tagInt128, 7}, make([]byte, 15)...)
	back, err := Unmarshal(raw)
	if err != nil || !back.(time.Time).Equal(time.Unix(7, 0)) {
		t.Fatalf("decoded %#v, %v", back, err)
	}
	// An unknown logical id over an Int128 keeps the published type in V,
	// and writes back unchanged.
	raw = append([]byte{tagEnvelope, 200, 0, tagInt128, 7}, make([]byte, 15)...)
	back, err = Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if tagged, ok := back.(Tagged); !ok || tagged.V != (pubInt128{7}) {
		t.Fatalf("decoded %#v", back)
	}
	if again := mustMarshal(t, back); !bytes.Equal(again, raw) {
		t.Fatalf("re-encoded %x, want %x", again, raw)
	}
}

func TestAPublishedTypeInAStorageBlob(t *testing.T) {
	publishForTest(t)
	type record struct {
		Big  pubInt128         `vc:"big"`
		ID   pubUUID           `vc:"id"`
		Keys map[pubInt128]int `vc:"keys"`
	}
	in := record{Big: pubInt128{1}, ID: pubUUID{2}, Keys: map[pubInt128]int{{3}: 4}}
	blob, err := MarshalStorage(in)
	if err != nil {
		t.Fatal(err)
	}
	want, err := MarshalStorage(struct {
		Big  Int128         `vc:"big"`
		ID   UUID           `vc:"id"`
		Keys map[Int128]int `vc:"keys"`
	}{Int128{1}, UUID{2}, map[Int128]int{{3}: 4}})
	if err != nil || !bytes.Equal(blob, want) {
		t.Fatalf("published types write %x, value types %x, %v", blob, want, err)
	}
	var out record
	if err := UnmarshalStorage(blob, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out, in) {
		t.Fatalf("read back %#v, want %#v", out, in)
	}
	// A published date has no storage form, as a Date has none, and the
	// refusal names the type the program used.
	_, err = MarshalStorage(pubDate{Year: 1, Month: 1, Day: 1})
	if !errors.Is(err, ErrUnwritable) || !strings.Contains(err.Error(), "frame.pubDate has no storage form") {
		t.Fatalf("a published date: %v", err)
	}
}

func TestThePublishedEncryptableWritesItself(t *testing.T) {
	publishForTest(t)
	got := mustMarshal(t, cents(3))
	if want := mustMarshal(t, int64(300)); !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
	// A nil pointer to one is written as the plain null. The encoder does
	// not call its method.
	if got := mustMarshal(t, (*cents)(nil)); !bytes.Equal(got, []byte{tagNull}) {
		t.Fatalf("a nil pointer writes %x", got)
	}
	// The type has no storage form, because no Encryptable has one.
	if _, err := MarshalStorage(struct{ C cents }{}); !errors.Is(err, ErrUnwritable) {
		t.Fatalf("storage: %v", err)
	}
}

func TestPublishRefusesWhatItCannotPublish(t *testing.T) {
	publishForTest(t)
	type otherDate struct {
		Year  int
		Month time.Month
		Day   int
	}
	for name, publish := range map[string]func(){
		"a type that is not a value type": func() { Publish[pubDate, Object]() },
		"the value type itself":           func() { Publish[Date, Date]() },
		"a different underlying type":     func() { Publish[pubUUID, Date]() },
		"a second type for a value type":  func() { Publish[otherDate, Date]() },
		"a type published as another":     func() { Publish[pubInt128, Uint128]() },
		"an Encryptable that is not an interface": func() {
			PublishEncryptable(func(cents, Encoder) error { return nil })
		},
		"a second Encryptable": func() {
			PublishEncryptable(func(testEncryptable, Encoder) error { return nil })
		},
	} {
		func() {
			defer func() {
				if r := recover(); r == nil || !strings.HasPrefix(r.(string), "frame: ") {
					t.Errorf("%s: recovered %v, want a panic", name, r)
				}
			}()
			publish()
		}()
	}
	// Publishing the same pair again changes nothing.
	Publish[pubDate, Date]()
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// checksEncoder records what the Encoder it is handed reports, and writes a
// value only when that Encoder is usable.
type checksEncoder struct{ usable *bool }

func (c checksEncoder) EncryptValue(enc Encoder) error {
	*c.usable = enc.Usable()
	if enc.Err() != nil {
		return enc.Err()
	}
	enc.Bool(true)
	return nil
}

func TestTheZeroEncoderIsNotUsable(t *testing.T) {
	var zero Encoder
	if zero.Usable() || zero.Err() == nil {
		t.Fatalf("the zero Encoder: usable %v, err %v", zero.Usable(), zero.Err())
	}
	var usable bool
	if _, err := Marshal(checksEncoder{usable: &usable}); err != nil || !usable {
		t.Fatalf("the Encoder the codec hands out: usable %v, %v", usable, err)
	}
	// Err reports the first error of the encode so far.
	enc := func(e Encoder) error {
		e.String(string([]byte{0xff}))
		if e.Err() == nil {
			return errors.New("Err reported nothing after a refused string")
		}
		return nil
	}
	if _, err := Marshal(encryptableFunc(enc)); err == nil || strings.Contains(err.Error(), "reported nothing") {
		t.Fatalf("got %v", err)
	}
}
