package vcffi

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// The storage corpus is shared with Rust (packages/aead-frame), which pins
// version 1 byte for byte; this file holds Go to the same rows.
const storageCorpus = "../../../packages/aead-frame/testdata/storage-v1.json"

type storageRow struct {
	Name     string          `json:"name"`
	Value    json.RawMessage `json:"value"`
	Blob     string          `json:"blob"`
	Refusal  string          `json:"refusal"`
	Type     json.RawMessage `json:"type"`
	ReadsAs  json.RawMessage `json:"reads_as"`
	HasReads bool            `json:"-"`
}

type storageCorpusFile struct {
	Version int          `json:"version"`
	Header  string       `json:"header"`
	Vectors []storageRow `json:"vectors"`
	Refused []storageRow `json:"refused"`
	Reads   []storageRow `json:"reads"`
}

func loadStorageCorpus(t testing.TB) storageCorpusFile {
	t.Helper()
	data, err := os.ReadFile(storageCorpus)
	if err != nil {
		t.Fatal(err)
	}
	var c storageCorpusFile
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	// reads_as is null for a row that reads as null, so its presence is
	// told apart from a refusal by the refusal field.
	for i := range c.Reads {
		c.Reads[i].HasReads = c.Reads[i].Refusal == ""
	}
	return c
}

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// storageModel builds the Go value a corpus value describes, without the
// storage reader, so a reader and writer wrong in the same way cannot pass.
func storageModel(t testing.TB, raw json.RawMessage) any {
	t.Helper()
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var kind map[string]json.RawMessage
	if err := json.Unmarshal(raw, &kind); err != nil || len(kind) != 1 {
		t.Fatalf("a value names one kind: %s", raw)
	}
	for k, v := range kind {
		var text string
		_ = json.Unmarshal(v, &text)
		signed := func(bits int) int64 {
			n, err := strconv.ParseInt(text, 10, bits)
			if err != nil {
				t.Fatal(err)
			}
			return n
		}
		unsigned := func(bits int) uint64 {
			n, err := strconv.ParseUint(text, 10, bits)
			if err != nil {
				t.Fatal(err)
			}
			return n
		}
		pairs := func() [][2]json.RawMessage {
			var p [][2]json.RawMessage
			if err := json.Unmarshal(v, &p); err != nil {
				t.Fatal(err)
			}
			return p
		}
		switch k {
		case "bool":
			var b bool
			_ = json.Unmarshal(v, &b)
			return b
		case "i8":
			return int8(signed(8))
		case "i16":
			return int16(signed(16))
		case "i32":
			return int32(signed(32))
		case "i64":
			return signed(64)
		case "i128":
			n, err := vcvalue.ParseInt128(text)
			if err != nil {
				t.Fatal(err)
			}
			return n
		case "u8":
			return uint8(unsigned(8))
		case "u16":
			return uint16(unsigned(16))
		case "u32":
			return uint32(unsigned(32))
		case "u64":
			return unsigned(64)
		case "u128":
			n, err := vcvalue.ParseUint128(text)
			if err != nil {
				t.Fatal(err)
			}
			return n
		case "f32_bits":
			bits, _ := strconv.ParseUint(text, 16, 32)
			return math.Float32frombits(uint32(bits))
		case "f64_bits":
			bits, _ := strconv.ParseUint(text, 16, 64)
			return math.Float64frombits(bits)
		case "text":
			return text
		case "bytes":
			return mustHex(t, text)
		case "some":
			return Some{V: storageModel(t, v)}
		case "array":
			var items []json.RawMessage
			_ = json.Unmarshal(v, &items)
			out := make([]any, len(items))
			for i, item := range items {
				out[i] = storageModel(t, item)
			}
			return out
		case "object":
			out := vcvalue.Object{}
			for _, p := range pairs() {
				var key string
				_ = json.Unmarshal(p[0], &key)
				out = append(out, vcvalue.Field{Key: key, Value: storageModel(t, p[1])})
			}
			return out
		case "map":
			out := StorageEntries{}
			for _, p := range pairs() {
				out = append(out, StorageEntry{Key: storageModel(t, p[0]), Value: storageModel(t, p[1])})
			}
			return out
		case "nest":
			var n struct {
				Kind  string          `json:"kind"`
				Depth int             `json:"depth"`
				Leaf  json.RawMessage `json:"leaf"`
			}
			_ = json.Unmarshal(v, &n)
			m := storageModel(t, n.Leaf)
			for range n.Depth {
				switch n.Kind {
				case "array":
					m = []any{m}
				case "object":
					m = vcvalue.Object{{Key: "k", Value: m}}
				case "some":
					m = Some{V: m}
				case "map":
					m = StorageEntries{{Key: uint8(0), Value: m}}
				default:
					t.Fatalf("unknown nest kind %s", n.Kind)
				}
			}
			return m
		default:
			t.Fatalf("unknown kind %s", k)
		}
	}
	return nil
}

// sameModel compares two models, floats by their bits so NaNs compare.
func sameModel(a, b any) bool {
	switch x := a.(type) {
	case float32:
		y, ok := b.(float32)
		return ok && math.Float32bits(x) == math.Float32bits(y)
	case float64:
		y, ok := b.(float64)
		return ok && math.Float64bits(x) == math.Float64bits(y)
	case Some:
		y, ok := b.(Some)
		return ok && sameModel(x.V, y.V)
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !sameModel(x[i], y[i]) {
				return false
			}
		}
		return true
	case vcvalue.Object:
		y, ok := b.(vcvalue.Object)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if x[i].Key != y[i].Key || !sameModel(x[i].Value, y[i].Value) {
				return false
			}
		}
		return true
	case StorageEntries:
		y, ok := b.(StorageEntries)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !sameModel(x[i].Key, y[i].Key) || !sameModel(x[i].Value, y[i].Value) {
				return false
			}
		}
		return true
	}
	return reflect.DeepEqual(a, b)
}

func storageClass(t testing.TB, name, refusal string) error {
	t.Helper()
	switch refusal {
	case "not_a_blob":
		return ErrNotABlob
	case "unsupported_version":
		return ErrUnsupportedVersion
	case "malformed":
		return ErrMalformed
	case "mismatch":
		return ErrMismatch
	}
	t.Fatalf("%s: unknown refusal %s", name, refusal)
	return nil
}

func TestStorageCorpusHeader(t *testing.T) {
	c := loadStorageCorpus(t)
	if c.Version != StorageVersion || !bytes.Equal(mustHex(t, c.Header), StorageHeader[:]) {
		t.Fatalf("corpus version %d header %s", c.Version, c.Header)
	}
}

// Every vector reads as its value and writes as its bytes.
func TestStorageCorpusVectors(t *testing.T) {
	c := loadStorageCorpus(t)
	if len(c.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, row := range c.Vectors {
		blob := mustHex(t, row.Blob)
		want := storageModel(t, row.Value)
		var got any
		if err := UnmarshalStorage(blob, &got); err != nil {
			t.Errorf("%s: %v", row.Name, err)
			continue
		}
		if !sameModel(got, want) {
			t.Errorf("%s: read %#v, want %#v", row.Name, got, want)
		}
		written, err := MarshalStorage(want)
		if err != nil {
			t.Errorf("%s: %v", row.Name, err)
		} else if !bytes.Equal(written, blob) {
			t.Errorf("%s: wrote %x, want %x", row.Name, written, blob)
		}
	}
}

// Every refused row is refused by its class, whatever it is read into.
func TestStorageCorpusRefused(t *testing.T) {
	c := loadStorageCorpus(t)
	if len(c.Refused) == 0 {
		t.Fatal("no refused rows")
	}
	for _, row := range c.Refused {
		blob := mustHex(t, row.Blob)
		class := storageClass(t, row.Name, row.Refusal)
		var anything any
		if err := UnmarshalStorage(blob, &anything); !errors.Is(err, class) {
			t.Errorf("%s: %v, want %v", row.Name, err, class)
		}
		var nothing struct{}
		if err := UnmarshalStorage(blob, &nothing); !errors.Is(err, class) {
			t.Errorf("%s: into a struct: %v, want %v", row.Name, err, class)
		}
	}
}

// goType is the Go type a corpus type describes, or why Go has none: Go has
// no enums and no unit type, and a []byte cannot be a map key.
func goType(t testing.TB, raw json.RawMessage) (reflect.Type, string) {
	t.Helper()
	var name string
	if json.Unmarshal(raw, &name) == nil {
		types := map[string]reflect.Type{
			"bool": reflect.TypeOf(false), "f32": reflect.TypeOf(float32(0)), "f64": reflect.TypeOf(float64(0)),
			"i8": reflect.TypeOf(int8(0)), "i16": reflect.TypeOf(int16(0)), "i32": reflect.TypeOf(int32(0)),
			"i64": reflect.TypeOf(int64(0)), "i128": int128Type,
			"u8": reflect.TypeOf(uint8(0)), "u16": reflect.TypeOf(uint16(0)), "u32": reflect.TypeOf(uint32(0)),
			"u64": reflect.TypeOf(uint64(0)), "u128": uint128Type,
			"text": reflect.TypeOf(""), "bytes": reflect.TypeOf([]byte(nil)),
		}
		if ty, ok := types[name]; ok {
			return ty, ""
		}
		if name == "unit" {
			return nil, "Go has no unit type"
		}
		t.Fatalf("unknown type %s", name)
	}
	var kind map[string]json.RawMessage
	if err := json.Unmarshal(raw, &kind); err != nil {
		t.Fatal(err)
	}
	for k, v := range kind {
		switch k {
		case "option":
			inner, why := goType(t, v)
			if inner == nil {
				return nil, why
			}
			return reflect.PointerTo(inner), ""
		case "seq":
			inner, why := goType(t, v)
			if inner == nil {
				return nil, why
			}
			if inner.Kind() == reflect.Uint8 {
				return nil, "Go's []uint8 is []byte, which is bytes; a Rust Vec<u8> is an array unless it uses serde_bytes"
			}
			return reflect.SliceOf(inner), ""
		case "map":
			var kv [2]json.RawMessage
			_ = json.Unmarshal(v, &kv)
			key, why := goType(t, kv[0])
			if key == nil {
				return nil, why
			}
			if !key.Comparable() {
				return nil, "a Go map key cannot be " + key.String()
			}
			value, why := goType(t, kv[1])
			if value == nil {
				return nil, why
			}
			return reflect.MapOf(key, value), ""
		// UnmarshalStorage ignores unknown fields: a struct that denies them
		// reads as one that does not, and its refusals are skipped below.
		case "unit_struct":
			return nil, "Go has no unit type"
		case "struct", "struct_deny_unknown":
			var pairs [][2]json.RawMessage
			_ = json.Unmarshal(v, &pairs)
			fields := make([]reflect.StructField, len(pairs))
			for i, p := range pairs {
				var fieldName string
				_ = json.Unmarshal(p[0], &fieldName)
				ty, why := goType(t, p[1])
				if ty == nil {
					return nil, why
				}
				fields[i] = reflect.StructField{
					Name: fmt.Sprintf("F%d", i),
					Type: ty,
					Tag:  reflect.StructTag(`vc:"` + fieldName + `"`),
				}
			}
			return reflect.StructOf(fields), ""
		case "enum":
			return nil, "Go has no enums"
		}
	}
	t.Fatalf("unknown type %s", raw)
	return nil, ""
}

// deniesUnknown reports whether a row's type is itself a struct that
// denies unknown keys. UnmarshalStorage has no way to deny them, so a
// refused row of such a type that Go reads anyway is skipped. A row of
// that type that Go refuses is still checked for its error class. A
// struct that denies them nested in another type is not looked for: a row
// refused for that would fail below, rather than be skipped.
func deniesUnknown(raw json.RawMessage) bool {
	var kind map[string]json.RawMessage
	if json.Unmarshal(raw, &kind) != nil {
		return false
	}
	_, ok := kind["struct_deny_unknown"]
	return ok
}

// Every reads row Go can express reads as it says, or is refused as a
// mismatch. What it reads as is compared as the blob it writes back to.
func TestStorageCorpusReads(t *testing.T) {
	c := loadStorageCorpus(t)
	expressed := 0
	for _, row := range c.Reads {
		ty, why := goType(t, row.Type)
		if ty == nil {
			t.Logf("%s: not expressible in Go: %s", row.Name, why)
			continue
		}
		blob := mustHex(t, row.Blob)
		into := reflect.New(ty)
		err := UnmarshalStorage(blob, into.Interface())
		if !row.HasReads && err == nil && deniesUnknown(row.Type) {
			t.Logf("%s: not expressible in Go: UnmarshalStorage has no way to deny unknown fields", row.Name)
			continue
		}
		expressed++
		if !row.HasReads {
			if class := storageClass(t, row.Name, row.Refusal); !errors.Is(err, class) {
				t.Errorf("%s: %v, want %v", row.Name, err, class)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", row.Name, err)
			continue
		}
		// What the row reads as, written canonically, read by the same
		// type: the Go value both blobs must read as.
		canonical, err := MarshalStorage(storageModel(t, row.ReadsAs))
		if err != nil {
			t.Fatal(err)
		}
		want := reflect.New(ty)
		if err := UnmarshalStorage(canonical, want.Interface()); err != nil {
			t.Fatalf("%s: the canonical form: %v", row.Name, err)
		}
		if !reflect.DeepEqual(into.Elem().Interface(), want.Elem().Interface()) {
			t.Errorf("%s: read as %#v, want %#v", row.Name, into.Elem().Interface(), want.Elem().Interface())
		}
	}
	// Most rows are expressible; a new row Go cannot express is logged
	// above, and this guards against a typo skipping them all.
	if expressed < len(c.Reads)/2 {
		t.Fatalf("only %d of %d reads rows are expressed in Go", expressed, len(c.Reads))
	}
}

// =============================================================================
// The Go mapping
// =============================================================================

type stamp struct{ at string }

// folded writes itself in lower case, so two keys can write as one.
type folded string

func (f folded) MarshalText() ([]byte, error) { return []byte(strings.ToLower(string(f))), nil }

func (s stamp) MarshalText() ([]byte, error)  { return []byte("<" + s.at + ">"), nil }
func (s *stamp) UnmarshalText(b []byte) error { s.at = strings.Trim(string(b), "<>"); return nil }

type record struct {
	Name    string            `vc:"name"`
	Age     uint8             `vc:"age"`
	Pinned  *bool             `vc:"pinned"`
	Nested  **int32           `vc:"nested"`
	Absent  **int32           `vc:"absent"`
	Tags    []string          `vc:"tags"`
	Raw     []byte            `vc:"raw"`
	ID      vcvalue.UUID      `vc:"id"`
	Scores  map[uint32]string `vc:"scores"`
	When    time.Time         `vc:"when"`
	Stamp   stamp             `vc:"stamp"`
	Big     vcvalue.Int128    `vc:"big"`
	Ratio   float32           `vc:"ratio"`
	Skipped string            `vc:"-"`
	Untyped any               `vc:"untyped"`
}

func TestStorageRecordRoundTrips(t *testing.T) {
	yes := true
	n := int32(-3)
	np := &n
	var nilInt *int32
	big, _ := vcvalue.ParseInt128("-170141183460469231731687303715884105728")
	in := record{
		Name:    "ada",
		Age:     36,
		Pinned:  &yes,
		Nested:  &np,
		Absent:  &nilInt,
		Tags:    []string{"x", "y"},
		Raw:     []byte{1, 2},
		ID:      vcvalue.UUID{15: 1},
		Scores:  map[uint32]string{7: "a", 1: "b"},
		When:    time.Date(2026, 10, 25, 1, 2, 3, 4, time.UTC),
		Stamp:   stamp{at: "noon"},
		Big:     big,
		Ratio:   math.Float32frombits(0x7fa00001),
		Skipped: "gone",
		Untyped: StorageEntries{{Key: int16(-1), Value: Some{V: nil}}},
	}
	blob, err := MarshalStorage(in)
	if err != nil {
		t.Fatal(err)
	}
	var out record
	if err := UnmarshalStorage(blob, &out); err != nil {
		t.Fatal(err)
	}
	in.Skipped = ""
	if math.Float32bits(out.Ratio) != 0x7fa00001 {
		t.Fatalf("a signaling NaN lost its bits: %x", math.Float32bits(out.Ratio))
	}
	in.Ratio, out.Ratio = 0, 0
	if !reflect.DeepEqual(out, in) {
		t.Fatalf("read %+v, want %+v", out, in)
	}
	// The pieces whose bytes Rust must agree on.
	var model any
	if err := UnmarshalStorage(blob, &model); err != nil {
		t.Fatal(err)
	}
	fields := model.(vcvalue.Object)
	for _, f := range fields {
		switch f.Key {
		case "pinned":
			if !sameModel(f.Value, true) {
				t.Errorf("a pointer is its value: %#v", f.Value)
			}
		case "nested":
			if !sameModel(f.Value, int32(-3)) {
				t.Errorf("a pointer to a pointer is its value: %#v", f.Value)
			}
		case "absent":
			if !sameModel(f.Value, Some{V: nil}) {
				t.Errorf("a pointer to nil is marked, so it is not read as nil: %#v", f.Value)
			}
		case "id":
			if !sameModel(f.Value, append(make([]byte, 15), 1)) {
				t.Errorf("a UUID is its 16 bytes: %#v", f.Value)
			}
		case "scores":
			want := StorageEntries{{Key: uint32(1), Value: "b"}, {Key: uint32(7), Value: "a"}}
			if !sameModel(f.Value, want) {
				t.Errorf("a map is sorted by key: %#v", f.Value)
			}
		case "when":
			if f.Value != "2026-10-25T01:02:03.000000004Z" {
				t.Errorf("a time is its RFC 3339 text: %#v", f.Value)
			}
		case "stamp":
			if f.Value != "<noon>" {
				t.Errorf("a TextMarshaler is its text: %#v", f.Value)
			}
		case "big":
			if !sameModel(f.Value, big) {
				t.Errorf("an Int128 is an integer: %#v", f.Value)
			}
		case "-", "Skipped":
			t.Errorf("a vc:\"-\" field is written")
		}
	}
}

// Integer keys sort by value, as a Rust BTreeMap orders them, so the same
// map writes the same bytes in both languages.
func TestStorageMapKeysSortLikeRust(t *testing.T) {
	cases := []struct {
		in   any
		keys []any
	}{
		{map[int8]bool{1: true, -1: true, -128: true, 0: true}, []any{int8(-128), int8(-1), int8(0), int8(1)}},
		{map[uint64]bool{math.MaxUint64: true, 2: true}, []any{uint64(2), uint64(math.MaxUint64)}},
		{map[string]bool{"b": true, "B": true, "": true, "é": true}, []any{"", "B", "b", "é"}},
		{map[[2]byte]bool{{2, 0}: true, {1, 9}: true}, []any{[]byte{1, 9}, []byte{2, 0}}},
	}
	for _, c := range cases {
		blob, err := MarshalStorage(c.in)
		if err != nil {
			t.Fatal(err)
		}
		var model any
		if err := UnmarshalStorage(blob, &model); err != nil {
			t.Fatal(err)
		}
		entries := model.(StorageEntries)
		for i, k := range c.keys {
			if !sameModel(entries[i].Key, k) {
				t.Errorf("%T: key %d is %#v, want %#v", c.in, i, entries[i].Key, k)
			}
		}
		back := reflect.New(reflect.TypeOf(c.in))
		if err := UnmarshalStorage(blob, back.Interface()); err != nil || !reflect.DeepEqual(back.Elem().Interface(), c.in) {
			t.Errorf("%T: %v", c.in, err)
		}
	}
}

func TestStorageNilSliceAndMapAreEmpty(t *testing.T) {
	var s []int32
	var m map[string]int32
	for _, v := range []any{s, m} {
		blob, err := MarshalStorage(v)
		if err != nil {
			t.Fatal(err)
		}
		if blob[4] == tagNull {
			t.Errorf("%T: a nil container is written as null; Rust reads only an empty one", v)
		}
	}
}

func TestStorageRefusesWhatHasNoStorageForm(t *testing.T) {
	type hidden struct{ secret string }
	deep := any(nil)
	for range maxDepth + 1 {
		deep = []any{deep}
	}
	for name, v := range map[string]any{
		"a channel":                      make(chan int),
		"a function":                     func() {},
		"a complex number":               complex(1, 2),
		"a passthrough":                  vcvalue.Plain{V: 1},
		"a date":                         vcvalue.Date{},
		"a decimal":                      vcvalue.Decimal{},
		"a typed null":                   vcvalue.TypedNull{},
		"unexported fields":              hidden{secret: "s3cr3t"},
		"a float key":                    map[float64]bool{1.5: true},
		"a bool key":                     map[bool]bool{true: true},
		"a nil key":                      StorageEntries{{Key: nil, Value: 1}},
		"a repeated key":                 StorageEntries{{Key: uint8(1)}, {Key: int64(1)}},
		"a repeated field":               vcvalue.Object{{Key: "k"}, {Key: "k"}},
		"invalid UTF-8":                  string([]byte{0xff}),
		"invalid UTF-8 key":              map[string]bool{string([]byte{0xff}): true},
		"too deep":                       deep,
		"a key spelled twice":            map[folded]bool{"A": true, "a": true},
		"an array element too":           [1]any{make(chan int)},
		"an Encryptable":                 point{X: 1, Y: 2},
		"a pointer-receiver Encryptable": sealedSecret{Secret: "s3cr3t"},
		"a pointer to one":               &sealedSecret{Secret: "s3cr3t"},
		"a nil pointer to one":           (*sealedSecret)(nil),
		"an Encryptable field":           struct{ S sealedSecret }{},
	} {
		_, err := MarshalStorage(v)
		if !errors.Is(err, ErrUnwritable) {
			t.Errorf("%s: %v, want ErrUnwritable", name, err)
		}
		if err != nil && strings.Contains(err.Error(), "s3cr3t") {
			t.Errorf("%s: the error echoes a value: %v", name, err)
		}
	}
	_, err := MarshalStorage(deep)
	if !errors.Is(err, ErrTooDeep) {
		t.Errorf("too deep: %v, want ErrTooDeep as well", err)
	}
}

// sealedSecret chooses its own encoding, so its fields are not its value.
type sealedSecret struct{ Secret string }

func (s *sealedSecret) EncryptValue(enc Encoder) error {
	enc.String("redacted")
	return nil
}

// A bytes key read into an interface key would be a []byte, which a Go map
// cannot hold: it is a mismatch, not a panic.
func TestStorageBytesKeyIntoAnyKeyIsAMismatch(t *testing.T) {
	blob, err := MarshalStorage(map[[1]byte]int{{1}: 42})
	if err != nil {
		t.Fatal(err)
	}
	var into map[any]any
	if err := UnmarshalStorage(blob, &into); !errors.Is(err, ErrMismatch) {
		t.Fatalf("%v, want ErrMismatch", err)
	}
	var keyed map[[1]byte]int
	if err := UnmarshalStorage(blob, &keyed); err != nil || keyed[[1]byte{1}] != 42 {
		t.Fatalf("%v, %v", err, keyed)
	}
}

func TestStorageMismatchNamesWhereAndNotWhat(t *testing.T) {
	blob, err := MarshalStorage(map[string]any{"secret_key": "s3cr3t"})
	if err != nil {
		t.Fatal(err)
	}
	var into map[string]int
	err = UnmarshalStorage(blob, &into)
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("%v, want ErrMismatch", err)
	}
	if strings.Contains(err.Error(), "s3cr3t") || strings.Contains(err.Error(), "secret_key") {
		t.Fatalf("the error echoes the blob: %v", err)
	}
	type inner struct {
		N uint8 `vc:"n"`
	}
	type outer struct {
		List []inner `vc:"list"`
	}
	blob, _ = MarshalStorage(map[string]any{"list": []any{map[string]any{"n": int32(300)}}})
	err = UnmarshalStorage(blob, &outer{})
	if !errors.Is(err, ErrMismatch) || !strings.Contains(err.Error(), "list[0].n") {
		t.Fatalf("%v, want a mismatch at list[0].n", err)
	}
	if err := UnmarshalStorage(blob, outer{}); err == nil || errors.Is(err, ErrMismatch) {
		t.Fatalf("a non-pointer destination: %v", err)
	}
}

// A field that became a pointer reads its old value; a missing pointer
// field is nil, and any other missing field is refused.
func TestStorageOptionalFields(t *testing.T) {
	type before struct {
		N uint32 `vc:"n"`
	}
	type after struct {
		N *uint32 `vc:"n"`
		M *string `vc:"m"`
	}
	type stricter struct {
		N uint32 `vc:"n"`
		M string `vc:"m"`
	}
	blob, _ := MarshalStorage(before{N: 7})
	var a after
	if err := UnmarshalStorage(blob, &a); err != nil || a.N == nil || *a.N != 7 || a.M != nil {
		t.Fatalf("%+v %v", a, err)
	}
	if err := UnmarshalStorage(blob, &stricter{}); !errors.Is(err, ErrMismatch) {
		t.Fatalf("a missing field: %v, want ErrMismatch", err)
	}
	// A tagged default reads a missing field as its zero value, and keeps
	// its name, or the field's own with an empty name.
	type defaulted struct {
		N uint32 `vc:"n"`
		M string `vc:"m,default"`
		K []int8 `vc:",default"`
	}
	d := defaulted{M: "x", K: []int8{1}}
	if err := UnmarshalStorage(blob, &d); err != nil || d.N != 7 || d.M != "" || d.K != nil {
		t.Fatalf("%+v %v", d, err)
	}
	full, _ := MarshalStorage(defaulted{N: 1, M: "m", K: []int8{2}})
	var model any
	_ = UnmarshalStorage(full, &model)
	if names := []string{model.(vcvalue.Object)[1].Key, model.(vcvalue.Object)[2].Key}; names[0] != "m" || names[1] != "K" {
		t.Fatalf("a tag's options are not part of its name: %v", names)
	}
	// A Go pointer is written bare, so a field that is not a pointer on the
	// reading side reads it; Rust's marked Some reads only into a pointer.
	blob, _ = MarshalStorage(after{N: a.N})
	if err := UnmarshalStorage(blob, &before{}); err != nil {
		t.Fatalf("a pointer into a plain field: %v", err)
	}
	blob, _ = MarshalStorage(vcvalue.Object{{Key: "n", Value: Some{V: uint32(7)}}})
	if err := UnmarshalStorage(blob, &before{}); !errors.Is(err, ErrMismatch) {
		t.Fatalf("a marked value into a plain field: %v, want ErrMismatch", err)
	}
	if err := UnmarshalStorage(blob, &a); err != nil || *a.N != 7 {
		t.Fatalf("a marked value into a pointer: %v", err)
	}
}

// The transport names a struct's fields by the same tags, options and all.
func TestTransportFieldNamesIgnoreTagOptions(t *testing.T) {
	type tagged struct {
		Age uint8 `vc:"age,default"`
	}
	buf, err := Marshal(tagged{Age: 3})
	if err != nil {
		t.Fatal(err)
	}
	v, err := Unmarshal(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := v.(vcvalue.Object)[0].Key; got != "age" {
		t.Fatalf("the transport named the field %q", got)
	}
}

// =============================================================================
// Fuzzing
// =============================================================================

func addStorageSeeds(f *testing.F) {
	c := loadStorageCorpus(f)
	for _, rows := range [][]storageRow{c.Vectors, c.Refused, c.Reads} {
		for _, row := range rows {
			f.Add(mustHex(f, row.Blob))
		}
	}
}

// FuzzUnmarshalStorage holds the reader to its contract on hostile bytes:
// it never panics, a blob it reads writes back as exactly the same bytes
// (one encoding per value), and reading into a struct never panics either.
func FuzzUnmarshalStorage(f *testing.F) {
	addStorageSeeds(f)
	f.Fuzz(func(t *testing.T, blob []byte) {
		var model any
		if err := UnmarshalStorage(blob, &model); err == nil {
			again, err := MarshalStorage(model)
			if err != nil {
				t.Fatalf("read but cannot write back: %v", err)
			}
			if !bytes.Equal(again, blob) {
				t.Fatalf("read %x but wrote back %x", blob, again)
			}
		}
		var r record
		_ = UnmarshalStorage(blob, &r)
	})
}

// Every level of a pointer to a pointer reads back: a pointer to a value
// that is itself written as null or marked present is marked, so its
// reader never takes the inner level's null or marker for its own.
func TestStoragePointerLevelsReadBack(t *testing.T) {
	five := 5
	var leaf *int
	middle := &leaf
	present := &five
	presentMiddle := &present
	var nilMiddle **int
	for name, original := range map[string]***int{
		"all present":   &presentMiddle,
		"innermost nil": &middle,
		"middle nil":    &nilMiddle,
		"outermost nil": nil,
	} {
		blob, err := MarshalStorage(original)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var back ***int
		if err := UnmarshalStorage(blob, &back); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !reflect.DeepEqual(back, original) {
			t.Errorf("%s: %x read back as a different shape", name, blob)
		}
	}

	// The blob Codex found: the innermost nil is two markers, then null.
	blob, err := MarshalStorage(&middle)
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x56, 0x43, 0x53, 0x01, StorageSome, StorageSome, tagNull}; !bytes.Equal(blob, want) {
		t.Errorf("%x, want %x", blob, want)
	}

	// A pointer to [Some] is marked too, so the Some keeps its own marker.
	some := Some{V: int64(1)}
	blob, err = MarshalStorage(&some)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(blob[4:], []byte{StorageSome, StorageSome}) {
		t.Errorf("%x: a pointer to Some is not marked", blob)
	}
}

// A nil pointer is no map key. It is refused, never handed to its type's
// MarshalText, which would be called on nil.
func TestStorageRefusesANilPointerKey(t *testing.T) {
	for name, v := range map[string]any{
		"a map":            map[*time.Time]int{nil: 1},
		"entries":          StorageEntries{{Key: (*time.Time)(nil), Value: 1}},
		"an interface key": map[any]int{(*time.Time)(nil): 1},
	} {
		if _, err := MarshalStorage(v); !errors.Is(err, ErrUnwritable) {
			t.Errorf("%s: %v, want ErrUnwritable", name, err)
		}
	}
}

// A `vc` tag option other than `default` is refused where a struct is
// written or read, in a blob or the transport, rather than ignored.
func TestUnknownTagOptionsAreRefused(t *testing.T) {
	type misspelt struct {
		Email string `vc:"email,defualt"`
	}
	if _, err := MarshalStorage(misspelt{}); !errors.Is(err, ErrUnwritable) || !strings.Contains(err.Error(), `"defualt"`) {
		t.Errorf("writing: %v", err)
	}
	blob, err := MarshalStorage(map[string]string{"email": "x"})
	if err != nil {
		t.Fatal(err)
	}
	if err := UnmarshalStorage(blob, &misspelt{}); err == nil || !strings.Contains(err.Error(), `"defualt"`) {
		t.Errorf("reading: %v", err)
	}
	if _, err := Marshal(misspelt{Email: "x"}); err == nil || !strings.Contains(err.Error(), `"defualt"`) {
		t.Errorf("the transport: %v", err)
	}
	type empty struct {
		Email string `vc:"email,"`
	}
	if _, err := MarshalStorage(empty{}); err != nil {
		t.Errorf("an empty option: %v", err)
	}
}

// A pointer that writes no node of its own costs no depth, so a linked
// list is as deep in Go as its blob is; a pointer cycle is still refused.
func TestStoragePointersCostOnlyTheDepthTheyWrite(t *testing.T) {
	type node struct {
		Next *node `vc:"next"`
	}
	var list *node
	for range 100 {
		list = &node{Next: list}
	}
	blob, err := MarshalStorage(list)
	if err != nil {
		t.Fatalf("a 100-deep list: %v", err)
	}
	var back *node
	if err := UnmarshalStorage(blob, &back); err != nil || !reflect.DeepEqual(back, list) {
		t.Fatalf("a 100-deep list read back as %v", err)
	}

	type loop *loop
	var p loop
	p = &p
	if _, err := MarshalStorage(p); !errors.Is(err, ErrTooDeep) {
		t.Errorf("a pointer cycle: %v, want ErrTooDeep", err)
	}
	var a any
	a = &a
	if _, err := MarshalStorage(a); !errors.Is(err, ErrTooDeep) {
		t.Errorf("an interface cycle: %v, want ErrTooDeep", err)
	}
}
