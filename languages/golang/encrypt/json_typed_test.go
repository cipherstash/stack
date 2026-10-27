package encrypt_test

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// Generated code for document fields of Go types: testusers.Subscriber's
// Profile (a struct, ordered at $.age and $.visits[*].at), its optional
// Prefs (a pointer to a struct, null=sql) and its Labels (a map).

// subscribers hold the values a float64 would round, in declared fields.
var subscribers = []testusers.Subscriber{
	{
		ID: 1,
		Profile: testusers.SubscriberProfile{
			Name: "Alice", Age: 34, Tier: "gold",
			Big: math.MaxUint64, Small: math.MinInt64, Score: 0.30000000000000004,
			Visits: []testusers.Visit{{At: 3, Place: "home"}, {At: 1, Place: "work"}},
		},
		Prefs:  &testusers.SubscriberPrefs{Theme: "dark"},
		Labels: map[string]string{"team": "red"},
	},
	{ID: 2, Profile: testusers.SubscriberProfile{Name: "Bob", Age: 7, Big: math.MaxInt64, Small: math.MaxInt64, Visits: []testusers.Visit{{At: 5}}}},
	{ID: 3, Profile: testusers.SubscriberProfile{Name: "Carol", Age: 61, Visits: []testusers.Visit{}}, Prefs: &testusers.SubscriberPrefs{}, Labels: map[string]string{}},
}

func TestASubscribersTypedDocumentsRoundTrip(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	encrypted, err := testusers.EncryptSubscriber(ctx, c.DefaultKeyset(), subscribers)
	if err != nil {
		t.Fatal(err)
	}
	// A nil pointer is SQL NULL; a pointer to a zero struct is a document.
	if encrypted[1].Prefs != nil || encrypted[2].Prefs == nil {
		t.Fatalf("prefs: %v %v", encrypted[1].Prefs, encrypted[2].Prefs)
	}
	if s := encrypted[0].String(); strings.Contains(s, "Alice") {
		t.Fatalf("String shows the document: %s", s)
	}
	back, err := testusers.DecryptSubscriber(ctx, c, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	// Every integer to 64 bits and the 17-digit float come back exactly,
	// in the declared types; a nil map is a JSON null, and reads back nil.
	if !reflect.DeepEqual(back, subscribers) {
		t.Fatalf("round trip:\n got %+v\nwant %+v", back, subscribers)
	}
	// One field's Encrypt writes the same document the record does: it
	// opens to the same value through the record's Decrypt.
	one, err := testusers.SubscriberFields.Profile.Encrypt(ctx, c.DefaultKeyset(), subscribers[0].Profile)
	if err != nil {
		t.Fatal(err)
	}
	rec := encrypted[0]
	rec.Profile = one
	again, err := testusers.DecryptSubscriber(ctx, c, []testusers.EncryptedSubscriber{rec})
	if err != nil || !reflect.DeepEqual(again[0].Profile, subscribers[0].Profile) {
		t.Fatalf("a field's Encrypt: %+v %v", again, err)
	}
	// A value encoding/json cannot write is refused before anything is
	// sealed, naming no value.
	bad := []testusers.Subscriber{{ID: 4, Profile: testusers.SubscriberProfile{Score: math.Inf(1)}}}
	if _, err := testusers.EncryptSubscriber(ctx, c.DefaultKeyset(), bad); !errors.Is(err, encrypt.ErrEncoding) || strings.Contains(err.Error(), "+Inf") {
		t.Fatalf("an infinity: %v", err)
	}
}

func TestASubscribersTypedNeedlesDeriveTheRawQuery(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	f := testusers.SubscriberFields.Profile
	// same derives a query twice, once from a Go value and once from the
	// JSON text encoding/json writes for it, and wants the same selector
	// set: a typed needle is that text, nothing more. Each derivation sends
	// its set in a random order of its own, so the two compare as sets.
	same := func(name string, typed, raw func() ([]byte, error)) {
		t.Helper()
		a, err := typed()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		b, err := raw()
		if err != nil {
			t.Fatalf("%s raw: %v", name, err)
		}
		if !sameSelectorSet(t, a, b) {
			t.Errorf("%s: the typed needle derives another query than its JSON text", name)
		}
	}
	bytesOf := func(v []byte, err error) ([]byte, error) { return v, err }
	same("contains, a needle struct",
		func() ([]byte, error) {
			return bytesOf(f.Contains(ctx, cipher, testusers.ProfileNeedle{Tier: ptr("gold"), Visits: []testusers.Visit{{At: 3, Place: "home"}}}))
		},
		func() ([]byte, error) {
			return bytesOf(f.Contains(ctx, cipher, json.RawMessage(`{"tier":"gold","visits":[{"at":3,"place":"home"}]}`)))
		})
	same("contains, a map",
		func() ([]byte, error) { return bytesOf(f.Contains(ctx, cipher, map[string]any{"age": 34})) },
		func() ([]byte, error) { return bytesOf(f.Contains(ctx, cipher, json.RawMessage(`{"age":34}`))) })
	same("contained by, the document type",
		func() ([]byte, error) { return bytesOf(f.ContainedBy(ctx, cipher, subscribers[1].Profile)) },
		func() ([]byte, error) {
			text, err := json.Marshal(subscribers[1].Profile)
			if err != nil {
				return nil, err
			}
			return bytesOf(f.ContainedBy(ctx, cipher, json.RawMessage(text)))
		})
	same("eq_at, a string",
		func() ([]byte, error) { return bytesOf(f.EqAt(ctx, cipher, "$.name", "Alice")) },
		func() ([]byte, error) { return bytesOf(f.EqAt(ctx, cipher, "$.name", json.RawMessage(`"Alice"`))) })
	same("eq_at, a uint64 past 2^53",
		func() ([]byte, error) { return bytesOf(f.EqAt(ctx, cipher, "$.big", uint64(math.MaxUint64))) },
		func() ([]byte, error) {
			return bytesOf(f.EqAt(ctx, cipher, "$.big", json.RawMessage(`18446744073709551615`)))
		})
	// The orderings take Go numbers; a leaf query need not repeat, so each
	// is derived and bound, not compared.
	if q, err := f.At.Age.Gt(ctx, cipher, 40); err != nil || len(q) == 0 {
		t.Fatalf("Gt(40): %v", err)
	}
	if r, err := f.At.VisitsAt.Between(ctx, cipher, int64(1), 2.5); err != nil || len(r.Low) == 0 || len(r.High) == 0 {
		t.Fatalf("Between(1, 2.5): %v", err)
	}

	// The field's own struct type is no containment needle: its zero
	// fields would narrow the query. Refused before anything is derived,
	// by value and by pointer; a type defined over it is the caller's
	// choice, and derives.
	for name, needle := range map[string]any{
		"the type":   testusers.SubscriberProfile{Tier: "gold"},
		"a pointer":  &testusers.SubscriberProfile{Tier: "gold"},
		"prefs type": testusers.SubscriberPrefs{Theme: "dark"},
	} {
		var err error
		if name == "prefs type" {
			_, err = testusers.SubscriberFields.Prefs.Contains(ctx, cipher, needle)
		} else {
			_, err = f.Contains(ctx, cipher, needle)
		}
		if !errors.Is(err, encrypt.ErrEncoding) || !strings.Contains(err.Error(), "omitempty") || strings.Contains(err.Error(), "gold") {
			t.Errorf("%s as a needle: %v", name, err)
		}
	}
	type wholeProfile testusers.SubscriberProfile
	if _, err := f.Contains(ctx, cipher, wholeProfile(subscribers[0].Profile)); err != nil {
		t.Fatalf("a type defined over the document type: %v", err)
	}
	// A map of strings is a needle of its own type.
	if _, err := testusers.SubscriberFields.Labels.Contains(ctx, cipher, map[string]string{"team": "red"}); err != nil {
		t.Fatalf("a map needle: %v", err)
	}
	// What encoding/json cannot write, and a []byte, are refused, naming
	// no value.
	type doc []byte
	type redefined json.RawMessage
	type text string
	for name, err := range map[string]error{
		"[]byte": func() error { _, err := f.Contains(ctx, cipher, []byte(`{"tier":"secret"}`)); return err }(),
		// A type defined over []byte, json.RawMessage included, has no
		// MarshalJSON and would be written as base64.
		"defined []byte": func() error { _, err := f.EqAt(ctx, cipher, "$.name", doc(`"secret"`)); return err }(),
		"redefined RawMessage": func() error {
			_, err := f.Contains(ctx, cipher, redefined(`{"tier":"secret"}`))
			return err
		}(),
		// JSON text in a Go string would be one JSON string: refused as a
		// needle, which is never what it means.
		"string needle":         func() error { _, err := f.Contains(ctx, cipher, `{"tier":"secret"}`); return err }(),
		"defined string needle": func() error { _, err := f.ContainedBy(ctx, cipher, text(`{"tier":"secret"}`)); return err }(),
		"NaN":                   func() error { _, err := f.At.Age.Lt(ctx, cipher, math.NaN()); return err }(),
		"chan":                  func() error { _, err := f.EqAt(ctx, cipher, "$.name", make(chan int)); return err }(),
	} {
		if !errors.Is(err, encrypt.ErrEncoding) || strings.Contains(err.Error(), "secret") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// sameSelectorSet reports whether two containment queries hold the same
// selector set: the same {s, vs} pairs in the same element groups, and the
// same alternative, whatever order their lists are in (the engine shuffles
// each query's set, as it does a stored document's).
func sameSelectorSet(t *testing.T, a, b []byte) bool {
	t.Helper()
	canonical := func(text []byte) string {
		var query any
		if err := json.Unmarshal(text, &query); err != nil {
			t.Fatalf("a query is JSON: %v", err)
		}
		out, err := json.Marshal(sortedSet(query))
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	return canonical(a) == canonical(b)
}

// sortedSet is a query's JSON with every list sorted by its members'
// text, recursively: one spelling for one set.
func sortedSet(v any) any {
	switch v := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, member := range v {
			out[k] = sortedSet(member)
		}
		return out
	case []any:
		out := make([]any, len(v))
		keys := make([]string, len(v))
		for i, member := range v {
			out[i] = sortedSet(member)
			text, _ := json.Marshal(out[i])
			keys[i] = string(text)
		}
		sort.Sort(byKey{out, keys})
		return out
	default:
		return v
	}
}

// byKey sorts a list by a key per member.
type byKey struct {
	items []any
	keys  []string
}

func (b byKey) Len() int           { return len(b.items) }
func (b byKey) Less(i, j int) bool { return b.keys[i] < b.keys[j] }
func (b byKey) Swap(i, j int) {
	b.items[i], b.items[j] = b.items[j], b.items[i]
	b.keys[i], b.keys[j] = b.keys[j], b.keys[i]
}
