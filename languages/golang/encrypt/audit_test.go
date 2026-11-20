package encrypt_test

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// Audit metadata. The unit tests here need no guest. The round trips run
// through the deterministic test build, and the live test reads the request
// that ZeroKMS receives.

func listIssues() encrypt.AuditMetadata {
	return encrypt.AuditMetadata{"purpose": "list issues", "request_id": "req_01J9Z3"}
}

// facts is the metadata cipher holds, as the guest receives it.
func facts(t *testing.T, cipher *encrypt.Cipher) any {
	t.Helper()
	got, err := cipher.AuditFactsForTest()
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func object(fields ...vcvalue.Field) vcvalue.Object { return fields }

// A cipher sends the facts it was given, at the types the caller wrote. A
// time is the exception: it is sent as RFC 3339 text in UTC.
func TestAuditHoldsTheFactsAsGiven(t *testing.T) {
	base := (&encrypt.Client{}).DefaultKeyset()
	if got := facts(t, base); got != nil {
		t.Fatalf("a cipher with no Audit holds %v", got)
	}
	if got := facts(t, base.Audit(nil)); got != nil {
		t.Fatalf("Audit(nil) holds %v", got)
	}
	if got := facts(t, base.Audit(encrypt.AuditMetadata{})); got != nil {
		t.Fatalf("Audit of no facts holds %v", got)
	}
	sydney := time.FixedZone("AEDT", 11*60*60)
	at := time.Date(2026, 11, 20, 10, 0, 0, 0, sydney)
	cipher := base.Audit(encrypt.AuditMetadata{
		"purpose": "export",
		"dry_run": false,
		"actor":   nil,
		"ratio":   0.25,
		"ratio32": float32(0.5),
		// Every integer type the list names, at its own width.
		"int": int(-1), "int8": int8(-8), "int16": int16(-16), "int32": int32(-32), "int64": int64(-64),
		"uint": uint(1), "uint8": uint8(8), "uint16": uint16(16), "uint32": uint32(32), "uint64": uint64(64),
		// A time is sent as RFC 3339 text in UTC, wherever it is.
		"at":       at,
		"at_nanos": time.Date(2026, 11, 20, 10, 0, 0, 123456789, time.UTC),
		"at_half":  time.Date(2026, 11, 20, 10, 0, 0, 500000000, time.UTC),
		"first":    time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC),
		"last":     time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		"tables":   []string{"users", "orders"},
		"mixed":    []any{"ok", 7, nil, at, []any{at}, map[string]any{"at": at}},
		"request":  map[string]any{"id": "req_01J9Z3"},
		"nested":   encrypt.AuditMetadata{"team": "platform"},
	})
	const utc = "2026-11-19T23:00:00Z"
	want := object(
		vcvalue.Field{Key: "actor", Value: nil},
		vcvalue.Field{Key: "at", Value: utc},
		vcvalue.Field{Key: "at_half", Value: "2026-11-20T10:00:00.5Z"},
		vcvalue.Field{Key: "at_nanos", Value: "2026-11-20T10:00:00.123456789Z"},
		vcvalue.Field{Key: "dry_run", Value: false},
		vcvalue.Field{Key: "first", Value: "0000-01-01T00:00:00Z"},
		vcvalue.Field{Key: "int", Value: int64(-1)},
		vcvalue.Field{Key: "int16", Value: int16(-16)},
		vcvalue.Field{Key: "int32", Value: int32(-32)},
		vcvalue.Field{Key: "int64", Value: int64(-64)},
		vcvalue.Field{Key: "int8", Value: int8(-8)},
		vcvalue.Field{Key: "last", Value: "9999-12-31T23:59:59Z"},
		vcvalue.Field{Key: "mixed", Value: []any{
			"ok", int64(7), nil, utc, []any{utc}, object(vcvalue.Field{Key: "at", Value: utc}),
		}},
		vcvalue.Field{Key: "nested", Value: object(vcvalue.Field{Key: "team", Value: "platform"})},
		vcvalue.Field{Key: "purpose", Value: "export"},
		vcvalue.Field{Key: "ratio", Value: 0.25},
		vcvalue.Field{Key: "ratio32", Value: float32(0.5)},
		vcvalue.Field{Key: "request", Value: object(vcvalue.Field{Key: "id", Value: "req_01J9Z3"})},
		vcvalue.Field{Key: "tables", Value: []any{"users", "orders"}},
		vcvalue.Field{Key: "uint", Value: uint64(1)},
		vcvalue.Field{Key: "uint16", Value: uint16(16)},
		vcvalue.Field{Key: "uint32", Value: uint32(32)},
		vcvalue.Field{Key: "uint64", Value: uint64(64)},
		vcvalue.Field{Key: "uint8", Value: uint8(8)},
	)
	if got := facts(t, cipher); !reflect.DeepEqual(got, want) {
		t.Fatalf("facts = %#v\nwant    %#v", got, want)
	}
}

// Audit adds to the facts a cipher has, a later fact replaces an earlier
// one that has the same key, and the cipher Audit was called on is unchanged.
func TestAuditAddsFactsAndALaterFactReplaces(t *testing.T) {
	base := (&encrypt.Client{}).DefaultKeyset()
	service := base.Audit(encrypt.AuditMetadata{"service": "billing", "purpose": "default"})
	request := service.Audit(encrypt.AuditMetadata{"request_id": "req_01J9Z3", "purpose": "export"})

	if got := facts(t, base); got != nil {
		t.Errorf("the first cipher now holds %v", got)
	}
	wantService := object(
		vcvalue.Field{Key: "purpose", Value: "default"},
		vcvalue.Field{Key: "service", Value: "billing"},
	)
	if got := facts(t, service); !reflect.DeepEqual(got, wantService) {
		t.Errorf("the service cipher holds %#v, want %#v", got, wantService)
	}
	wantRequest := object(
		vcvalue.Field{Key: "purpose", Value: "export"},
		vcvalue.Field{Key: "request_id", Value: "req_01J9Z3"},
		vcvalue.Field{Key: "service", Value: "billing"},
	)
	if got := facts(t, request); !reflect.DeepEqual(got, wantRequest) {
		t.Errorf("the request cipher holds %#v, want %#v", got, wantRequest)
	}
	// Scope and Bind keep the facts.
	if got := facts(t, request.Scope("tenant-42").Bind(int64(7))); !reflect.DeepEqual(got, wantRequest) {
		t.Errorf("after Scope and Bind the cipher holds %#v", got)
	}
}

// The cipher keeps its own copy: a change to the caller's map, or to a
// slice or a map inside it, does not change what the cipher sends.
func TestAuditKeepsItsOwnCopy(t *testing.T) {
	tables := []string{"users"}
	request := map[string]any{"id": "req_01J9Z3"}
	metadata := encrypt.AuditMetadata{"purpose": "export", "tables": tables, "request": request}
	cipher := (&encrypt.Client{}).DefaultKeyset().Audit(metadata)
	before := facts(t, cipher)

	metadata["purpose"] = "changed"
	metadata["added"] = true
	tables[0] = "changed"
	request["id"] = "changed"

	if after := facts(t, cipher); !reflect.DeepEqual(before, after) {
		t.Fatalf("the cipher's facts changed with the caller's map:\n%#v\n%#v", before, after)
	}
}

// Printing a cipher shows none of its facts. A fact can be personal data,
// and a debug log is not the audit log.
func TestPrintingACipherDoesNotShowItsFacts(t *testing.T) {
	cipher := (&encrypt.Client{}).DefaultKeyset().Audit(encrypt.AuditMetadata{"actor": "alice@example.com"})
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if shown := fmt.Sprintf(verb, cipher); strings.Contains(shown, "alice@example.com") {
			t.Errorf("%s shows the fact: %s", verb, shown)
		}
		if shown := fmt.Sprintf(verb, *cipher); strings.Contains(shown, "alice@example.com") {
			t.Errorf("%s of the value shows the fact: %s", verb, shown)
		}
	}
}

// A value of a type the list does not name is reported by the first call,
// as ErrEncoding, and never by a panic. The error names the fact and the
// type, and shows no value. An earlier refusal is the one reported.
func TestAValueOfAnotherTypeIsReportedByTheFirstCall(t *testing.T) {
	ctx := context.Background()
	client := &encrypt.Client{}
	type window struct{ From time.Time }
	type requestID string
	at := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	cycle := map[string]any{}
	cycle["again"] = cycle
	deep := []any{"leak-marker"}
	for range 40 {
		deep = []any{deep}
	}
	for name, tc := range map[string]struct {
		value any
		names string
	}{
		"bytes":                   {[]byte("leak-marker"), "[]byte"},
		"a byte array":            {[4]byte{1, 2, 3, 4}, "[4]uint8"},
		"a struct":                {window{From: at}, "window"},
		"a pointer":               {&at, "*time.Time"},
		"a named string":          {requestID("leak-marker"), "requestID"},
		"a slice of integers":     {[]int{1}, "[]int"},
		"a slice of times":        {[]time.Time{at}, "[]time.Time"},
		"a map keyed by int":      {map[int]string{1: "leak-marker"}, "map[int]string"},
		"a channel":               {make(chan int), "chan int"},
		"a function":              {func() {}, "func()"},
		"text not in UTF-8":       {"leak-marker\xff", "UTF-8"},
		"a time in year 10000":    {time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), "RFC 3339"},
		"a time before year 0":    {time.Date(-1, 12, 31, 0, 0, 0, 0, time.UTC), "RFC 3339"},
		"bytes inside a list":     {[]any{"ok", []byte("leak-marker")}, "[]byte"},
		"bytes inside a map":      {map[string]any{"inner": []byte("leak-marker")}, "[]byte"},
		"a map that holds itself": {cycle, "levels deep"},
		"a list nested too deep":  {deep, "levels deep"},
	} {
		t.Run(name, func(t *testing.T) {
			metadata := encrypt.AuditMetadata{"the_fact": tc.value}
			cipher := client.DefaultKeyset().Audit(metadata)
			for call, err := range map[string]error{
				"Encrypt":                    second(testusers.Encrypt(ctx, cipher, people)),
				"Decrypt":                    second(testusers.Decrypt(ctx, cipher, nil)),
				"Decrypt through the client": second(testusers.Decrypt(ctx, client.Audit(metadata), nil)),
				// A later Audit of good facts does not clear the refusal.
				"Encrypt after a later Audit": second(testusers.Encrypt(ctx, cipher.Audit(listIssues()), people)),
			} {
				switch {
				case !errors.Is(err, encrypt.ErrEncoding):
					t.Errorf("%s: %v, want ErrEncoding", call, err)
				case !strings.Contains(err.Error(), "Audit") || !strings.Contains(err.Error(), `"the_fact"`) || !strings.Contains(err.Error(), tc.names):
					t.Errorf("%s: %v, want an error that names Audit, the fact and %q", call, err, tc.names)
				case strings.Contains(err.Error(), "leak-marker"):
					t.Errorf("%s shows the value: %v", call, err)
				}
			}
		})
	}
	badKey := client.DefaultKeyset().Audit(encrypt.AuditMetadata{"leak-marker\xff": true})
	if _, err := testusers.Encrypt(ctx, badKey, people); !errors.Is(err, encrypt.ErrEncoding) || strings.Contains(err.Error(), "leak-marker") {
		t.Errorf("Encrypt with a key that is not UTF-8: %v, want ErrEncoding that does not show the key", err)
	}
	scoped := client.DefaultKeyset().Scope(struct{}{}).Audit(encrypt.AuditMetadata{"fact": make(chan int)})
	if _, err := testusers.Encrypt(ctx, scoped, people); !errors.Is(err, encrypt.ErrEncoding) || !strings.Contains(err.Error(), "Scope") {
		t.Errorf("Encrypt: %v, want the Scope refusal, which came first", err)
	}
	var none *encrypt.Client
	if _, err := testusers.Decrypt(ctx, none.Audit(listIssues()), nil); !errors.Is(err, encrypt.ErrEncoding) {
		t.Errorf("Decrypt through a nil client: %v, want ErrEncoding", err)
	}
	// 32 levels are taken: the limit refuses only what is deeper.
	nested := []any{"ok"}
	for range 30 {
		nested = []any{nested}
	}
	if got := facts(t, client.DefaultKeyset().Audit(encrypt.AuditMetadata{"fact": nested})); got == nil {
		t.Error("metadata nested 32 levels deep was not kept")
	}
}

// Every call that asks for data keys works through a cipher that has
// metadata, and so does a query, which sends none.
func TestAuditedCipherRoundTrips(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	plain := c.DefaultKeyset()
	cipher := plain.Audit(encrypt.AuditMetadata{
		"purpose": "list issues",
		"rows":    len(people),
		"ratio":   math.NaN(),
		"at":      time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC),
		"request": map[string]any{"id": "req_01J9Z3", "tables": []string{"users"}},
	})

	encrypted, err := testusers.Encrypt(ctx, cipher, people)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	want := append([]testusers.User(nil), people...)
	want[0].Internal = ""
	for name, by := range map[string]encrypt.Decrypter{
		"the audited cipher": cipher,
		"the plain cipher":   plain,
		"the audited client": c.Audit(listIssues()),
		"the plain client":   c,
	} {
		back, err := testusers.Decrypt(ctx, by, encrypted)
		if err != nil {
			t.Fatalf("Decrypt through %s: %v", name, err)
		}
		if !reflect.DeepEqual(back, want) {
			t.Fatalf("Decrypt through %s = %+v, want %+v", name, back, want)
		}
	}

	// A query derives the same term with and without metadata. The guest
	// refuses metadata on a term call, so this also shows the SDK sends none.
	audited, err := testusers.Fields.Email.Eq(ctx, cipher, "bob@example.com")
	if err != nil {
		t.Fatalf("a query through the audited cipher: %v", err)
	}
	unaudited, err := testusers.Fields.Email.Eq(ctx, plain, "bob@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !audited.Equal(unaudited) || !audited.Equal(encrypted[1].Email.Equality) {
		t.Error("the audited cipher derives another query term")
	}
	one, err := testusers.Fields.Email.Encrypt(ctx, cipher, "bob@example.com")
	if err != nil || !one.Equality.Equal(unaudited) {
		t.Errorf("a field's own Encrypt through the audited cipher: %v", err)
	}
}

// The guest refuses metadata on a term call. A term asks for no data key,
// so a host that sent facts there would log nothing.
func TestTheGuestRefusesAuditOnATermCall(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	context := []any{"users", "email"}
	if _, err := c.DefaultKeyset().TermWithAuditForTest(ctx, "bob@example.com", context); err != nil {
		t.Fatalf("a term call with no metadata: %v", err)
	}
	_, err := c.DefaultKeyset().Audit(listIssues()).TermWithAuditForTest(ctx, "bob@example.com", context)
	if !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("a term call with metadata: %v, want ErrEncoding", err)
	}
}

// ZeroKMS reads a number as an int64 or a float64. Whether an integer fits
// is the engine's rule, so the engine refuses one that does not. The
// refusal reaches every call that sends the metadata, and the error does
// not show the value.
func TestAnIntegerAboveInt64IsRefusedByTheEngine(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	encrypted, err := testusers.Encrypt(ctx, c.DefaultKeyset(), people)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]any{
		"at the top":    uint64(math.MaxInt64) + 1,
		"inside a list": []any{"ok", uint64(math.MaxUint64)},
		"inside a map":  map[string]any{"inner": uint64(math.MaxInt64) + 1},
	} {
		t.Run(name, func(t *testing.T) {
			metadata := encrypt.AuditMetadata{"fact": value}
			cipher := c.DefaultKeyset().Audit(metadata)
			for call, err := range map[string]error{
				"Encrypt":                    second(testusers.Encrypt(ctx, cipher, people)),
				"Decrypt":                    second(testusers.Decrypt(ctx, cipher, encrypted)),
				"Decrypt through the client": second(testusers.Decrypt(ctx, c.Audit(metadata), encrypted)),
			} {
				if !errors.Is(err, encrypt.ErrEncoding) {
					t.Errorf("%s: %v, want ErrEncoding", call, err)
				} else if strings.Contains(err.Error(), "9223372036854775808") || strings.Contains(err.Error(), "18446744073709551615") {
					t.Errorf("%s shows the value: %v", call, err)
				}
			}
		})
	}
	// The largest int64 has a form, as a uint64 too.
	fits := c.DefaultKeyset().Audit(encrypt.AuditMetadata{"fact": uint64(math.MaxInt64)})
	if _, err := testusers.Encrypt(ctx, fits, people); err != nil {
		t.Errorf("Encrypt with the largest int64: %v", err)
	}
}

func second[T any](_ T, err error) error { return err }
