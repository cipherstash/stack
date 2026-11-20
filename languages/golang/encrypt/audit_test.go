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

// A cipher sends the facts it was given, at the types the caller wrote.
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
	type window struct{ From, To time.Time }
	cipher := base.Audit(encrypt.AuditMetadata{
		"purpose": "export",
		"rows":    250,
		// A time is sent as RFC 3339 text in UTC, wherever it is.
		"at":       at,
		"at_nanos": time.Date(2026, 11, 20, 10, 0, 0, 123456789, time.UTC),
		"at_ptr":   &at,
		"times":    []time.Time{at},
		"window":   window{From: at, To: at.Add(time.Hour)},
		"mixed":    []any{"ok", at, map[string]any{"at": at}},
		"dry_run":  false,
		"actor":    nil,
		"ratio":    0.25,
		"tables":   []string{"users", "orders"},
		"request":  map[string]any{"id": "req_01J9Z3"},
	})
	const utc = "2026-11-19T23:00:00Z"
	want := object(
		vcvalue.Field{Key: "actor", Value: nil},
		vcvalue.Field{Key: "at", Value: utc},
		vcvalue.Field{Key: "at_nanos", Value: "2026-11-20T10:00:00.123456789Z"},
		vcvalue.Field{Key: "at_ptr", Value: utc},
		vcvalue.Field{Key: "dry_run", Value: false},
		vcvalue.Field{Key: "mixed", Value: []any{"ok", utc, object(vcvalue.Field{Key: "at", Value: utc})}},
		vcvalue.Field{Key: "purpose", Value: "export"},
		vcvalue.Field{Key: "ratio", Value: 0.25},
		vcvalue.Field{Key: "request", Value: object(vcvalue.Field{Key: "id", Value: "req_01J9Z3"})},
		vcvalue.Field{Key: "rows", Value: int64(250)},
		vcvalue.Field{Key: "tables", Value: []any{"users", "orders"}},
		vcvalue.Field{Key: "times", Value: []any{utc}},
		vcvalue.Field{Key: "window", Value: object(
			vcvalue.Field{Key: "From", Value: utc},
			vcvalue.Field{Key: "To", Value: "2026-11-20T00:00:00Z"},
		)},
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

// A Go value the SDK cannot send is reported by the first call, as
// ErrEncoding, and never by a panic. An earlier refusal is the one reported.
func TestAValueTheSDKCannotSendIsReportedByTheFirstCall(t *testing.T) {
	ctx := context.Background()
	client := &encrypt.Client{}
	for name, value := range map[string]any{
		"a channel":          make(chan int),
		"a function":         func() {},
		"text not in UTF-8":  "\xff",
		"a map keyed by int": map[int]string{1: "a"},
	} {
		t.Run(name, func(t *testing.T) {
			metadata := encrypt.AuditMetadata{"fact": value}
			cipher := client.DefaultKeyset().Audit(metadata)
			if _, err := testusers.Encrypt(ctx, cipher, people); !errors.Is(err, encrypt.ErrEncoding) || !strings.Contains(err.Error(), "Audit") {
				t.Errorf("Encrypt: %v, want ErrEncoding from Audit", err)
			}
			if _, err := testusers.Decrypt(ctx, cipher, nil); !errors.Is(err, encrypt.ErrEncoding) || !strings.Contains(err.Error(), "Audit") {
				t.Errorf("Decrypt: %v, want ErrEncoding from Audit", err)
			}
			if _, err := testusers.Decrypt(ctx, client.Audit(metadata), nil); !errors.Is(err, encrypt.ErrEncoding) || !strings.Contains(err.Error(), "Audit") {
				t.Errorf("Decrypt through the client: %v, want ErrEncoding from Audit", err)
			}
			// A later Audit of good facts does not clear the refusal.
			later := cipher.Audit(listIssues())
			if _, err := testusers.Encrypt(ctx, later, people); !errors.Is(err, encrypt.ErrEncoding) {
				t.Errorf("Encrypt after a later Audit: %v, want ErrEncoding", err)
			}
		})
	}
	scoped := client.DefaultKeyset().Scope(struct{}{}).Audit(encrypt.AuditMetadata{"fact": make(chan int)})
	if _, err := testusers.Encrypt(ctx, scoped, people); !errors.Is(err, encrypt.ErrEncoding) || !strings.Contains(err.Error(), "Scope") {
		t.Errorf("Encrypt: %v, want the Scope refusal, which came first", err)
	}
	var none *encrypt.Client
	if _, err := testusers.Decrypt(ctx, none.Audit(listIssues()), nil); !errors.Is(err, encrypt.ErrEncoding) {
		t.Errorf("Decrypt through a nil client: %v, want ErrEncoding", err)
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

// ZeroKMS has no form for bytes or for an integer above the largest int64.
// The engine refuses each one before any key is requested, and the error
// does not show the value.
func TestAuditValuesZeroKMSHasNoFormFor(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	encrypted, err := testusers.Encrypt(ctx, c.DefaultKeyset(), people)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]any{
		"bytes":                      []byte("leak-marker"),
		"an integer above int64":     uint64(math.MaxInt64) + 1,
		"bytes inside a list":        []any{"ok", []byte("leak-marker")},
		"bytes inside a nested fact": map[string]any{"inner": []byte("leak-marker")},
	} {
		t.Run(name, func(t *testing.T) {
			metadata := encrypt.AuditMetadata{"fact": value}
			cipher := c.DefaultKeyset().Audit(metadata)
			encrypt.ResetSends(c)
			for call, err := range map[string]error{
				"Encrypt":                    second(testusers.Encrypt(ctx, cipher, people)),
				"Decrypt":                    second(testusers.Decrypt(ctx, cipher, encrypted)),
				"Decrypt through the client": second(testusers.Decrypt(ctx, c.Audit(metadata), encrypted)),
			} {
				if !errors.Is(err, encrypt.ErrEncoding) {
					t.Errorf("%s: %v, want ErrEncoding", call, err)
				} else if strings.Contains(err.Error(), "leak-marker") || strings.Contains(err.Error(), "9223372036854775808") {
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
