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
	return encrypt.NewAuditMetadata().
		Text("purpose", "list issues").
		Text("request_id", "req_01J9Z3")
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

// sent is what a cipher given metadata sends, as the guest receives it.
func sent(t *testing.T, metadata encrypt.AuditMetadata) any {
	t.Helper()
	return facts(t, (&encrypt.Client{}).DefaultKeyset().Audit(metadata))
}

func object(fields ...vcvalue.Field) vcvalue.Object { return fields }

func field(key string, value any) vcvalue.Field { return vcvalue.Field{Key: key, Value: value} }

// Each method sends its fact as the caller gave it. A time is the
// exception: it is sent as RFC 3339 text in UTC.
func TestAuditMetadataSendsEachFactAsBuilt(t *testing.T) {
	if got := sent(t, encrypt.NewAuditMetadata()); got != nil {
		t.Fatalf("metadata with no facts sends %v", got)
	}
	if got := sent(t, encrypt.AuditMetadata{}); got != nil {
		t.Fatalf("the zero value sends %v", got)
	}
	sydney := time.FixedZone("AEDT", 11*60*60)
	at := time.Date(2026, 11, 20, 10, 0, 0, 0, sydney)
	const utc = "2026-11-19T23:00:00Z"
	metadata := encrypt.NewAuditMetadata().
		Text("purpose", "export").
		Bool("dry_run", false).
		Int("rows", -250).
		Int64("cursor", math.MaxInt64).
		Float("ratio", 0.25).
		Null("actor").
		// A time is sent as RFC 3339 text in UTC, whatever its zone.
		Time("at", at).
		Time("at_nanos", time.Date(2026, 11, 20, 10, 0, 0, 123456789, time.UTC)).
		Time("at_half", time.Date(2026, 11, 20, 10, 0, 0, 500000000, time.UTC)).
		Time("first", time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC)).
		Time("last", time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)).
		TextList("tables", "users", "orders").
		TextList("none").
		List("mixed", encrypt.NewAuditList().
			Text("ok").
			Bool(true, false).
			Int(7).
			Int64(math.MinInt64).
			Float(0.5).
			Time(at).
			Null().
			List(encrypt.NewAuditList().Time(at)).
			Map(encrypt.NewAuditMetadata().Time("at", at))).
		List("empty", encrypt.NewAuditList()).
		Map("request", encrypt.NewAuditMetadata().Text("id", "req_01J9Z3")).
		Map("nothing", encrypt.NewAuditMetadata())
	want := object(
		field("actor", nil),
		field("at", utc),
		field("at_half", "2026-11-20T10:00:00.5Z"),
		field("at_nanos", "2026-11-20T10:00:00.123456789Z"),
		field("cursor", int64(math.MaxInt64)),
		field("dry_run", false),
		field("empty", []any{}),
		field("first", "0000-01-01T00:00:00Z"),
		field("last", "9999-12-31T23:59:59Z"),
		field("mixed", []any{
			"ok", true, false, int64(7), int64(math.MinInt64), 0.5, utc, nil,
			[]any{utc}, object(field("at", utc)),
		}),
		field("none", []any{}),
		field("nothing", vcvalue.Object{}),
		field("purpose", "export"),
		field("ratio", 0.25),
		field("request", object(field("id", "req_01J9Z3"))),
		field("rows", int64(-250)),
		field("tables", []any{"users", "orders"}),
	)
	if got := sent(t, metadata); !reflect.DeepEqual(got, want) {
		t.Fatalf("sent %#v\nwant %#v", got, want)
	}
}

// A method returns new metadata and leaves its own unchanged, so two
// branches from one base do not share facts. A later fact replaces an
// earlier one that has the same key. A list behaves the same way.
func TestAMethodReturnsNewMetadata(t *testing.T) {
	base := encrypt.NewAuditMetadata().Text("service", "billing").Text("purpose", "default")
	export := base.Text("purpose", "export")
	list := base.Text("purpose", "list").Int("rows", 2)

	wantBase := object(field("purpose", "default"), field("service", "billing"))
	if got := sent(t, base); !reflect.DeepEqual(got, wantBase) {
		t.Errorf("the base sends %#v, want %#v", got, wantBase)
	}
	wantExport := object(field("purpose", "export"), field("service", "billing"))
	if got := sent(t, export); !reflect.DeepEqual(got, wantExport) {
		t.Errorf("the first branch sends %#v, want %#v", got, wantExport)
	}
	wantList := object(field("purpose", "list"), field("rows", int64(2)), field("service", "billing"))
	if got := sent(t, list); !reflect.DeepEqual(got, wantList) {
		t.Errorf("the second branch sends %#v, want %#v", got, wantList)
	}

	hosts := encrypt.NewAuditList().Text("db-1")
	first, second := hosts.Text("db-2"), hosts.Text("db-3")
	got := sent(t, encrypt.NewAuditMetadata().List("base", hosts).List("first", first).List("second", second))
	want := object(
		field("base", []any{"db-1"}),
		field("first", []any{"db-1", "db-2"}),
		field("second", []any{"db-1", "db-3"}),
	)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the lists send %#v, want %#v", got, want)
	}
}

// Audit adds to the facts a cipher has, a later fact replaces an earlier
// one that has the same key, and the cipher Audit was called on is unchanged.
func TestAuditAddsFactsAndALaterFactReplaces(t *testing.T) {
	base := (&encrypt.Client{}).DefaultKeyset()
	service := base.Audit(encrypt.NewAuditMetadata().Text("service", "billing").Text("purpose", "default"))
	request := service.Audit(encrypt.NewAuditMetadata().Text("request_id", "req_01J9Z3").Text("purpose", "export"))

	if got := facts(t, base); got != nil {
		t.Errorf("the first cipher now holds %v", got)
	}
	wantService := object(field("purpose", "default"), field("service", "billing"))
	if got := facts(t, service); !reflect.DeepEqual(got, wantService) {
		t.Errorf("the service cipher holds %#v, want %#v", got, wantService)
	}
	wantRequest := object(
		field("purpose", "export"),
		field("request_id", "req_01J9Z3"),
		field("service", "billing"),
	)
	if got := facts(t, request); !reflect.DeepEqual(got, wantRequest) {
		t.Errorf("the request cipher holds %#v, want %#v", got, wantRequest)
	}
	// Metadata with no facts changes nothing, and Scope and Bind keep the
	// facts.
	if got := facts(t, request.Audit(encrypt.NewAuditMetadata())); !reflect.DeepEqual(got, wantRequest) {
		t.Errorf("after Audit of no facts the cipher holds %#v", got)
	}
	if got := facts(t, request.Scope("tenant-42").Bind(int64(7))); !reflect.DeepEqual(got, wantRequest) {
		t.Errorf("after Scope and Bind the cipher holds %#v", got)
	}
}

// Printing metadata shows its keys, in order, and never a value. Printing
// a list or a cipher shows no fact at all. A fact can be personal data, and
// a debug log is not the audit log.
func TestPrintingShowsNoValue(t *testing.T) {
	list := encrypt.NewAuditList().Text("alice@example.com")
	metadata := encrypt.NewAuditMetadata().
		Text("purpose", "export").
		Text("actor", "alice@example.com").
		List("seen_by", list)
	if got, want := metadata.String(), "AuditMetadata{keys: [actor purpose seen_by]}"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	if got, want := encrypt.NewAuditMetadata().String(), "AuditMetadata{keys: []}"; got != want {
		t.Errorf("String() of no facts = %q, want %q", got, want)
	}
	cipher := (&encrypt.Client{}).DefaultKeyset().Audit(metadata)
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		for name, value := range map[string]any{
			"the metadata":             metadata,
			"a pointer to it":          &metadata,
			"the list":                 list,
			"the cipher":               cipher,
			"the cipher's value":       *cipher,
			"a struct that holds both": struct{ m, l any }{metadata, list},
		} {
			if shown := fmt.Sprintf(verb, value); strings.Contains(shown, "alice@example.com") || strings.Contains(shown, "export") {
				t.Errorf("%s of %s shows a value: %s", verb, name, shown)
			}
		}
	}
}

// What the compiler cannot check is reported by the first call, as
// ErrEncoding, and never by a panic. The error names Audit and the fact,
// and shows no value. The first refusal is the one reported.
func TestAValueTheCompilerCannotCheckIsReportedByTheFirstCall(t *testing.T) {
	ctx := context.Background()
	client := &encrypt.Client{}
	const badText = "leak-marker\xff"
	tooLate := time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	tooEarly := time.Date(-1, 12, 31, 0, 0, 0, 0, time.UTC)
	// 32 levels are taken, and 33 are refused.
	deepMap := encrypt.NewAuditMetadata().Text("leaf", "leak-marker")
	for range 31 {
		deepMap = encrypt.NewAuditMetadata().Map("inner", deepMap)
	}
	deepList := encrypt.NewAuditList().Text("leak-marker")
	for range 30 {
		deepList = encrypt.NewAuditList().List(deepList)
	}
	for name, metadata := range map[string]encrypt.AuditMetadata{
		"the deepest map":  deepMap,
		"the deepest list": encrypt.NewAuditMetadata().List("the_fact", deepList),
	} {
		cipher := client.DefaultKeyset().Audit(metadata)
		if got, err := cipher.AuditFactsForTest(); err != nil || got == nil {
			t.Errorf("%s was refused or not kept: %v", name, err)
		}
	}

	base := encrypt.NewAuditMetadata().Text("purpose", "export")
	for name, tc := range map[string]struct {
		metadata encrypt.AuditMetadata
		names    string
	}{
		"text":                 {base.Text("the_fact", badText), "UTF-8"},
		"text in a text list":  {base.TextList("the_fact", "ok", badText), "UTF-8"},
		"text in a list":       {base.List("the_fact", encrypt.NewAuditList().Bool(true).Text(badText)), "UTF-8"},
		"text in a nested map": {base.Map("the_fact", encrypt.NewAuditMetadata().Text("inner", badText)), `"inner"`},
		"text in a map in a list": {
			base.List("the_fact", encrypt.NewAuditList().Map(encrypt.NewAuditMetadata().Text("inner", badText))),
			`"inner"`,
		},
		"text in a list in a list": {
			base.List("the_fact", encrypt.NewAuditList().List(encrypt.NewAuditList().Text(badText))),
			"UTF-8",
		},
		"a time in year 10000":       {base.Time("the_fact", tooLate), "RFC 3339"},
		"a time before year 0":       {base.Time("the_fact", tooEarly), "RFC 3339"},
		"a time in a list":           {base.List("the_fact", encrypt.NewAuditList().Time(time.Now(), tooLate)), "RFC 3339"},
		"a map nested too deep":      {base.Map("the_fact", deepMap), "levels deep"},
		"a list nested too deep":     {base.List("the_fact", encrypt.NewAuditList().List(deepList)), "levels deep"},
		"a refusal, then good facts": {base.Text("the_fact", badText).Text("later", "ok").Int("rows", 2), "UTF-8"},
		"two refusals":               {base.Text("the_fact", badText).Time("other", tooLate), "UTF-8"},
	} {
		t.Run(name, func(t *testing.T) {
			cipher := client.DefaultKeyset().Audit(tc.metadata)
			for call, err := range map[string]error{
				"Encrypt":                    second(testusers.Encrypt(ctx, cipher, people)),
				"Decrypt":                    second(testusers.Decrypt(ctx, cipher, nil)),
				"Decrypt through the client": second(testusers.Decrypt(ctx, client.Audit(tc.metadata), nil)),
				// A later Audit of good facts does not clear the refusal.
				"Encrypt after a later Audit": second(testusers.Encrypt(ctx, cipher.Audit(listIssues()), people)),
			} {
				switch {
				case !errors.Is(err, encrypt.ErrEncoding):
					t.Errorf("%s: %v, want ErrEncoding", call, err)
				case !strings.Contains(err.Error(), "Audit") || !strings.Contains(err.Error(), tc.names):
					t.Errorf("%s: %v, want an error that names Audit and %q", call, err, tc.names)
				case !strings.Contains(err.Error(), `"the_fact"`) && !strings.Contains(tc.names, "levels"):
					t.Errorf("%s: %v, want an error that names the fact", call, err)
				case strings.Contains(err.Error(), "leak-marker"):
					t.Errorf("%s shows the value: %v", call, err)
				}
			}
		})
	}
	badKey := client.DefaultKeyset().Audit(encrypt.NewAuditMetadata().Bool(badText, true))
	if _, err := testusers.Encrypt(ctx, badKey, people); !errors.Is(err, encrypt.ErrEncoding) || strings.Contains(err.Error(), "leak-marker") {
		t.Errorf("Encrypt with a key that is not UTF-8: %v, want ErrEncoding that does not show the key", err)
	}
	scoped := client.DefaultKeyset().Scope(struct{}{}).Audit(encrypt.NewAuditMetadata().Text("fact", badText))
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
	cipher := plain.Audit(encrypt.NewAuditMetadata().
		Text("purpose", "list issues").
		Int("rows", len(people)).
		Float("ratio", math.NaN()).
		Time("at", time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)).
		Null("actor").
		Map("request", encrypt.NewAuditMetadata().Text("id", "req_01J9Z3").TextList("tables", "users")))

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

// The builder cannot build a value that ZeroKMS has no form for: there is
// no method for bytes, for a uint64 or for a typed time. The guest still
// refuses each one, for a binding that sends it anyway. This test sends
// them past the builder. The refusal reaches every call that sends the
// metadata, and the error does not show the value.
func TestTheGuestRefusesWhatTheBuilderCannotBuild(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	encrypted, err := testusers.Encrypt(ctx, c.DefaultKeyset(), people)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]any{
		"an integer above int64":   uint64(math.MaxInt64) + 1,
		"bytes":                    []byte("leak-marker"),
		"a typed time":             time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC),
		"an integer inside a list": []any{"ok", uint64(math.MaxUint64)},
		"bytes inside a map":       map[string]any{"inner": []byte("leak-marker")},
	} {
		t.Run(name, func(t *testing.T) {
			cipher := c.DefaultKeyset().AuditUncheckedForTest(map[string]any{"fact": value})
			for call, err := range map[string]error{
				"Encrypt": second(testusers.Encrypt(ctx, cipher, people)),
				"Decrypt": second(testusers.Decrypt(ctx, cipher, encrypted)),
			} {
				if !errors.Is(err, encrypt.ErrEncoding) {
					t.Errorf("%s: %v, want ErrEncoding", call, err)
				} else if strings.Contains(err.Error(), "leak-marker") || strings.Contains(err.Error(), "9223372036854775808") || strings.Contains(err.Error(), "18446744073709551615") {
					t.Errorf("%s shows the value: %v", call, err)
				}
			}
		})
	}
	// The largest int64 has a form, as a uint64 too.
	fits := c.DefaultKeyset().AuditUncheckedForTest(map[string]any{"fact": uint64(math.MaxInt64)})
	if _, err := testusers.Encrypt(ctx, fits, people); err != nil {
		t.Errorf("Encrypt with the largest int64: %v", err)
	}
}

func second[T any](_ T, err error) error { return err }
