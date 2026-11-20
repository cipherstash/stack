package encrypt_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// Round trips through real ZeroKMS, through the generated API. See
// live_internal_test.go for the variables that enable them.

var livePeople = []testusers.User{
	{ID: 1, Age: 34, Email: "alice@example.com", Notes: "likes cats", Internal: "never stored"},
	{ID: 2, Age: 29, Email: "bob@example.com", Notes: "likes dogs"},
}

func TestLiveRecordsAndTerms(t *testing.T) {
	c := encrypt.LiveClient(t)
	ctx := t.Context()
	cipher := c.DefaultKeyset()

	encrypt.ResetSends(c)
	encrypted, err := testusers.Encrypt(ctx, cipher, livePeople)
	if err != nil {
		t.Fatal(err)
	}
	if n := encrypt.Sends(c); n != 1 {
		t.Errorf("Encrypt made %d ZeroKMS calls for %d rows, want 1", n, len(livePeople))
	}
	if len(encrypted) != 2 || len(encrypted[0].Age.Equality) != 32 || encrypted[0].Email.Match == nil || encrypted[0].Age.Ore == nil || encrypted[0].ID != 1 {
		t.Fatalf("encrypted = %+v", encrypted)
	}

	probe, err := testusers.Fields.Age.Eq(ctx, cipher, 34)
	if err != nil {
		t.Fatal(err)
	}
	if !probe.Equal(encrypted[0].Age.Equality) {
		t.Error("probe does not equal the stored equality term")
	}
	if probe.Equal(encrypted[1].Age.Equality) {
		t.Error("probe equals another value's term")
	}

	want := append([]testusers.User(nil), livePeople...)
	want[0].Internal = "" // left out: never stored
	encrypt.ResetSends(c)
	back, err := testusers.Decrypt(ctx, cipher, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if n := encrypt.Sends(c); n != 1 {
		t.Errorf("Decrypt made %d ZeroKMS calls, want 1", n)
	}
	if !reflect.DeepEqual(back, want) {
		t.Fatalf("decrypted %+v, want %+v", back, want)
	}
	// The client opens too, under whichever keyset sealed each row.
	if back, err := testusers.Decrypt(ctx, c, encrypted[1:]); err != nil || back[0].Email != "bob@example.com" {
		t.Fatalf("Decrypt through the client: %v %+v", err, back)
	}

	// A context extension is part of the identity: the write, the query
	// and the read all go through the extended cipher.
	tenant7, tenant8 := cipher.Extend(uint64(7)), cipher.Extend(uint64(8))
	ext, err := testusers.Encrypt(ctx, tenant7, livePeople)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testusers.Decrypt(ctx, cipher, ext); !errors.Is(err, encrypt.ErrForbidden) && !errors.Is(err, encrypt.ErrAuthentication) {
		t.Fatalf("extended record opened without its extension: %v", err)
	}
	if _, err := testusers.Decrypt(ctx, tenant7, ext); err != nil {
		t.Fatalf("extended record with its extension: %v", err)
	}
	other, err := testusers.Encrypt(ctx, tenant8, livePeople)
	if err != nil {
		t.Fatal(err)
	}
	scoped, err := testusers.Fields.Email.Eq(ctx, tenant7, "bob@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !scoped.Equal(ext[1].Email.Equality) {
		t.Error("tenant probe does not equal the term written under the same extension")
	}
	if scoped.Equal(other[1].Email.Equality) || scoped.Equal(encrypted[1].Email.Equality) {
		t.Error("tenant probe equals another tenant's or the unextended term")
	}
}

// Audit metadata reaches ZeroKMS as the unverified context of each data-key
// request, from a cipher and from the client. A call with no metadata sends
// an empty one, and a query makes no request to send any with.
func TestLiveAuditMetadataReachesZeroKMS(t *testing.T) {
	c := encrypt.LiveClient(t)
	ctx := t.Context()
	requests := encrypt.RecordRequests(c)
	metadata := encrypt.AuditMetadata{
		"purpose": "live audit test",
		"rows":    len(livePeople),
		"request": map[string]any{"id": "req_01J9Z3"},
	}
	want := map[string]any{
		"purpose": "live audit test",
		"rows":    float64(len(livePeople)),
		"request": map[string]any{"id": "req_01J9Z3"},
	}
	// unverified is the unverified context of the one request a call made
	// to the endpoint.
	unverified := func(call, endpoint string) map[string]any {
		t.Helper()
		made := requests()
		if len(made) != 1 || !strings.HasSuffix(made[0].Path, "/"+endpoint) {
			t.Fatalf("%s made %d requests (%v), want one to %s", call, len(made), paths(made), endpoint)
		}
		var body struct {
			UnverifiedContext map[string]any `json:"unverified_context"`
		}
		if err := json.Unmarshal(made[0].Body, &body); err != nil {
			t.Fatalf("%s: the request body is not JSON: %v", call, err)
		}
		return body.UnverifiedContext
	}
	plain := c.DefaultKeyset()
	if _, err := plain.KeysetID(ctx); err != nil {
		t.Fatal(err)
	}
	requests() // the client's start-up requests are not under test

	cipher := plain.Audit(metadata)
	encrypted, err := testusers.Encrypt(ctx, cipher, livePeople)
	if err != nil {
		t.Fatal(err)
	}
	if got := unverified("an audited Encrypt", "generate-data-key"); !reflect.DeepEqual(got, want) {
		t.Errorf("an audited Encrypt sent %v, want %v", got, want)
	}
	if _, err := testusers.Decrypt(ctx, cipher, encrypted); err != nil {
		t.Fatal(err)
	}
	if got := unverified("an audited Decrypt", "retrieve-data-key"); !reflect.DeepEqual(got, want) {
		t.Errorf("an audited Decrypt sent %v, want %v", got, want)
	}
	if _, err := testusers.Decrypt(ctx, c.Audit(metadata), encrypted); err != nil {
		t.Fatal(err)
	}
	if got := unverified("a Decrypt through the audited client", "retrieve-data-key"); !reflect.DeepEqual(got, want) {
		t.Errorf("a Decrypt through the audited client sent %v, want %v", got, want)
	}

	// No metadata: the request carries no facts.
	if _, err := testusers.Decrypt(ctx, plain, encrypted); err != nil {
		t.Fatal(err)
	}
	if got := unverified("a Decrypt with no metadata", "retrieve-data-key"); len(got) != 0 {
		t.Errorf("a Decrypt with no metadata sent %v, want no facts", got)
	}

	// A query through the audited cipher asks ZeroKMS for nothing.
	if _, err := testusers.Fields.Age.Eq(ctx, cipher, 34); err != nil {
		t.Fatal(err)
	}
	if made := requests(); len(made) != 0 {
		t.Errorf("a query made %d requests (%v), want none", len(made), paths(made))
	}
}

func paths(requests []encrypt.RecordedRequest) []string {
	out := make([]string, len(requests))
	for i, r := range requests {
		out[i] = r.Path
	}
	return out
}

func TestLiveForeignKeysetIsRefusedBeforeRetrieval(t *testing.T) {
	c := encrypt.LiveClient(t)
	ctx := t.Context()
	other := os.Getenv("STACK_ENCRYPT_TEST_OTHER_KEYSET")
	if other == "" {
		t.Skip("STACK_ENCRYPT_TEST_OTHER_KEYSET not set")
	}
	encrypted, err := testusers.EncryptDocument(ctx, c.Keyset(encrypt.KeysetName(other)), []testusers.Document{{Title: "tenant b", Body: "x"}})
	if err != nil {
		t.Fatal(err)
	}
	encrypt.ResetSends(c)
	_, err = testusers.DecryptDocument(ctx, c.DefaultKeyset(), encrypted)
	if !errors.Is(err, encrypt.ErrForeignKeyset) {
		t.Fatalf("default cipher opened another keyset's row: %v", err)
	}
	if n := encrypt.Sends(c); n != 0 {
		t.Errorf("a foreign row cost %d ZeroKMS calls before refusal", n)
	}
	// The refusal names both keysets: the default the cipher is bound to,
	// and the one the row was sealed under.
	d := encrypt.WantDiagnostic(t, err, "stack_encrypt::foreign_keyset")
	wantExpected, err := c.DefaultKeyset().KeysetID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	wantFound, err := c.Keyset(encrypt.KeysetName(other)).KeysetID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := d.ExpectedKeyset(); !ok || got != wantExpected {
		t.Errorf("ExpectedKeyset() = %x, %v; want %s", got, ok, wantExpected)
	}
	if got, ok := d.FoundKeyset(); !ok || got != wantFound {
		t.Errorf("FoundKeyset() = %x, %v; want %s", got, ok, wantFound)
	}
	if docs, err := testusers.DecryptDocument(ctx, c, encrypted); err != nil || docs[0].Title != "tenant b" {
		t.Fatalf("client decrypt of the other keyset: %v %+v", err, docs)
	}
}

// The hermetic residency test (TestPlaintextDoesNotRemainInGuestMemory)
// runs on every pull request; this is the same check across a real ZeroKMS
// request, where the guest also stages the service's responses — wrapped
// data keys — and must wipe those too.
func TestPlaintextDoesNotRemainInGuestMemoryAfterLiveRoundTrip(t *testing.T) {
	c := encrypt.LiveClient(t)
	cipher := c.DefaultKeyset()
	const plaintext = "residency-probe-4111-b1c2d3e4f5"
	probe := testusers.User{ID: 1, Age: 34, Email: "probe@example.com", Notes: plaintext}
	encrypted, err := testusers.Encrypt(t.Context(), cipher, []testusers.User{probe})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if n := bytes.Count(encrypt.GuestMemory(t, c), []byte(plaintext)); n != 0 {
		t.Fatalf("plaintext found %d times in guest memory after Encrypt", n)
	}
	// After Decrypt one copy remains; see the hermetic
	// TestPlaintextDoesNotRemainInGuestMemoryAfterDecrypt for the cause.
	if _, err := testusers.Decrypt(t.Context(), cipher, encrypted); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
}
