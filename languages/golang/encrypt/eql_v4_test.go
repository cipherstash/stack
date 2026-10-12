package encrypt_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// The EQL v4 types the engine produces besides TextEq, sealed through
// generated code over the deterministic guest build with the EQL types:
// each Go field type reaches its v4 type's own plan, and the values open
// back to what went in.

var profiles = []testusers.Profile{
	{ID: 1, Age: 42, Visits: 3, Balance: 1234567890123, Active: true, Ratio: 0.5, Score: 2.25, Note: "a private note", Name: "alice"},
	{ID: 2, Age: -7, Visits: 0, Balance: -1, Active: false, Ratio: -1.5, Score: 0, Note: "", Name: "bob smith"},
}

// keysOf is the sorted top-level keys of an EQL value.
func keysOf(t *testing.T, value []byte) string {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(value, &raw); err != nil {
		t.Fatalf("the EQL value is not JSON: %v: %s", err, value)
	}
	if string(raw["v"]) != "4" {
		t.Errorf("v = %s, want 4: %s", raw["v"], value)
	}
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

func TestV4FieldsSealToTheirEQLTypesAndOpenBack(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()

	encrypted, err := testusers.EncryptProfile(ctx, cipher, profiles)
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range encrypted {
		for name, tc := range map[string]struct {
			value []byte
			keys  string
		}{
			"age":     {e.Age, "c,hm,i,v"},
			"visits":  {e.Visits, "c,i,v"},
			"balance": {e.Balance, "c,hm,i,v"},
			"active":  {e.Active, "c,i,v"},
			"ratio":   {e.Ratio, "c,i,v"},
			"score":   {e.Score, "c,i,v"},
			"note":    {e.Note, "c,i,v"},
			"name":    {e.Name, "bf,c,i,v"},
		} {
			if got := keysOf(t, tc.value); got != tc.keys {
				t.Errorf("row %d %s: keys %s, want %s", i, name, got, tc.keys)
			}
		}
	}

	decrypted, err := testusers.DecryptProfile(ctx, cipher, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	for i := range profiles {
		if decrypted[i] != profiles[i] {
			t.Errorf("row %d: %+v, want %+v", i, decrypted[i], profiles[i])
		}
	}
}

func TestV4QueriesMatchTheRustFixture(t *testing.T) {
	c := deterministicEQLClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", "eql", "tests", "encryption", "fixtures", "v4_queries.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Table string
		Age   struct {
			Plaintext int32
			Query     string
		}
		Balance struct {
			Plaintext int64
			Query     string
		}
		Name struct {
			Plaintext string
			Query     string
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Table != "profiles" {
		t.Fatalf("the fixture's table changed: %q", fixture.Table)
	}

	// Byte for byte what eql-bindings' own dispatch derived under the same
	// index key: each Go field runs its v4 type's plan and no other.
	age, err := testusers.ProfileFields.Age.Query(ctx, cipher, fixture.Age.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if string(age) != fixture.Age.Query {
		t.Errorf("Age.Query = %s\nwant          %s", age, fixture.Age.Query)
	}
	balance, err := testusers.ProfileFields.Balance.Query(ctx, cipher, fixture.Balance.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if string(balance) != fixture.Balance.Query {
		t.Errorf("Balance.Query = %s\nwant              %s", balance, fixture.Balance.Query)
	}
	name, err := testusers.ProfileFields.Name.Query(ctx, cipher, fixture.Name.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if string(name) != fixture.Name.Query {
		t.Errorf("Name.Query = %s\nwant           %s", name, fixture.Name.Query)
	}

	// And a stored value carries the term its query probes for.
	stored, err := testusers.ProfileFields.Age.Encrypt(ctx, cipher, fixture.Age.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	var s, q struct {
		HM string `json:"hm"`
	}
	if err := json.Unmarshal(stored, &s); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(age, &q); err != nil {
		t.Fatal(err)
	}
	if s.HM != q.HM {
		t.Errorf("stored hm %s, query hm %s", s.HM, q.HM)
	}
}
