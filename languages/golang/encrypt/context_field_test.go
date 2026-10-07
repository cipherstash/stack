package encrypt_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// A type whose context is one of its own fields (`context_field`), through
// the deterministic guest: each row is sealed under the context its field
// names, a cipher that names a context refuses a row stored under another
// before any key is retrieved, and a query derives under the named context.

var notes = []testusers.Note{
	{Tenant: "tenants/acme", Text: "hello", ID: 1},
	{Tenant: "tenants/globex", Text: "hello", ID: 2},
	{Tenant: "tenants/acme", Text: "goodbye", ID: 3},
}

func TestContextFieldSealsEachRowUnderItsOwnContext(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()

	encrypted, err := testusers.EncryptNote(ctx, cipher, notes)
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range encrypted {
		if e.Tenant != notes[i].Tenant || e.ID != notes[i].ID {
			t.Errorf("row %d: the context field and the passthrough are stored as they are: %+v", i, e)
		}
		if len(e.Text.Ciphertext) == 0 || len(e.Text.Equality) != 32 {
			t.Errorf("row %d: outputs missing: %+v", i, e)
		}
	}
	// The same text under two tenants is two terms: the context came from
	// each row, not from the type.
	if encrypted[0].Text.Equality.Equal(encrypted[1].Text.Equality) {
		t.Error("the same text under two tenants derived one term")
	}

	// With no context named, each row opens under the context it stores,
	// through the cipher and through the client alike.
	for _, d := range []struct {
		name string
		by   encrypt.Decrypter
	}{{"cipher", cipher}, {"client", c}} {
		back, err := testusers.DecryptNote(ctx, d.by, encrypted)
		if err != nil {
			t.Fatalf("DecryptNote through the %s: %v", d.name, err)
		}
		for i := range notes {
			if back[i] != notes[i] {
				t.Fatalf("through the %s: row %d = %+v, want %+v", d.name, i, back[i], notes[i])
			}
		}
	}

	// A cipher that names the context refuses a row stored under another,
	// before any key is retrieved: the batch holds a globex row.
	acme := cipher.Context("tenants/acme")
	if _, err := testusers.DecryptNote(ctx, acme, encrypted); !errors.Is(err, encrypt.ErrContextMismatch) {
		t.Fatalf("a globex row through the acme cipher: %v, want ErrContextMismatch", err)
	}
	onlyAcme := []testusers.EncryptedNote{encrypted[0], encrypted[2]}
	back, err := testusers.DecryptNote(ctx, acme, onlyAcme)
	if err != nil || back[0] != notes[0] || back[1] != notes[2] {
		t.Fatalf("acme rows through the acme cipher: %v %+v", err, back)
	}
	if _, err := testusers.DecryptNote(ctx, cipher.Context("tenants/globex"), onlyAcme); !errors.Is(err, encrypt.ErrContextMismatch) {
		t.Fatalf("acme rows through the globex cipher: %v, want ErrContextMismatch", err)
	}

	// A stored context changed in storage opens nothing: every field was
	// sealed under the original, so the key source refuses it.
	moved := encrypted[0]
	moved.Tenant = "tenants/globex"
	if _, err := testusers.DecryptNote(ctx, cipher, []testusers.EncryptedNote{moved}); !errors.Is(err, encrypt.ErrForbidden) {
		t.Fatalf("a row whose stored context was changed: %v, want ErrForbidden", err)
	}

	// Encrypt through a cipher that names the context refuses a value
	// whose field says otherwise, before anything is sent.
	if _, err := testusers.EncryptNote(ctx, acme, notes); !errors.Is(err, encrypt.ErrContextMismatch) {
		t.Fatalf("a globex value through the acme cipher: %v, want ErrContextMismatch", err)
	}
	again, err := testusers.EncryptNote(ctx, acme, notes[:1])
	if err != nil || !again[0].Text.Equality.Equal(encrypted[0].Text.Equality) {
		t.Fatalf("an acme value through the acme cipher: %v", err)
	}
}

func TestContextFieldQueriesNameTheContext(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	encrypted, err := testusers.EncryptNote(ctx, cipher, notes)
	if err != nil {
		t.Fatal(err)
	}
	// A query through a cipher with no context has nothing to derive under.
	if _, err := testusers.NoteFields.Text.Equality(ctx, cipher, "hello"); !errors.Is(err, encrypt.ErrEncoding) || !strings.Contains(err.Error(), "Cipher.Context") {
		t.Fatalf("a query with no context: %v, want ErrEncoding naming Cipher.Context", err)
	}
	// Under the tenant it singles out that tenant's row.
	acme := cipher.Context("tenants/acme")
	probe, err := testusers.NoteFields.Text.Equality(ctx, acme, "hello")
	if err != nil {
		t.Fatal(err)
	}
	if !probe.Equal(encrypted[0].Text.Equality) || probe.Equal(encrypted[1].Text.Equality) || probe.Equal(encrypted[2].Text.Equality) {
		t.Error("the probe under tenants/acme does not single out acme's hello")
	}
	globex, err := testusers.NoteFields.Text.Equality(ctx, cipher.Context("tenants/globex"), "hello")
	if err != nil || !globex.Equal(encrypted[1].Text.Equality) {
		t.Fatalf("the probe under tenants/globex: %v", err)
	}
	// A field's own Encrypt seals one value under the named context: the
	// column it writes opens in that tenant's row.
	one, err := testusers.NoteFields.Text.Encrypt(ctx, acme, "hello")
	if err != nil || !one.Equality.Equal(encrypted[0].Text.Equality) {
		t.Fatalf("a field's own Encrypt under tenants/acme: %v", err)
	}
	if _, err := testusers.NoteFields.Text.Encrypt(ctx, cipher, "hello"); !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("a field's own Encrypt with no context: %v, want ErrEncoding", err)
	}
	updated := encrypted[0]
	updated.Text = one
	back, err := testusers.DecryptNote(ctx, acme, []testusers.EncryptedNote{updated})
	if err != nil || back[0].Text != "hello" {
		t.Fatalf("after a column update: %v %+v", err, back)
	}
	// A cipher with a context refuses a type whose context is in its tags.
	if _, err := testusers.Encrypt(ctx, acme, people[:1]); !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("a context= type through a cipher with a context: %v, want ErrEncoding", err)
	}
	// A label that is not plain is reported by the first call.
	if _, err := testusers.DecryptNote(ctx, cipher.Context("tenants/(acme)"), encrypted[:1]); !errors.Is(err, encrypt.ErrEncoding) {
		t.Fatalf("Context with a label that is not plain: %v, want ErrEncoding", err)
	}
}

// The context-field case of the Rust record fixture: the typed chain and
// the data-plan lowering each sealed a Note under the deterministic source,
// and the generated code opens both under the context they store, refuses
// both under another, and derives the same term.
type contextFieldFixture struct {
	KeySource struct {
		Seed string `json:"seed"`
	} `json:"key_source"`
	ContextField struct {
		Plaintext struct {
			Tenant string `json:"tenant"`
			Text   string `json:"text"`
			ID     uint32 `json:"id"`
		} `json:"plaintext"`
		Records map[string]map[string]map[string]json.RawMessage `json:"records"`
	} `json:"context_field"`
}

func TestGeneratedCodeOpensTheRustContextFieldFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", "stack-encrypt", "tests", "fixtures", "record_lowering.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f contextFieldFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.ContextField.Records) != 2 {
		t.Fatalf("the fixture's context_field case has %d records, want the two authors'", len(f.ContextField.Records))
	}
	seedBytes, err := hex.DecodeString(f.KeySource.Seed)
	if err != nil || len(seedBytes) != 32 {
		t.Fatalf("seed: %v (%d bytes)", err, len(seedBytes))
	}
	c, err := encrypt.NewDeterministicClient(context.Background(), [32]byte(seedBytes))
	if errors.Is(err, encrypt.ErrDeterministicGuestNotBuilt) || errors.Is(err, encrypt.ErrGuestNotBuilt) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	want := testusers.Note{Tenant: f.ContextField.Plaintext.Tenant, Text: f.ContextField.Plaintext.Text, ID: f.ContextField.Plaintext.ID}

	for author, rec := range f.ContextField.Records {
		t.Run(author, func(t *testing.T) {
			var tenant string
			if err := json.Unmarshal(rec["tenant"]["passthrough"], &tenant); err != nil {
				t.Fatal(err)
			}
			stored := testusers.EncryptedNote{
				Tenant: tenant,
				Text: testusers.EncryptedNoteText{
					Ciphertext: hexField(t, rec, "text", "c"),
					Equality:   hexField(t, rec, "text", "eq"),
				},
				ID: want.ID,
			}
			for name, d := range map[string]encrypt.Decrypter{"cipher": cipher, "client": c, "the acme cipher": cipher.Context(want.Tenant)} {
				back, err := testusers.DecryptNote(ctx, d, []testusers.EncryptedNote{stored})
				if err != nil {
					t.Fatalf("DecryptNote through %s: %v", name, err)
				}
				if back[0] != want {
					t.Fatalf("DecryptNote through %s = %+v, want %+v", name, back[0], want)
				}
			}
			if _, err := testusers.DecryptNote(ctx, cipher.Context("tenants/globex"), []testusers.EncryptedNote{stored}); !errors.Is(err, encrypt.ErrContextMismatch) {
				t.Fatalf("through the globex cipher: %v, want ErrContextMismatch", err)
			}
			// The term Go derives under the tenant is the bytes Rust stored.
			eq, err := testusers.NoteFields.Text.Equality(ctx, cipher.Context(want.Tenant), want.Text)
			if err != nil || !eq.Equal(stored.Text.Equality) {
				t.Errorf("text equality: %v, equal=%v", err, eq.Equal(stored.Text.Equality))
			}
			again, err := testusers.EncryptNote(ctx, cipher, []testusers.Note{want})
			if err != nil || !bytes.Equal(again[0].Text.Equality, stored.Text.Equality) {
				t.Errorf("a Go record of the fixture's note derives other terms than Rust did: %v", err)
			}
		})
	}
}
