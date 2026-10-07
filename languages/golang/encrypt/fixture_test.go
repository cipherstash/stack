package encrypt_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// The record fixture is the proof that generated Go code is a third author
// of one declaration (ADR-0007, amended): the typed Rust chain and the data
// plan lowering each sealed packages/stack-encrypt/tests/fixtures/
// record_lowering.json under a deterministic key source, and the generated
// testusers package — the same context, identities, kinds and indexes as
// tags — opens both records through the guest built over the same source
// and derives the same term bytes. Skipped when the deterministic test
// build of the guest is absent.

type recordFixture struct {
	KeySource struct {
		Kind string `json:"kind"`
		Seed string `json:"seed"`
	} `json:"key_source"`
	KeysetID  string `json:"keyset_id"`
	Plaintext struct {
		Age   uint32 `json:"age"`
		Email string `json:"email"`
		ID    uint32 `json:"id"`
		Notes string `json:"notes"`
	} `json:"plaintext"`
	Records map[string]map[string]map[string]json.RawMessage `json:"records"`
}

func readFixture(t *testing.T) recordFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", "stack-encrypt", "tests", "fixtures", "record_lowering.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f recordFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.KeySource.Kind != "deterministic-sha256" || f.KeysetID != "00000000-0000-0000-0000-000000000000" {
		t.Fatalf("the fixture's key source changed shape: %+v", f.KeySource)
	}
	return f
}

func hexField(t *testing.T, rec map[string]map[string]json.RawMessage, field, output string) []byte {
	t.Helper()
	raw, ok := rec[field][output]
	if !ok {
		t.Fatalf("the fixture record has no %s.%s", field, output)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestGeneratedCodeOpensTheRustRecordFixture(t *testing.T) {
	f := readFixture(t)
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
	// The fixture's keyset is the nil UUID: the fake source's default.
	cipher := c.DefaultKeyset()
	if id, err := cipher.KeysetID(ctx); err != nil || id != (encrypt.KeysetID{}) {
		t.Fatalf("default keyset = %v, %v; want the nil id", id, err)
	}

	for author, rec := range f.Records {
		t.Run(author, func(t *testing.T) {
			// The stored record, as a program that read the columns Rust
			// wrote would hold it. The passthrough id never crossed the
			// binding on either side.
			stored := testusers.EncryptedUser{
				ID: int64(f.Plaintext.ID),
				Age: testusers.EncryptedUserAge{
					Ciphertext: hexField(t, rec, "age", "c"),
					Equality:   hexField(t, rec, "age", "eq"),
					Ore:        hexField(t, rec, "age", "ore"),
				},
				Email: testusers.EncryptedUserEmail{
					Ciphertext: hexField(t, rec, "email", "c"),
					Equality:   hexField(t, rec, "email", "eq"),
					Match:      hexField(t, rec, "email", "match"),
				},
				Notes: testusers.EncryptedUserNotes{Ciphertext: hexField(t, rec, "notes", "c")},
			}
			for name, d := range map[string]encrypt.Decrypter{"cipher": cipher, "client": c} {
				back, err := testusers.Decrypt(ctx, d, []testusers.EncryptedUser{stored})
				if err != nil {
					t.Fatalf("Decrypt through the %s: %v", name, err)
				}
				want := testusers.User{ID: int64(f.Plaintext.ID), Age: f.Plaintext.Age, Email: f.Plaintext.Email, Notes: f.Plaintext.Notes}
				if back[0] != want {
					t.Fatalf("Decrypt through the %s = %+v, want %+v", name, back[0], want)
				}
			}
			// The terms Go derives are the bytes Rust stored.
			eq, err := testusers.Fields.Age.Equality(ctx, cipher, f.Plaintext.Age)
			if err != nil || !eq.Equal(stored.Age.Equality) {
				t.Errorf("age equality: %v, equal=%v", err, eq.Equal(stored.Age.Equality))
			}
			ore, err := testusers.Fields.Age.Ore(ctx, cipher, f.Plaintext.Age)
			if err != nil || !bytes.Equal(ore, stored.Age.Ore) {
				t.Errorf("age ore: %v, equal=%v", err, bytes.Equal(ore, stored.Age.Ore))
			}
			emailEq, err := testusers.Fields.Email.Equality(ctx, cipher, f.Plaintext.Email)
			if err != nil || !emailEq.Equal(stored.Email.Equality) {
				t.Errorf("email equality: %v, equal=%v", err, emailEq.Equal(stored.Email.Equality))
			}
			match, err := testusers.Fields.Email.Match(ctx, cipher, f.Plaintext.Email)
			if err != nil || !bytes.Equal(match, stored.Email.Match) {
				t.Errorf("email match: %v, equal=%v", err, bytes.Equal(match, stored.Email.Match))
			}
			// A fresh Go record of the same plaintext derives the same terms.
			again, err := testusers.Encrypt(ctx, cipher, []testusers.User{{ID: int64(f.Plaintext.ID), Age: f.Plaintext.Age, Email: f.Plaintext.Email, Notes: f.Plaintext.Notes}})
			if err != nil {
				t.Fatal(err)
			}
			if !again[0].Age.Equality.Equal(stored.Age.Equality) || !bytes.Equal(again[0].Email.Match, stored.Email.Match) || !bytes.Equal(again[0].Age.Ore, stored.Age.Ore) {
				t.Error("a Go record of the fixture's plaintext derives other terms than Rust did")
			}
			// A leaf moved under another field's label does not open.
			moved := stored
			moved.Notes.Ciphertext = stored.Email.Ciphertext
			if _, err := testusers.Decrypt(ctx, cipher, []testusers.EncryptedUser{moved}); err == nil {
				t.Error("a leaf opened under another field's label")
			}
		})
	}
}
