package stashgen_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/stashgen"
	"github.com/cipherstash/stack/languages/golang/stashgen/enginetest"
)

// build runs go vet over a module the test wrote, after the generated file
// is written into it.
func build(t *testing.T, dir string) {
	t.Helper()
	cmd := exec.Command("go", "vet", "./...")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOPROXY=off", "GOWORK=off", "GOFLAGS=-mod=mod", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generated code does not build: %v\n%s", err, out)
	}
}

func TestModelDeclaredByAnotherStruct(t *testing.T) {
	// userdb.ContactRow stands in for a sqlc row struct: it cannot carry
	// tags, so contactRow in the package declares them.
	dir := writeModule(t, map[string]string{
		"userdb/row.go": "package userdb\n\nimport \"github.com/cipherstash/stack/languages/golang/encrypt\"\n\n" +
			"type ContactRow struct {\n\tID      int64\n\tEmail   encrypt.Ciphertext\n\tEmailEq encrypt.EqualityTerm\n\tNote    encrypt.Ciphertext\n}\n",
		"model.go": "package contacts\n\nimport (\n\t\"example.com/app/userdb\"\n\t\"github.com/cipherstash/stack/languages/golang/encrypt\"\n)\n\nvar _ userdb.ContactRow\n\n" +
			"//go:generate go tool stashgen -type Contact -name Contact -model Rows=userdb.ContactRow:contactRow\n" +
			"type Contact struct {\n\t_     struct{} `stash:\"context=contacts\"`\n\tID    int64    `stash:\"id,passthrough\"`\n\tEmail string   `stash:\"email,encrypt,index=equality\"`\n\tNote  string   `stash:\"note,encrypt\"`\n}\n\n" +
			"type contactRow struct {\n\tID      int64                `stash:\"id\"`\n\tEmail   encrypt.Ciphertext   `stash:\"email\"`\n\tEmailEq encrypt.EqualityTerm `stash:\"email,equality\"`\n\tNote    encrypt.Ciphertext   `stash:\"note\"`\n}\n\n" +
			"// badRow gives Email the wrong type.\ntype badRow struct {\n\tID      int64                `stash:\"id\"`\n\tEmail   string               `stash:\"email\"`\n\tEmailEq encrypt.EqualityTerm `stash:\"email,equality\"`\n\tNote    encrypt.Ciphertext   `stash:\"note\"`\n}\n",
	})
	req := stashgen.Request{Dir: dir, Type: "Contact", Name: "Contact", Models: []stashgen.ModelRequest{{Name: "Rows", Type: "userdb.ContactRow", Declares: "contactRow"}}}
	file, err := stashgen.FromTags(context.Background(), enginetest.Static{}, req)
	if err != nil {
		t.Fatal(err)
	}
	src := string(file.Content)
	for _, want := range []string{
		"type contactRowsShape struct {",
		"var contactRowsCodec = gensupport.Records(contactCodec,",
		"return userdb.ContactRow(contactRowsShape{",
		"EmailEq: e.Email.Equality,",
		"func EncryptRows(ctx context.Context, cipher *encrypt.Cipher, values []Contact) ([]userdb.ContactRow, error) {",
		"func DecryptRows(ctx context.Context, d encrypt.Decrypter, rows []userdb.ContactRow) ([]Contact, error) {",
		"var ContactFields = struct {",
		"type ContactEmailField struct {",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("generated file lacks %q", want)
		}
	}
	if err := file.Write(); err != nil {
		t.Fatal(err)
	}
	build(t, dir)

	// The declaring struct must match the model field for field.
	_, err = stashgen.FromTags(context.Background(), enginetest.Static{}, stashgen.Request{Dir: dir, Type: "Contact", Name: "Contact",
		Models: []stashgen.ModelRequest{{Name: "Rows", Type: "userdb.ContactRow", Declares: "badRow"}}})
	if err == nil || !strings.Contains(err.Error(), "badRow.Email: has type string, and userdb.ContactRow.Email has type encrypt.Ciphertext") {
		t.Fatalf("a declaring struct that does not match: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "contact_stash.go")); err != nil {
		t.Fatal(err)
	}
}

func TestModelWithEQLColumnsAndEmbeddedPassthrough(t *testing.T) {
	// A model that carries an EQL value and leaves a column unbound with "-".
	dir := writeModule(t, map[string]string{
		"model.go": "package users\n\nimport \"github.com/cipherstash/stack/languages/golang/encrypt/eql\"\n\n" +
			"type User struct {\n\t_     struct{} `stash:\"context=users\"`\n\tID    int64    `stash:\"id,passthrough\"`\n\tEmail string   `stash:\"email,encrypt_into=TextEq\"`\n}\n\n" +
			"type Row struct {\n\tID      int64      `stash:\"id\"`\n\tEmail   eql.TextEq `stash:\"email\"`\n\tVersion int        `stash:\"-\"`\n}\n",
	})
	file, err := stashgen.FromTags(context.Background(), enginetest.Static{}, stashgen.Request{Dir: dir, Type: "User", Models: []stashgen.ModelRequest{{Name: "Rows", Type: "Row"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(file.Content), "Email: e.Email,") || strings.Contains(string(file.Content), "Version:") {
		t.Fatalf("model conversion:\n%s", file.Content)
	}
	if err := file.Write(); err != nil {
		t.Fatal(err)
	}
	build(t, dir)
}

func TestParseModelFlag(t *testing.T) {
	good := map[string]stashgen.ModelRequest{
		"Rows=ContactRow":           {Name: "Rows", Type: "ContactRow"},
		"Rows=userdb.Row:rowDecl":   {Name: "Rows", Type: "userdb.Row", Declares: "rowDecl"},
		"LegacyRows=Legacy:legacyD": {Name: "LegacyRows", Type: "Legacy", Declares: "legacyD"},
	}
	for in, want := range good {
		got, err := stashgen.ParseModelFlag(in)
		if err != nil || got != want {
			t.Errorf("ParseModelFlag(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "Rows", "Rows=", "=R", "rows=R", "Rows=R:", "Ro-ws=R"} {
		if _, err := stashgen.ParseModelFlag(bad); err == nil {
			t.Errorf("ParseModelFlag(%q) accepted", bad)
		}
	}
}
