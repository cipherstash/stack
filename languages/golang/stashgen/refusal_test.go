package stashgen_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/stashgen"
	"github.com/cipherstash/stack/languages/golang/stashgen/enginetest"
)

// generate writes one package into a module that resolves the SDK to the
// stub, and runs the generator over it.
func generate(t *testing.T, src string, req stashgen.Request) (*stashgen.File, error) {
	t.Helper()
	dir := writeModule(t, map[string]string{"model.go": src, "crm/contact.go": crmPackage})
	req.Dir = dir
	return stashgen.FromTags(context.Background(), enginetest.Static{}, req)
}

func writeModule(t *testing.T, files map[string]string) string {
	t.Helper()
	stubs, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	gomod := "module example.com/app\n\ngo 1.26\n\nrequire (\n\tgithub.com/cipherstash/stack/languages/golang v0.0.0\n\tgorm.io/gorm v0.0.0\n)\n\nreplace github.com/cipherstash/stack/languages/golang => " + filepath.Join(stubs, "stubsdk") + "\n\nreplace gorm.io/gorm => " + filepath.Join(stubs, "stubgorm") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, src := range files {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// user wraps field lines into a tagged struct named User in package users.
func user(fields string) string {
	return "package users\n\nimport (\n\t\"time\"\n\n\t\"example.com/app/crm\"\n\t\"github.com/cipherstash/stack/languages/golang/encrypt\"\n\t\"gorm.io/gorm\"\n)\n\nvar (\n\t_ time.Time\n\t_ crm.Contact\n\t_ encrypt.Cipher\n\t_ gorm.Model\n)\n\ntype User struct {\n" + fields + "\n}\n"
}

const ctx = "\t_ struct{} `stash:\"context=users\"`\n"

// TestRefusals covers every entry of the refusal list in the plan's stashgen
// reference, and a few the reference implies. Each refusal names the field.
func TestRefusals(t *testing.T) {
	cases := []struct {
		name  string
		src   string
		req   stashgen.Request
		field string // the field the error must name, "" for the type
		want  string
	}{
		{"an exported field with no stash tag", user(ctx + "\tEmail string"), stashgen.Request{Type: "User"}, "Email", "no stash tag"},
		{"a tag that does not parse", user(ctx + "\tEmail string `stash:\"email,shred\"`"), stashgen.Request{Type: "User"}, "Email", `unknown part "shred"`},
		{"two fields with one name", user(ctx + "\tEmail string `stash:\"email,encrypt\"`\n\tAlt string `stash:\"email,encrypt\"`"), stashgen.Request{Type: "User"}, "Alt", `two fields write the name "email"`},
		{"an omitted field whose name a column takes", user(ctx + "\tEmail string `stash:\"-\"`\n\tAddr string `stash:\"email,encrypt\"`"), stashgen.Request{Type: "User"}, "Addr", `two fields write the name "email"`},
		{"a struct with no context field", user("\tEmail string `stash:\"email,encrypt\"`"), stashgen.Request{Type: "User"}, "", "declares the context"},
		{"a context declared twice", user(ctx + ctx + "\tEmail string `stash:\"email,encrypt\"`"), stashgen.Request{Type: "User"}, "_", "declared twice"},
		{"context on a named field", user(ctx + "\tEmail string `stash:\"context=x\"`"), stashgen.Request{Type: "User"}, "Email", "goes on a `_ struct{}` field"},
		{"a _ field with no context", user("\t_ struct{}\n\tEmail string `stash:\"email,encrypt\"`"), stashgen.Request{Type: "User"}, "_", "carries the context tag"},
		{"an index that does not apply to the field type", user(ctx + "\tAge int32 `stash:\"age,encrypt,index=match\"`"), stashgen.Request{Type: "User"}, "Age", "match applies to a string, not to int32"},
		{"an EQL type that does not apply to the field type", user(ctx + "\tAge int64 `stash:\"age,encrypt_into=TextEq\"`"), stashgen.Request{Type: "User"}, "Age", "TextEq seals a string, and int64 is int"},
		{"a field type the engine cannot seal", user(ctx + "\tDone chan int `stash:\"done,encrypt\"`"), stashgen.Request{Type: "User"}, "Done", "seals only as part of an opaque struct"},
		{"a composite sealed outside an opaque struct", user(ctx + "\tAt time.Time `stash:\"at,encrypt\"`"), stashgen.Request{Type: "User"}, "At", "a time.Time seals only as part of an opaque struct"},
		{"a slice sealed outside an opaque struct", user(ctx + "\tTags []string `stash:\"tags,encrypt\"`"), stashgen.Request{Type: "User"}, "Tags", "seals only as part of an opaque struct"},
		{"a map sealed outside an opaque struct", user(ctx + "\tCounts map[string]int64 `stash:\"counts,encrypt\"`"), stashgen.Request{Type: "User"}, "Counts", "seals only as part of an opaque struct"},
		{"a slice of ints sealed outside an opaque struct", user(ctx + "\tNs []int64 `stash:\"ns,encrypt\"`"), stashgen.Request{Type: "User"}, "Ns", "seals only as part of an opaque struct"},
		{"an opaque struct with a channel", user("\t_ struct{} `stash:\"context=users,opaque\"`\n\tDone chan int"), stashgen.Request{Type: "User"}, "Done", "is not a type JSON carries"},
		{"an opaque struct with an interface", user("\t_ struct{} `stash:\"context=users,opaque\"`\n\tAny any"), stashgen.Request{Type: "User"}, "Any", "is not a type JSON carries"},
		{"an opaque struct with a struct JSON would truncate", user("\t_ struct{} `stash:\"context=users,opaque\"`\n\tTx hidden") + "\ntype hidden struct {\n\tA int\n\tb int\n}\n", stashgen.Request{Type: "User"}, "Tx", "JSON would drop"},
		{"an opaque struct with a map keyed by a struct", user("\t_ struct{} `stash:\"context=users,opaque\"`\n\tM map[hidden]int") + "\ntype hidden struct{ A int }\n", stashgen.Request{Type: "User"}, "M", "map key that is not a string or an integer"},
		{"an EQL type the engine cannot produce yet", user(ctx + "\tEmail string `stash:\"email,encrypt_into=TextMatch\"`"), stashgen.Request{Type: "User"}, "Email", "has no EQL type TextMatch"},
		{"an index on a composite", user(ctx + "\tAttrs map[string]string `stash:\"attrs,encrypt,index=equality\"`"), stashgen.Request{Type: "User"}, "Attrs", "seals only as part of an opaque struct"},
		{"the json index, not in the engine yet", user(ctx + "\tAttrs string `stash:\"attrs,index=json\"`"), stashgen.Request{Type: "User"}, "Attrs", "cannot derive the json index yet"},
		{"an index option the engine cannot carry", user(ctx + "\tEmail string `stash:\"email,encrypt,index=match(k=3)\"`"), stashgen.Request{Type: "User"}, "Email", "cannot carry index options"},
		{"a passthrough field that has an index", user(ctx + "\tID int64 `stash:\"id,passthrough,index=equality\"`"), stashgen.Request{Type: "User"}, "ID", "passthrough field has no index"},
		{"an embedded struct from another package with no tag", user(ctx + "\tgorm.Model\n\tEmail string `stash:\"email,encrypt\"`"), stashgen.Request{Type: "User"}, "Model", "cannot carry tags; tag the field"},
		{"an embedded struct with a verb other than passthrough", user(ctx + "\tgorm.Model `stash:\",encrypt\"`\n\tEmail string `stash:\"email,encrypt\"`"), stashgen.Request{Type: "User"}, "Model", "takes only passthrough"},
		{"an embedded pointer", user(ctx + "\t*gorm.Model `stash:\",passthrough\"`\n\tEmail string `stash:\"email,encrypt\"`"), stashgen.Request{Type: "User"}, "Model", "must be a struct, not a pointer"},
		{"a struct that stores no field", user(ctx + "\tEmail string `stash:\"-\"`"), stashgen.Request{Type: "User"}, "", "stores no field"},
		{"an opaque struct with a tagged field", user("\t_ struct{} `stash:\"context=users,opaque\"`\n\tEmail string `stash:\"email,encrypt\"`"), stashgen.Request{Type: "User"}, "Email", "opaque struct seals as one value"},
		{"two structs that would both write Encrypt", user(ctx+"\tEmail string `stash:\"email,encrypt\"`") + "\n//go:generate go tool stashgen -type Admin\ntype Admin struct {\n" + ctx + "\tEmail string `stash:\"email,encrypt\"`\n}\n", stashgen.Request{Type: "User"}, "", "User and Admin would both write Encrypt"},
		{"-redact on a type with a String method", user(ctx+"\tEmail string `stash:\"email,encrypt\"`") + "\nfunc (User) String() string { return \"\" }\n", stashgen.Request{Type: "User", Redact: true}, "", "already has a String method"},
		{"-for a field the struct names with another type", user(ctx + "\tEmail int `stash:\"email,encrypt\"`"), stashgen.Request{Type: "User", For: "crm.Contact"}, "Email", "has type int, and crm.Contact.Email has type string"},
		{"-for a field the type does not have", user(ctx + "\tPhone string `stash:\"phone,encrypt\"`"), stashgen.Request{Type: "User", For: "crm.Contact"}, "Phone", "crm.Contact has no field Phone"},
		{"-for a field the struct does not name", user(ctx + "\tEmail string `stash:\"email,encrypt\"`"), stashgen.Request{Type: "User", For: "crm.Contact"}, "ID", "not named by User"},
		{"-for with -redact", user(ctx + "\tID int64 `stash:\"id,passthrough\"`\n\tEmail string `stash:\"email,encrypt\"`"), stashgen.Request{Type: "User", For: "crm.Contact", Redact: true}, "", "cannot add print methods to crm.Contact"},
		{"-for an unknown package", user(ctx + "\tEmail string `stash:\"email,encrypt\"`"), stashgen.Request{Type: "User", For: "nowhere.Contact"}, "", "imports no package named nowhere"},
		{"a model with a field that has no tag", user(ctx+"\tID int64 `stash:\"id,passthrough\"`\n\tEmail string `stash:\"email,encrypt,index=equality\"`") + "\ntype Row struct {\n\tID int64 `stash:\"id\"`\n\tEmail encrypt.Ciphertext\n}\n", stashgen.Request{Type: "User", Models: []stashgen.ModelRequest{{Name: "Rows", Type: "Row"}}}, "Email", "no stash tag; each field of a model names one output"},
		{"a model with no field for an output", user(ctx+"\tID int64 `stash:\"id,passthrough\"`\n\tEmail string `stash:\"email,encrypt,index=equality\"`") + "\ntype Row struct {\n\tID int64 `stash:\"id\"`\n\tEmail encrypt.Ciphertext `stash:\"email\"`\n}\n", stashgen.Request{Type: "User", Models: []stashgen.ModelRequest{{Name: "Rows", Type: "Row"}}}, "", `no field for the equality term of "email"`},
		{"a model field with the wrong type", user(ctx+"\tID int64 `stash:\"id,passthrough\"`\n\tEmail string `stash:\"email,encrypt\"`") + "\ntype Row struct {\n\tID int64 `stash:\"id\"`\n\tEmail string `stash:\"email\"`\n}\n", stashgen.Request{Type: "User", Models: []stashgen.ModelRequest{{Name: "Rows", Type: "Row"}}}, "Email", "has type string, and the ciphertext of \"email\" is encrypt.Ciphertext"},
		{"a model field naming an index the field lacks", user(ctx+"\tID int64 `stash:\"id,passthrough\"`\n\tEmail string `stash:\"email,encrypt\"`") + "\ntype Row struct {\n\tID int64 `stash:\"id\"`\n\tEmail encrypt.Ciphertext `stash:\"email\"`\n\tEq encrypt.EqualityTerm `stash:\"email,equality\"`\n}\n", stashgen.Request{Type: "User", Models: []stashgen.ModelRequest{{Name: "Rows", Type: "Row"}}}, "Eq", `field "email" has no equality index`},
		{"a model that binds one output twice", user(ctx+"\tID int64 `stash:\"id,passthrough\"`\n\tEmail string `stash:\"email,encrypt\"`") + "\ntype Row struct {\n\tID int64 `stash:\"id\"`\n\tEmail encrypt.Ciphertext `stash:\"email\"`\n\tCopy encrypt.Ciphertext `stash:\"email\"`\n}\n", stashgen.Request{Type: "User", Models: []stashgen.ModelRequest{{Name: "Rows", Type: "Row"}}}, "Copy", `"email" is already bound`},
		{"a model that names a field the struct lacks", user(ctx+"\tID int64 `stash:\"id,passthrough\"`\n\tEmail string `stash:\"email,encrypt\"`") + "\ntype Row struct {\n\tID int64 `stash:\"id\"`\n\tEmail encrypt.Ciphertext `stash:\"email\"`\n\tPhone encrypt.Ciphertext `stash:\"phone\"`\n}\n", stashgen.Request{Type: "User", Models: []stashgen.ModelRequest{{Name: "Rows", Type: "Row"}}}, "Phone", `declares no field named "phone"`},
		{"an opaque struct with two fields that write one name", user("\t_ struct{} `stash:\"context=users,opaque\"`\n\tUserID string\n\tUserId string"), stashgen.Request{Type: "User"}, "UserId", `two fields write the name "user_id"`},
		{"a package that already declares a name the file writes", user(ctx+"\tEmail string `stash:\"email,encrypt\"`") + "\nvar codec = \"json\"\n", stashgen.Request{Type: "User"}, "", "the package already declares codec"},
		{"a model for an opaque struct", user("\t_ struct{} `stash:\"context=users,opaque\"`\n\tEmail string") + "\ntype Row struct{}\n", stashgen.Request{Type: "User", Models: []stashgen.ModelRequest{{Name: "Rows", Type: "Row"}}}, "", "needs no model"},
		{"a type that is not a struct", "package users\n\ntype User int\n", stashgen.Request{Type: "User"}, "", "the generator reads a struct"},
		{"a type the package lacks", "package users\n", stashgen.Request{Type: "User"}, "", "has no type User"},
		{"a -name that is not exported", user(ctx + "\tEmail string `stash:\"email,encrypt\"`"), stashgen.Request{Type: "User", Name: "user"}, "", "must be an exported Go name"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := generate(t, c.src, c.req)
			if err == nil {
				t.Fatalf("want an error containing %q, got none", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not contain %q", err, c.want)
			}
			var fe *stashgen.FieldError
			if c.field != "" {
				if !errors.As(err, &fe) {
					t.Fatalf("error %q is not a *FieldError", err)
				}
				if fe.Field != c.field {
					t.Fatalf("error names field %q, want %q: %v", fe.Field, c.field, err)
				}
			}
		})
	}
}

// crmPackage stands in for a package the program does not own.
const crmPackage = "package crm\n\ntype Contact struct {\n\tID    int64\n\tEmail string\n}\n"

func TestForTypeInAnotherPackage(t *testing.T) {
	// crm.Contact lives in its own package; the tagged struct names it.
	dir := writeModule(t, map[string]string{
		"crm/contact.go":       "package crm\n\ntype Contact struct {\n\tID    int64\n\tEmail string\n\tnote  string\n}\n",
		"contacts/contacts.go": "package contacts\n\nimport \"example.com/app/crm\"\n\nvar _ crm.Contact\n\ntype contactStash struct {\n" + "\t_ struct{} `stash:\"context=contacts\"`\n\tID int64 `stash:\"id,passthrough\"`\n\tEmail string `stash:\"email,encrypt\"`\n}\n",
	})
	file, err := stashgen.FromTags(context.Background(), enginetest.Static{}, stashgen.Request{Dir: filepath.Join(dir, "contacts"), Type: "contactStash", For: "crm.Contact"})
	if err != nil {
		t.Fatal(err)
	}
	src := string(file.Content)
	for _, want := range []string{
		"Generated[*crm.Contact, EncryptedContact]",
		"contacts []*crm.Contact",
		"v := &crm.Contact{}",
		"crm.Contact has unexported fields, so Go cannot convert it",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("generated file lacks %q", want)
		}
	}
	if strings.Contains(src, "contactShape") {
		t.Error("a type with unexported fields got a shape check")
	}
}

func TestStaleOutputFileIsIgnored(t *testing.T) {
	src := user(ctx + "\tID int64 `stash:\"id,passthrough\"`\n\tEmail string `stash:\"email,encrypt_into=TextEq\"`")
	dir := writeModule(t, map[string]string{"model.go": src})
	req := stashgen.Request{Dir: dir, Type: "User"}
	first, err := stashgen.FromTags(context.Background(), enginetest.Static{}, req)
	if err != nil {
		t.Fatal(err)
	}
	// A stale file: it names a type that no longer exists and redeclares
	// Encrypt, so the package does not type-check with it.
	stale := "package users\n\nimport \"github.com/cipherstash/stack/languages/golang/encrypt/gensupport\"\n\nconst _ = gensupport.GeneratedVersion1\n\ntype EncryptedUser struct{ Gone Missing }\n\nfunc Encrypt() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "user_stash.go"), []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := stashgen.FromTags(context.Background(), enginetest.Static{}, req)
	if err != nil {
		t.Fatalf("with a stale output file: %v", err)
	}
	if string(first.Content) != string(second.Content) {
		t.Fatal("the stale output file changed the generated file")
	}
}

func TestOtherLibrariesTagsAreCopied(t *testing.T) {
	src := user(ctx + "\tID int64 `db:\"id\" stash:\"id,passthrough\" gorm:\"primaryKey\"`\n\tEmail string `stash:\"email,encrypt_into=TextEq\" json:\"email,omitempty\"`")
	file, err := generate(t, src, stashgen.Request{Type: "User"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ID    int64      `db:\"id\" gorm:\"primaryKey\"`",
		"Email eql.TextEq `json:\"email,omitempty\"`",
	} {
		if !strings.Contains(string(file.Content), want) {
			t.Errorf("generated type lacks %q:\n%s", want, file.Content)
		}
	}
}

func TestAStructWithPrintMethodsGetsNoNotice(t *testing.T) {
	src := user(ctx+"\tEmail string `stash:\"email,encrypt\"`") + "\nfunc (User) String() string { return \"\" }\nfunc (User) LogValue() any { return nil }\n"
	file, err := generate(t, src, stashgen.Request{Type: "User"})
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Notices) != 0 {
		t.Fatalf("notices = %q", file.Notices)
	}
	if strings.Contains(string(file.Content), "PrintsPlaintext") {
		t.Fatal("PrintsPlaintext set for a type with String and LogValue")
	}
}

// The refusals hold against the engine stashgen ships with, not only the
// fake: the embedded guest, through GuestEngine. Skips only when the guest
// is not built. The cases are the ones a reviewer found the two engines
// disagreeing on, and the composites a reviewer sealed and could not open.
func TestRefusalsHoldAgainstTheEmbeddedEngine(t *testing.T) {
	engine, err := stashgen.GuestEngine(context.Background())
	if errors.Is(err, encrypt.ErrGuestNotBuilt) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer engine.(io.Closer).Close()
	for _, c := range []struct{ name, field, line, want string }{
		{"time.Time", "At", "\tAt time.Time `stash:\"at,encrypt\"`", "seals only as part of an opaque struct"},
		{"a channel", "Done", "\tDone chan int `stash:\"done,encrypt\"`", "seals only as part of an opaque struct"},
		{"equality on a map", "Attrs", "\tAttrs map[string]string `stash:\"attrs,encrypt,index=equality\"`", "seals only as part of an opaque struct"},
		{"a sealed []string", "Tags", "\tTags []string `stash:\"tags,encrypt\"`", "seals only as part of an opaque struct"},
		{"a sealed map[string]int64", "Counts", "\tCounts map[string]int64 `stash:\"counts,encrypt\"`", "seals only as part of an opaque struct"},
		{"equality on a float", "Score", "\tScore float64 `stash:\"score,encrypt,index=equality\"`", "the engine refuses the declaration"},
		{"equality on a bool", "Done", "\tDone bool `stash:\"done,encrypt,index=equality\"`", "the engine refuses the declaration"},
		{"match on an integer", "Age", "\tAge int32 `stash:\"age,encrypt,index=match\"`", "the engine refuses the declaration"},
		{"encrypt_into, no EQL type in this build", "Email", "\tEmail string `stash:\"email,encrypt_into=TextEq\"`", "EQL types are not available yet"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := writeModule(t, map[string]string{"model.go": user(ctx + c.line), "crm/contact.go": crmPackage})
			_, err := stashgen.FromTags(context.Background(), engine, stashgen.Request{Dir: dir, Type: "User"})
			var fe *stashgen.FieldError
			if !errors.As(err, &fe) || fe.Field != c.field {
				t.Fatalf("err = %v, want a *FieldError naming %s", err, c.field)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
	// What the fake refuses, the engine refuses: the same cases against both.
	for _, c := range []struct{ name, line string }{
		{"equality on a float", "\tScore float64 `stash:\"score,encrypt,index=equality\"`"},
		{"a declaration the engine runs", "\tAge uint32 `stash:\"age,encrypt,index=equality;ore\"`\n\tName string `stash:\"name,encrypt,index=match\"`"},
	} {
		dir := writeModule(t, map[string]string{"model.go": user(ctx + c.line), "crm/contact.go": crmPackage})
		_, real := stashgen.FromTags(context.Background(), engine, stashgen.Request{Dir: dir, Type: "User"})
		_, fake := stashgen.FromTags(context.Background(), enginetest.Static{}, stashgen.Request{Dir: dir, Type: "User"})
		if (real == nil) != (fake == nil) {
			t.Errorf("%s: the engine says %v, the fake says %v", c.name, real, fake)
		}
	}
}

// The whole-declaration check: two fields that pass one at a time and fail
// together, because a policy pinned both to one identity. The error is a
// *FieldError with no field.
func TestTheWholeDeclarationIsCheckedAgainstTheEmbeddedEngine(t *testing.T) {
	engine, err := stashgen.GuestEngine(context.Background())
	if errors.Is(err, encrypt.ErrGuestNotBuilt) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer engine.(io.Closer).Close()
	decl := stashgen.Declaration{Type: "Individual", Context: "individuals", Fields: []stashgen.Field{
		{Name: "medicare_number", GoName: "MedicareNo", GoType: stashgen.GoType{Name: "string", Kind: stashgen.KindString, Basic: "string"}, Verb: stashgen.VerbEncrypt, Identity: "id"},
		{Name: "legacy_number", GoName: "LegacyNo", GoType: stashgen.GoType{Name: "string", Kind: stashgen.KindString, Basic: "string"}, Verb: stashgen.VerbEncrypt, Identity: "id"},
	}}
	err = engine.Check(context.Background(), decl)
	var fe *stashgen.FieldError
	if !errors.As(err, &fe) || fe.Field != "" || !strings.Contains(err.Error(), "as a whole") {
		t.Fatalf("err = %v, want the whole-declaration refusal naming no field", err)
	}
	decl.Fields[1].Identity = ""
	if err := engine.Check(context.Background(), decl); err != nil {
		t.Fatalf("distinct identities: %v", err)
	}
}
