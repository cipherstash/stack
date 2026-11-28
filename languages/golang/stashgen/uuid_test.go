package stashgen_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/stashgen"
	"github.com/cipherstash/stack/languages/golang/stashgen/enginetest"
)

// crmIDs is the source of two types in a package that the struct imports.
// The generator reads the types of an imported package from export data, so
// it reads these two declarations from the package's source.
const crmIDs = `package crm

import "github.com/cipherstash/stack/languages/golang/encrypt"

// Ref is a UUID: its declaration is an array of 16 bytes.
type Ref [16]byte

// Amount is declared over encrypt.Int128, so it is not a UUID.
type Amount encrypt.Int128
`

// A UUID is [16]byte, or a type whose declaration writes out an array of 16
// bytes. That type can be in the struct's package or in another package. An
// alias of either is a UUID too. The generator gives each of them the uuid
// kind.
func TestUUIDTypes(t *testing.T) {
	for _, c := range []struct{ name, field, decls string }{
		{"[16]byte", "\tID [16]byte `stash:\"id,encrypt,index=equality\"`", ""},
		{"a type declared as [16]byte", "\tID id `stash:\"id,encrypt,index=equality\"`", "type id [16]byte\n"},
		{"a type declared as [16]uint8", "\tID id `stash:\"id,encrypt,index=equality\"`", "type id [16]uint8\n"},
		{"a type declared with a constant length", "\tID id `stash:\"id,encrypt,index=equality\"`", "const size = 16\n\ntype id [size]byte\n"},
		{"an alias of a UUID type", "\tID idAlias `stash:\"id,encrypt,index=equality\"`", "type id [16]byte\n\ntype idAlias = id\n"},
		{"a pointer to a UUID type", "\tID *id `stash:\"id,encrypt,index=equality\"`", "type id [16]byte\n"},
		{"a UUID type of another package", "\tID crm.Ref `stash:\"id,encrypt,index=equality\"`", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := writeModule(t, map[string]string{"model.go": user(ctx+c.field) + "\n" + c.decls, "crm/contact.go": crmPackage, "crm/ids.go": crmIDs})
			file, err := stashgen.FromTags(context.Background(), enginetest.Static{}, stashgen.Request{Dir: dir, Type: "User"})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(file.Content), `EncryptIndex("id", gensupport.UUID, encrypt.Equality)`) {
				t.Fatalf("the field is not declared a UUID:\n%s", file.Content)
			}
		})
	}
	// The generator refuses a type of another package that is declared over
	// encrypt.Int128, as it refuses one of the struct's own package.
	refusesAmount(t)
}

func refusesAmount(t *testing.T) {
	t.Helper()
	dir := writeModule(t, map[string]string{"model.go": user(ctx + "\tTotal crm.Amount `stash:\"total,encrypt\"`"), "crm/contact.go": crmPackage, "crm/ids.go": crmIDs})
	_, err := stashgen.FromTags(context.Background(), enginetest.Static{}, stashgen.Request{Dir: dir, Type: "User"})
	var fe *stashgen.FieldError
	if !errors.As(err, &fe) || fe.Field != "Total" || !strings.Contains(err.Error(), "crm.Amount is declared over another type") {
		t.Fatalf("err = %v, want a refusal of crm.Amount naming Total", err)
	}
}

// Under -trimpath, the position that go/packages records for an imported
// type names a module path, not a file on disk. The generator still reads
// the declaration of a type in another package, from that package's source
// files. The generator accepts a UUID type there, and refuses a type
// declared over encrypt.Int128.
func TestUUIDTypesOfAnotherPackageUnderTrimpath(t *testing.T) {
	t.Setenv("GOFLAGS", "-trimpath")
	dir := writeModule(t, map[string]string{"model.go": user(ctx + "\tID crm.Ref `stash:\"id,encrypt,index=equality\"`"), "crm/contact.go": crmPackage, "crm/ids.go": crmIDs})
	file, err := stashgen.FromTags(context.Background(), enginetest.Static{}, stashgen.Request{Dir: dir, Type: "User"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(file.Content), `EncryptIndex("id", gensupport.UUID, encrypt.Equality)`) {
		t.Fatalf("crm.Ref is not declared a UUID:\n%s", file.Content)
	}
	refusesAmount(t)
}
