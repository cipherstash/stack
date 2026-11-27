package stashgen

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"golang.org/x/tools/go/packages"
)

// vcvalue's Int128, Uint128 and UUID are each declared as [16]byte. Int128
// and Uint128 are integers, and a type declared over either is not a UUID;
// vcvalue.UUID is one, known by name. The types are built here, so the test
// does not depend on where vcvalue lives.
func TestVcvalueIntegersAreNotUUIDs(t *testing.T) {
	fset := token.NewFileSet()
	src := "package app\n\nimport \"" + vcvaluePath + "\"\n\ntype Balance vcvalue.Int128\n\ntype Count vcvalue.Uint128\n\ntype ID [16]byte\n"
	file, err := parser.ParseFile(fset, "app.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	array := types.NewArray(types.Typ[types.Byte], 16)
	vcvalue := types.NewPackage(vcvaluePath, "vcvalue")
	app := types.NewPackage("example.com/app", "app")
	named := func(pkg *types.Package, name string) *types.Named {
		return types.NewNamed(types.NewTypeName(token.NoPos, pkg, name, nil), array, nil)
	}
	alias := func(name string, rhs types.Type) types.Type {
		return types.NewAlias(types.NewTypeName(token.NoPos, app, name, nil), rhs)
	}
	int128, uint128, uuid := named(vcvalue, "Int128"), named(vcvalue, "Uint128"), named(vcvalue, "UUID")
	balance, count, id := named(app, "Balance"), named(app, "Count"), named(app, "ID")

	r := &reader{pkg: &packages.Package{PkgPath: "example.com/app", Syntax: []*ast.File{file}, Fset: fset}, imports: newImportSet()}
	for _, c := range []struct {
		name string
		t    types.Type
		want Kind
	}{
		{"vcvalue.Int128", int128, KindInt128},
		{"vcvalue.Uint128", uint128, KindUint128},
		{"an alias of vcvalue.Int128", alias("I", int128), KindInt128},
		{"vcvalue.UUID", uuid, KindUUID},
		{"an alias of vcvalue.UUID", alias("U", uuid), KindUUID},
		{"a type declared as [16]byte", id, KindUUID},
		{"a type declared over vcvalue.Int128", balance, KindSlice},
		{"a type declared over vcvalue.Uint128", count, KindSlice},
		{"an alias of a type declared over vcvalue.Int128", alias("B", balance), KindSlice},
	} {
		if got := r.goType(c.t).Kind; got != c.want {
			t.Errorf("%s: kind %s, want %s", c.name, got, c.want)
		}
	}
}

// A type of a package whose source cannot be loaded has a declaration the
// generator cannot read, which it reports apart from a type declared over
// another type. vcvalue.UUID, known by name, needs no source.
func TestAnUnreadDeclarationIsNotAUUID(t *testing.T) {
	array := types.NewArray(types.Typ[types.Byte], 16)
	missing := types.NewPackage("example.com/missing", "missing")
	id := types.NewNamed(types.NewTypeName(token.NoPos, missing, "ID", nil), array, nil)
	known := types.NewNamed(types.NewTypeName(token.NoPos, types.NewPackage(vcvaluePath, "vcvalue"), "UUID", nil), array, nil)
	r := &reader{pkg: &packages.Package{PkgPath: "example.com/app"}, imports: newImportSet(), dir: t.TempDir()}
	if got := r.uuidVerdict(id); got != unreadDeclaration {
		t.Errorf("a type of a package with no source: verdict %d, want unreadDeclaration", got)
	}
	if got := r.goType(id).Kind; got == KindUUID {
		t.Error("a type whose declaration could not be read is a UUID")
	}
	if got := r.uuidVerdict(known); got != uuidType {
		t.Errorf("vcvalue.UUID: verdict %d, want uuidType", got)
	}
}
