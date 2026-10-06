package stashgen_test

import (
	"context"
	"go/types"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// TestStubAgreesWithGensupport loads the real encrypt/gensupport and the
// test stub of it, and fails when a symbol both declare has two shapes. The
// stub is the contract the integration step implements; the real package is
// what ships. A symbol that is only in the stub is the integration step's
// work, and a symbol only in the real package is fine.
func TestStubAgreesWithGensupport(t *testing.T) {
	compareStub(t, "gensupport", filepath.Join("..", "encrypt", "gensupport"), "./encrypt/gensupport", true)
}

// The encrypt package is wider than what generated code names; only the
// symbols the stub declares are compared, and an interface by presence (the
// real one's methods take the module's internal types).
func TestStubAgreesWithEncrypt(t *testing.T) {
	compareStub(t, "encrypt", filepath.Join("..", "encrypt"), "./encrypt", false)
}

func compareStub(t *testing.T, pkg, realDir, stubPattern string, every bool) {
	t.Helper()
	real := loadScope(t, realDir, ".")
	stub := loadScope(t, filepath.Join("testdata", "stubsdk"), stubPattern)
	shared := 0
	for _, name := range real.Names() {
		obj := real.Lookup(name)
		if !obj.Exported() {
			continue
		}
		stubObj := stub.Lookup(name)
		if stubObj == nil {
			if every {
				t.Errorf("%s.%s is not in the stub; generated code may not name it", pkg, name)
			}
			continue
		}
		shared++
		if _, isInterface := obj.Type().Underlying().(*types.Interface); isInterface {
			if _, stubInterface := stubObj.Type().Underlying().(*types.Interface); !stubInterface {
				t.Errorf("%s.%s: real package has an interface, stub has %s", pkg, name, stubObj.Type())
			}
			continue
		}
		got := shape(stubObj.Type())
		want := shape(obj.Type())
		if got != want {
			t.Errorf("%s.%s: stub has %s, real package has %s", pkg, name, got, want)
		}
	}
	for _, name := range stub.Names() {
		if stub.Lookup(name).Exported() && real.Lookup(name) == nil {
			t.Errorf("%s.%s is in the stub and not in the real package: the contract is unmet", pkg, name)
		}
	}
	if shared == 0 {
		t.Fatal("no shared symbols: the loader found nothing")
	}
}

// stripPkg qualifies nothing, so the two generatedVersion types compare by
// name alone.
func stripPkg(*types.Package) string { return "" }

// shape renders a type without parameter names, which a stub need not
// repeat: a signature's type parameters, parameter types and result types.
func shape(t types.Type) string {
	sig, ok := t.(*types.Signature)
	if !ok {
		return types.TypeString(t, stripPkg)
	}
	var b strings.Builder
	b.WriteString("func")
	if tp := sig.TypeParams(); tp != nil && tp.Len() > 0 {
		b.WriteString("[")
		for i := range tp.Len() {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(tp.At(i).Obj().Name())
			b.WriteString(" ")
			b.WriteString(types.TypeString(tp.At(i).Constraint(), stripPkg))
		}
		b.WriteString("]")
	}
	b.WriteString("(")
	for i := range sig.Params().Len() {
		if i > 0 {
			b.WriteString(", ")
		}
		if sig.Variadic() && i == sig.Params().Len()-1 {
			b.WriteString("...")
			b.WriteString(types.TypeString(sig.Params().At(i).Type().(*types.Slice).Elem(), stripPkg))
			continue
		}
		b.WriteString(types.TypeString(sig.Params().At(i).Type(), stripPkg))
	}
	b.WriteString(")")
	if sig.Results().Len() > 0 {
		b.WriteString(" (")
		for i := range sig.Results().Len() {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(types.TypeString(sig.Results().At(i).Type(), stripPkg))
		}
		b.WriteString(")")
	}
	return b.String()
}

func loadScope(t *testing.T, dir, pattern string) *types.Scope {
	t.Helper()
	cfg := &packages.Config{Context: context.Background(), Dir: dir, Mode: packages.NeedName | packages.NeedTypes}
	pkgs, err := packages.Load(cfg, pattern)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 || pkgs[0].Types == nil {
		t.Fatalf("loading %s in %s: %d packages", pattern, dir, len(pkgs))
	}
	for _, e := range pkgs[0].Errors {
		t.Fatalf("loading %s: %v", pattern, e)
	}
	return pkgs[0].Types.Scope()
}
