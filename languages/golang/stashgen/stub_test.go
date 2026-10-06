package stashgen_test

import (
	"context"
	"go/types"
	"path/filepath"
	"testing"

	"golang.org/x/tools/go/packages"
)

// TestStubAgreesWithGensupport loads the real encrypt/gensupport and the
// test stub of it, and fails when a symbol both declare has two shapes. The
// stub is the contract the integration step implements; the real package is
// what ships. A symbol that is only in the stub is the integration step's
// work, and a symbol only in the real package is fine.
func TestStubAgreesWithGensupport(t *testing.T) {
	real := loadScope(t, filepath.Join("..", "encrypt", "gensupport"), ".")
	stub := loadScope(t, filepath.Join("testdata", "stubsdk"), "./encrypt/gensupport")
	shared := 0
	for _, name := range real.Names() {
		obj := real.Lookup(name)
		if !obj.Exported() {
			continue
		}
		stubObj := stub.Lookup(name)
		if stubObj == nil {
			t.Errorf("gensupport.%s is not in the stub; generated code may not name it", name)
			continue
		}
		shared++
		got := types.TypeString(stubObj.Type(), stripPkg)
		want := types.TypeString(obj.Type(), stripPkg)
		if got != want {
			t.Errorf("gensupport.%s: stub has %s, real package has %s", name, got, want)
		}
	}
	if shared == 0 {
		t.Fatal("no shared symbols: the loader found nothing")
	}
}

// stripPkg qualifies nothing, so the two generatedVersion types compare by
// name alone.
func stripPkg(*types.Package) string { return "" }

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
