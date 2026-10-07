package stashgen

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/packages"
)

// loadPackage loads the package in dir with its types. It reads types, not
// text, and runs none of the package's code. The file at ignore, the
// generator's own output, is read as its package clause only, so a stale
// generated file does not stop the generator.
func loadPackage(ctx context.Context, dir, ignore string) (*packages.Package, error) {
	ignoreAbs, err := filepath.Abs(ignore)
	if err != nil {
		return nil, err
	}
	cfg := &packages.Config{
		Context: ctx,
		Dir:     dir,
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedImports | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedSyntax,
		ParseFile: func(fset *token.FileSet, filename string, src []byte) (*ast.File, error) {
			mode := parser.ParseComments | parser.SkipObjectResolution
			if sameFile(filename, ignoreAbs) {
				mode |= parser.PackageClauseOnly
			}
			return parser.ParseFile(fset, filename, src, mode)
		},
	}
	pkgs, err := packages.Load(cfg, ".")
	if err != nil {
		return nil, fmt.Errorf("stashgen: load %s: %w", dir, err)
	}
	if len(pkgs) != 1 {
		return nil, fmt.Errorf("stashgen: %s holds %d packages, and the generator reads one", dir, len(pkgs))
	}
	pkg := pkgs[0]
	if pkg.Types == nil || pkg.Types.Scope() == nil {
		return nil, fmt.Errorf("stashgen: %s: no types: %s", dir, packageErrors(pkg))
	}
	return pkg, nil
}

func sameFile(a, b string) bool {
	absA, err := filepath.Abs(a)
	if err != nil {
		return false
	}
	return absA == b
}

// packageErrors joins the errors go/packages reported, for a message that
// explains why a type could not be read.
func packageErrors(pkg *packages.Package) string {
	if len(pkg.Errors) == 0 {
		return "no errors reported"
	}
	msgs := make([]string, 0, len(pkg.Errors))
	for _, e := range pkg.Errors {
		msgs = append(msgs, e.Error())
	}
	return strings.Join(msgs, "; ")
}

// lookupStruct finds a named struct type in the package's scope.
func lookupStruct(pkg *packages.Package, name string) (*types.Named, *types.Struct, error) {
	obj := pkg.Types.Scope().Lookup(name)
	if obj == nil {
		return nil, nil, fmt.Errorf("stashgen: package %s has no type %s (%s)", pkg.Name, name, packageErrors(pkg))
	}
	tn, ok := obj.(*types.TypeName)
	if !ok {
		return nil, nil, fmt.Errorf("stashgen: %s.%s is not a type", pkg.Name, name)
	}
	named, ok := tn.Type().(*types.Named)
	if !ok {
		return nil, nil, fmt.Errorf("stashgen: %s.%s is not a named struct type", pkg.Name, name)
	}
	st, ok := named.Underlying().(*types.Struct)
	if !ok {
		return nil, nil, fmt.Errorf("stashgen: %s.%s is a %s, and the generator reads a struct", pkg.Name, name, named.Underlying())
	}
	return named, st, nil
}

// lookupQualified resolves "crm.Contact" through the package's imports: the
// package whose name is crm, and its type Contact.
func lookupQualified(pkg *packages.Package, qualified string) (*types.Named, *types.Struct, error) {
	i := strings.LastIndexByte(qualified, '.')
	if i <= 0 || i == len(qualified)-1 {
		return nil, nil, fmt.Errorf("stashgen: %q is not P.F, a type F in an imported package P", qualified)
	}
	pkgName, typeName := qualified[:i], qualified[i+1:]
	var found *packages.Package
	for _, imp := range pkg.Imports {
		if imp.Types != nil && imp.Types.Name() == pkgName {
			if found != nil {
				return nil, nil, fmt.Errorf("stashgen: %s imports two packages named %s: %s and %s", pkg.Name, pkgName, found.PkgPath, imp.PkgPath)
			}
			found = imp
		}
	}
	if found == nil {
		return nil, nil, fmt.Errorf("stashgen: package %s imports no package named %s", pkg.Name, pkgName)
	}
	return lookupStruct(found, typeName)
}

// hasInvalidType reports whether a type mentions the invalid type, which the
// checker uses for what it could not resolve.
func hasInvalidType(t types.Type) bool {
	seen := map[types.Type]bool{}
	var walk func(t types.Type) bool
	walk = func(t types.Type) bool {
		if t == nil || seen[t] {
			return false
		}
		seen[t] = true
		switch t := t.(type) {
		case *types.Basic:
			return t.Kind() == types.Invalid
		case *types.Named:
			return walk(t.Underlying())
		case *types.Pointer:
			return walk(t.Elem())
		case *types.Slice:
			return walk(t.Elem())
		case *types.Array:
			return walk(t.Elem())
		case *types.Map:
			return walk(t.Key()) || walk(t.Elem())
		case *types.Struct:
			for i := range t.NumFields() {
				if walk(t.Field(i).Type()) {
					return true
				}
			}
		}
		return false
	}
	return walk(t)
}
