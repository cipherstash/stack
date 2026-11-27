package stashgen

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
)

// uuidArray reports whether an array is [16]byte, the underlying type of a
// UUID. The element is byte itself, not a type defined over it, so a value of
// the array converts to [16]byte and back.
func uuidArray(a *types.Array) bool {
	return a.Len() == 16 && types.Identical(a.Elem(), types.Typ[types.Byte])
}

// knownUUIDs are UUID types the generator knows by name, so a field of one
// is a UUID even when the source of its package cannot be read.
var knownUUIDs = map[[2]string]bool{
	{"github.com/google/uuid", "UUID"}: true,
	{vcvaluePath, "UUID"}:              true,
}

// isUUID reports whether t, or the type an alias of it stands for, is a
// UUID:
//
//   - [16]byte itself;
//   - a type whose declaration writes the array type, such as
//     type ID [16]byte or type UUID [Size]byte with Size 16;
//   - github.com/google/uuid.UUID or vcvalue.UUID.
//
// A type declared over another named type is not a UUID, even when its
// underlying type is [16]byte. encrypt.Int128 and encrypt.Uint128 are
// [16]byte underneath, so type Balance encrypt.Int128 has the same
// underlying type as type ID [16]byte, and only the declaration tells them
// apart. go/types does not record what a defined type was declared over, so
// the generator reads the declaration from source. When it cannot read it,
// the type is not a UUID: the field is refused rather than sealed as the
// wrong kind.
func (r *reader) isUUID(t types.Type) bool {
	switch t := types.Unalias(t).(type) {
	case *types.Array:
		return uuidArray(t)
	case *types.Named:
		u, ok := t.Underlying().(*types.Array)
		if !ok || !uuidArray(u) {
			return false
		}
		obj := t.Origin().Obj()
		if obj.Pkg() == nil {
			return false
		}
		if knownUUIDs[[2]string{obj.Pkg().Path(), obj.Name()}] {
			return true
		}
		spec := r.typeSpec(obj)
		if spec == nil || spec.Assign.IsValid() {
			return false
		}
		_, array := ast.Unparen(spec.Type).(*ast.ArrayType)
		return array
	}
	return false
}

// typeSpec finds the declaration of a package-level type: in the loaded
// package's syntax for a type of that package, and otherwise in the source
// file the type's position names, which go/packages records for an imported
// package too. It returns nil when the file cannot be read or holds no such
// declaration, such as for a type declared inside a function.
func (r *reader) typeSpec(obj *types.TypeName) *ast.TypeSpec {
	if obj.Pkg().Path() == r.pkg.PkgPath && len(r.pkg.Syntax) > 0 {
		for _, file := range r.pkg.Syntax {
			if spec := findTypeSpec(file, obj.Name()); spec != nil {
				return spec
			}
		}
		return nil
	}
	if r.pkg.Fset == nil {
		return nil
	}
	pos := r.pkg.Fset.Position(obj.Pos())
	if !pos.IsValid() || pos.Filename == "" {
		return nil
	}
	file, ok := r.declFiles[pos.Filename]
	if !ok {
		parsed, err := parser.ParseFile(token.NewFileSet(), pos.Filename, nil, parser.SkipObjectResolution)
		if err == nil && parsed.Name.Name == obj.Pkg().Name() {
			file = parsed
		}
		if r.declFiles == nil {
			r.declFiles = map[string]*ast.File{}
		}
		r.declFiles[pos.Filename] = file
	}
	if file == nil {
		return nil
	}
	return findTypeSpec(file, obj.Name())
}

// findTypeSpec is the package-level declaration of the type named in file,
// or nil.
func findTypeSpec(file *ast.File, name string) *ast.TypeSpec {
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		for _, spec := range gen.Specs {
			if ts, ok := spec.(*ast.TypeSpec); ok && ts.Name.Name == name {
				return ts
			}
		}
	}
	return nil
}

// sixteenBytes is t, or the type t points to, when its underlying type is
// [16]byte; nil otherwise. It names the type in the refusal of a field that
// is [16]byte underneath and is not a UUID.
func sixteenBytes(t types.Type) types.Type {
	if p, ok := types.Unalias(t).Underlying().(*types.Pointer); ok {
		t = p.Elem()
	}
	if a, ok := t.Underlying().(*types.Array); ok && uuidArray(a) {
		return t
	}
	return nil
}
