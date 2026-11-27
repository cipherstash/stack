package stashgen

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/packages"
)

// uuidArray reports whether an array is [16]byte, the underlying type of a
// UUID. The element is byte itself, not a type defined over it, so a value of
// the array converts to [16]byte and back.
func uuidArray(a *types.Array) bool {
	return a.Len() == 16 && types.Identical(a.Elem(), types.Typ[types.Byte])
}

// knownUUIDs are UUID types the generator knows by name, so a field of one
// is a UUID without reading its package's source. They are kept apart from
// valueKind's types: those are types the codec writes by their exact type,
// which the other checks (a JSON document, a storage blob) treat as one
// value. A UUID type is written as its bytes and converted by gensupport.
var knownUUIDs = map[[2]string]bool{
	{"github.com/google/uuid", "UUID"}: true,
	{vcvaluePath, "UUID"}:              true,
}

// uuidTypes names the types a UUID field takes, for the generator's
// messages.
const uuidTypes = "a UUID field is [16]byte, a type whose declaration is an array of 16 bytes (type ID [16]byte), github.com/google/uuid.UUID or vcvalue.UUID"

// uuidVerdict is whether a type whose underlying type is [16]byte is a
// UUID, and why not.
type uuidVerdict uint8

const (
	// notUUID is a type that is not [16]byte underneath.
	notUUID uuidVerdict = iota
	// uuidType is a UUID.
	uuidType
	// declaredOver is a type declared over another named type, such as
	// type Balance encrypt.Int128.
	declaredOver
	// unreadDeclaration is a type whose declaration the generator could
	// not read.
	unreadDeclaration
)

// isUUID reports whether t is a UUID; see [reader.uuidVerdict].
func (r *reader) isUUID(t types.Type) bool { return r.uuidVerdict(t) == uuidType }

// uuidVerdict decides whether t, or the type an alias of it stands for, is a
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
func (r *reader) uuidVerdict(t types.Type) uuidVerdict {
	switch t := types.Unalias(t).(type) {
	case *types.Array:
		if uuidArray(t) {
			return uuidType
		}
	case *types.Named:
		u, ok := t.Underlying().(*types.Array)
		if !ok || !uuidArray(u) {
			return notUUID
		}
		obj := t.Origin().Obj()
		if obj.Pkg() == nil {
			return unreadDeclaration
		}
		if knownUUIDs[[2]string{obj.Pkg().Path(), obj.Name()}] {
			return uuidType
		}
		spec := r.typeSpec(obj)
		if spec == nil {
			return unreadDeclaration
		}
		if _, array := ast.Unparen(spec.Type).(*ast.ArrayType); array && !spec.Assign.IsValid() {
			return uuidType
		}
		return declaredOver
	}
	return notUUID
}

// typeSpec finds the declaration of a package-level type: in the loaded
// package's syntax for a type of that package, and otherwise in the source
// files of the type's package, which it loads by import path from the
// directory the package was loaded from. It does not use the position
// recorded for an imported type: under -trimpath, or after a //line
// directive, that names no file on disk. It returns nil when the package's
// source cannot be loaded or parsed, or holds no package-level declaration
// of the type.
func (r *reader) typeSpec(obj *types.TypeName) *ast.TypeSpec {
	if obj.Pkg().Path() == r.pkg.PkgPath && len(r.pkg.Syntax) > 0 {
		for _, file := range r.pkg.Syntax {
			if spec := findTypeSpec(file, obj.Name()); spec != nil {
				return spec
			}
		}
		return nil
	}
	for _, file := range r.packageSource(obj.Pkg()) {
		if spec := findTypeSpec(file, obj.Name()); spec != nil {
			return spec
		}
	}
	return nil
}

// packageSource is the parsed source of an imported package, loaded by its
// import path once per reader, or nil when it cannot be loaded or a file
// does not parse.
func (r *reader) packageSource(pkg *types.Package) []*ast.File {
	if files, ok := r.declFiles[pkg.Path()]; ok {
		return files
	}
	if r.declFiles == nil {
		r.declFiles = map[string][]*ast.File{}
	}
	files := loadSource(r.ctx, r.dir, pkg)
	r.declFiles[pkg.Path()] = files
	return files
}

// loadSource lists an imported package's Go files with go/packages, from
// dir, as the package itself was loaded, and parses them.
func loadSource(ctx context.Context, dir string, pkg *types.Package) []*ast.File {
	if ctx == nil {
		ctx = context.Background()
	}
	cfg := &packages.Config{Context: ctx, Dir: dir, Mode: packages.NeedName | packages.NeedFiles}
	loaded, err := packages.Load(cfg, pkg.Path())
	if err != nil || len(loaded) != 1 || len(loaded[0].Errors) > 0 || len(loaded[0].GoFiles) == 0 {
		return nil
	}
	fset := token.NewFileSet()
	files := make([]*ast.File, 0, len(loaded[0].GoFiles))
	for _, name := range loaded[0].GoFiles {
		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil
		}
		if file.Name.Name == pkg.Name() {
			files = append(files, file)
		}
	}
	return files
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
