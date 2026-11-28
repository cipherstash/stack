package stashgen

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/packages"
)

// uuidArray reports whether a is [16]byte, the array type of a UUID. The
// element type must be byte itself, so that a value of the array converts to
// [16]byte and back. An array of a type defined over byte does not convert.
func uuidArray(a *types.Array) bool {
	return a.Len() == 16 && types.Identical(a.Elem(), types.Typ[types.Byte])
}

// knownUUIDs lists the UUID types the generator recognises by package path
// and type name. A field of one of these types is a UUID. The generator does
// not read the type's declaration to decide.
//
// valueKind recognises other types by name, and no UUID type is one of them.
// The codec writes a valueKind type as that exact type. The checks for a
// JSON document and for a storage blob treat a valueKind type as one value.
// A UUID type is different: gensupport converts the value to a vcvalue.UUID
// before the codec writes it.
var knownUUIDs = map[[2]string]bool{
	{"github.com/google/uuid", "UUID"}: true,
	{vcvaluePath, "UUID"}:              true,
}

// uuidTypes lists the types a UUID field can have. The generator's refusal
// messages start with it.
const uuidTypes = "a UUID field is [16]byte, a type whose declaration is an array of 16 bytes (type ID [16]byte), github.com/google/uuid.UUID or vcvalue.UUID"

// uuidVerdict is the generator's decision on whether a type is a UUID. When
// the type is not a UUID, the verdict gives the reason. [reader.uuidVerdict]
// makes the decision and defines the terms used here.
type uuidVerdict uint8

const (
	// notUUID means the underlying type is not [16]byte.
	notUUID uuidVerdict = iota
	// uuidType means the type is a UUID.
	uuidType
	// declaredOver means the type's declaration names another type, as
	// type Balance encrypt.Int128 does. The type is not a UUID.
	declaredOver
	// unreadDeclaration means the generator could not read the type's
	// declaration, so it cannot decide.
	unreadDeclaration
)

// isUUID reports whether t is a UUID. [reader.uuidVerdict] gives the rules.
func (r *reader) isUUID(t types.Type) bool { return r.uuidVerdict(t) == uuidType }

// uuidVerdict decides whether t is a UUID. The rules use four of Go's terms:
//
//   - A type declaration is the source line that creates a type, such as
//     type ID [16]byte.
//   - A defined type is the type that a declaration creates.
//   - An alias is a second name for a type, declared as type A = T.
//   - The underlying type of a defined type is the type that all of its
//     declarations reduce to. Given type ID [16]byte and type Ref ID, the
//     underlying type of both ID and Ref is [16]byte.
//
// uuidVerdict first replaces an alias with the type it names. That type is a
// UUID in three cases:
//
//   - The type is [16]byte itself.
//   - The type's declaration writes out the array type, such as
//     type ID [16]byte, or type UUID [Size]byte where Size is 16.
//   - The type is github.com/google/uuid.UUID or vcvalue.UUID.
//
// A type whose declaration names another type is not a UUID, even when the
// underlying type is [16]byte. The underlying type of encrypt.Int128 and
// encrypt.Uint128 is [16]byte. So type Balance encrypt.Int128 and
// type ID [16]byte have the same underlying type, and only the two
// declarations differ.
//
// go/types does not record which type a declaration names, so the generator
// reads the declaration from source. If the generator cannot read the
// declaration, uuidVerdict returns unreadDeclaration. The generator then
// refuses the field, because a guess could seal the value as the wrong kind.
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

// typeSpec returns the declaration of the package-level type obj. The result
// is nil if the source of obj's package cannot be loaded or parsed, or if
// that source has no package-level declaration of obj.
//
// Where typeSpec searches depends on the package that declares obj:
//
//   - For a type of r.pkg, the package the generator loaded, typeSpec
//     searches the syntax trees in r.pkg.Syntax.
//   - For a type of any other package, typeSpec searches that package's
//     source files. packageSource loads them by import path.
//
// typeSpec does not use the position that the type information records for
// an imported type. Under -trimpath, or after a //line directive, that
// position names no file on disk.
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

// packageSource returns the parsed source files of the imported package pkg.
// The result is nil if the package cannot be loaded or if one of its files
// does not parse. The reader loads each package by its import path, once,
// and keeps the result.
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

// loadSource returns the parsed Go files of the imported package pkg, or nil
// if any step fails. The list of files comes from go/packages, and
// loadSource parses each file. The load runs from dir, the directory the
// generator loaded its own package from.
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

// findTypeSpec returns the package-level declaration of the type called name
// in file, or nil if file has none.
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

// sixteenBytes returns the type to name when the generator refuses a field
// that is not a UUID. If t is a pointer, sixteenBytes examines the type t
// points to. The result is that type when the underlying type is [16]byte,
// and nil otherwise.
func sixteenBytes(t types.Type) types.Type {
	if p, ok := types.Unalias(t).Underlying().(*types.Pointer); ok {
		t = p.Elem()
	}
	if a, ok := t.Underlying().(*types.Array); ok && uuidArray(a) {
		return t
	}
	return nil
}
