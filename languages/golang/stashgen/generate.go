package stashgen

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
)

// Request is one run of the generator over one tagged struct. The command
// fills it from its flags.
type Request struct {
	// Dir is the directory of the package. "" is the working directory.
	Dir string
	// Type is the struct that carries the stash tags.
	Type string
	// Name, when set, writes EncryptName, DecryptName and NameFields.
	Name string
	// For, as P.F, is the type in another package that Type declares for.
	For string
	// Models are the -model flags.
	Models []ModelRequest
	// Redact writes String and LogValue methods on Type.
	Redact bool
	// Output is the file to write, relative to Dir. "" is the type's name in
	// lower case with _stash.go.
	Output string
}

// OutputPath is the file the request writes, relative to Dir.
func (r Request) OutputPath() string {
	if r.Output != "" {
		return r.Output
	}
	return strings.ToLower(r.Type) + "_stash.go"
}

// File is a generated file, ready to write.
type File struct {
	// Path is where the file goes.
	Path string
	// Content is the formatted Go source.
	Content []byte
	// Notices are what the generator prints to stderr: the unexported fields
	// it ignored, and a type that prints its sealed fields.
	Notices []string
}

// Write writes the file. Generated source is committed and read by everyone
// who builds the package, so it gets the mode of any other source file.
func (f *File) Write() error {
	return os.WriteFile(f.Path, f.Content, 0o644) //nolint:gosec // source code, not a secret
}

// FromTags generates the file for the struct named in the request. It loads
// the package with go/packages and reads types, not text; it runs none of the
// package's code; it checks the declaration with the engine; and it returns
// the file without writing it. The same request always gives the same file.
func FromTags(ctx context.Context, engine Engine, req Request) (*File, error) {
	if engine == nil {
		return nil, errors.New("stashgen: no engine")
	}
	if req.Type == "" {
		return nil, errors.New("stashgen: -type is required")
	}
	if !isIdent(req.Type) {
		return nil, fmt.Errorf("stashgen: -type %q is not a type name in this package", req.Type)
	}
	if req.Name != "" && (!isIdent(req.Name) || strings.ToUpper(req.Name[:1]) != req.Name[:1]) {
		return nil, fmt.Errorf("stashgen: -name %q must be an exported Go name", req.Name)
	}
	dir := req.Dir
	if dir == "" {
		dir = "."
	}
	outPath := filepath.Join(dir, req.OutputPath())

	eqlTypes, err := engine.EQLTypes(ctx)
	if err != nil {
		return nil, fmt.Errorf("stashgen: the engine's EQL types: %w", err)
	}

	pkg, err := loadPackage(ctx, dir, outPath)
	if err != nil {
		return nil, err
	}
	r := &reader{pkg: pkg, req: req, eql: eqlTypes, imports: newImportSet()}
	gf, err := r.read()
	if err != nil {
		return nil, err
	}
	if err := engine.Check(ctx, gf.decl); err != nil {
		return nil, err
	}
	src, err := emit(gf)
	if err != nil {
		return nil, err
	}
	if err := checkNamesFree(pkg.Types.Scope(), gf.typeName, src, "pass -name to give the file's names a prefix (-name Rows writes EncryptRows and rowsCodec)"); err != nil {
		return nil, err
	}
	return &File{Path: outPath, Content: src, Notices: gf.stderrNotices()}, nil
}

// checkNamesFree refuses a file that declares a package-level name the
// package already declares: written, it would not compile, and the compiler
// would point at the generated file rather than at the clash. The previous
// output is loaded as its package clause only, so its names are not in scope
// and a second run is not a clash with the first.
func checkNamesFree(scope *types.Scope, typeName string, src []byte, remedy string) error {
	file, err := parser.ParseFile(token.NewFileSet(), "", src, parser.SkipObjectResolution)
	if err != nil {
		return fmt.Errorf("stashgen: the generated file does not parse: %w", err)
	}
	var clash []string
	taken := func(name string) {
		if name != "_" && name != "init" && scope.Lookup(name) != nil {
			clash = append(clash, name)
		}
	}
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil {
				taken(d.Name.Name)
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch sp := spec.(type) {
				case *ast.TypeSpec:
					taken(sp.Name.Name)
				case *ast.ValueSpec:
					for _, n := range sp.Names {
						taken(n.Name)
					}
				}
			}
		}
	}
	if len(clash) > 0 {
		return fieldErr(typeName, "", "the package already declares %s, which the generated file declares too; %s", strings.Join(clash, ", "), remedy)
	}
	return nil
}

// stderrNotices are the notices in the form the generator prints.
func (f *genFile) stderrNotices() []string {
	var out []string
	if len(f.unexported) > 0 {
		out = append(out, fmt.Sprintf("stashgen: %s: not encrypted and not stored: the unexported %s. Tag %s `stash:\"-\"` to confirm that.", f.typeName, fieldList(f.unexported), itOrEach(f.unexported)))
	}
	if f.printsPlaintext {
		out = append(out, fmt.Sprintf("stashgen: %s prints its sealed fields in the clear: it has no String or LogValue method. Write them, or run stashgen with -redact.", f.typeName))
	}
	return out
}
