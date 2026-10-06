package stashgen

import (
	"context"
	"errors"
	"fmt"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/cipherstash/stack/languages/golang/encrypt/policy"
	"golang.org/x/tools/go/packages"
)

// GenerateOption configures [Generate].
type GenerateOption func(*generateConfig)

type generateConfig struct {
	output  string
	engine  Engine
	notices io.Writer
	ctx     context.Context
}

// Output names the file to write. It is required. The file goes in a package
// of your own, not in the package of the generated type, so the generate
// program never imports a file that it wrote.
func Output(path string) GenerateOption { return func(c *generateConfig) { c.output = path } }

// WithEngine checks the declaration with this engine instead of the one the
// SDK embeds.
func WithEngine(e Engine) GenerateOption { return func(c *generateConfig) { c.engine = e } }

// WithNotices sends the generator's notices here instead of stderr.
func WithNotices(w io.Writer) GenerateOption { return func(c *generateConfig) { c.notices = w } }

// WithContext runs the generator under this context.
func WithContext(ctx context.Context) GenerateOption { return func(c *generateConfig) { c.ctx = ctx } }

// Generate writes the generated file for a message from a policy: the source
// gives the facts about each field, the message's rules decide each one, and
// the file is the same one stashgen writes from tags. The generated functions
// take and return pointers to the message.
//
// Every field of the message needs a decision. A field that no rule decides
// stops the generator with the field's name and its annotations, and so does
// a field that a rule refuses with Fail.
func Generate(source policy.Source, message policy.Message, opts ...GenerateOption) error {
	cfg := generateConfig{notices: os.Stderr, ctx: context.Background()}
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.output == "" {
		return errors.New("stashgen: Generate needs Output(path)")
	}
	if cfg.engine == nil {
		e, err := GuestEngine(cfg.ctx)
		if err != nil {
			return err
		}
		cfg.engine = e
	}
	pkgPath, typeName, err := messageType(message.Message())
	if err != nil {
		return err
	}
	return generateFor(cfg, source, message, pkgPath, typeName)
}

// messageType finds the package path and name of the message's struct type.
func messageType(message any) (pkgPath, typeName string, err error) {
	if message == nil {
		return "", "", errors.New("stashgen: ForMessage got a nil message; give it a value of the generated type, such as &pb.Individual{}")
	}
	t := reflect.TypeOf(message)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || t.Name() == "" || t.PkgPath() == "" {
		return "", "", fmt.Errorf("stashgen: the message is a %s, and the generator needs a named struct type", t)
	}
	return t.PkgPath(), t.Name(), nil
}

// generateFor is Generate once the message's type is known by name. The
// tests drive it with a type in a module the test process cannot import.
func generateFor(cfg generateConfig, source policy.Source, message policy.Message, pkgPath, typeName string) error {
	if message.Context() == "" {
		return fmt.Errorf("stashgen: %s: ForMessage needs a Context", typeName)
	}
	eqlTypes, err := cfg.engine.EQLTypes(cfg.ctx)
	if err != nil {
		return fmt.Errorf("stashgen: the engine's EQL types: %w", err)
	}
	facts, err := source.Facts(message.Message())
	if err != nil {
		return fmt.Errorf("stashgen: %s: %w", typeName, err)
	}

	outDir := filepath.Dir(cfg.output)
	outName, outPath, err := outputPackage(cfg.ctx, outDir)
	if err != nil {
		return err
	}
	msgPkg, err := loadImport(cfg.ctx, outDir, pkgPath)
	if err != nil {
		return err
	}
	if msgPkg.PkgPath == outPath {
		return fmt.Errorf("stashgen: %s is in package %s, and the generated file goes in a package of your own", typeName, outPath)
	}
	named, st, err := lookupStruct(msgPkg, typeName)
	if err != nil {
		return err
	}
	display := msgPkg.Name + "." + typeName

	// Facts decide fields; the struct's tags say which Go field a schema
	// field became, with the Go name as the fallback.
	byProtoName, byGoName := structFields(st)
	collected := &collected{context: message.Context()}
	seen := map[string]bool{}
	for _, fact := range facts {
		fld := byProtoName[fact.Name]
		if fld == nil {
			fld = byGoName[fact.GoName]
		}
		if fld == nil {
			return fieldErr(display, fact.GoName, "the source names the field %q, and the struct has no such field", fact.Name)
		}
		if seen[fld.Name()] {
			return fieldErr(display, fld.Name(), "two facts name this field")
		}
		seen[fld.Name()] = true
		outcome, ok := message.Decide(fact)
		if !ok {
			return fieldErr(display, fld.Name(), "no rule decides %s", fact)
		}
		if reason := outcome.Reason(); reason != "" {
			return fieldErr(display, fld.Name(), "refused by the policy: %s", reason)
		}
		tagValue, _ := outcome.Tag(fact.Name)
		t, err := parseTagValue(tagValue)
		if err != nil {
			return fieldErr(display, fld.Name(), "the policy's decision does not parse: %v", err)
		}
		t.Identity = outcome.Identity
		if hasInvalidType(fld.Type()) {
			return fieldErr(display, fld.Name(), "its type did not resolve: %s", packageErrors(msgPkg))
		}
		collected.fields = append(collected.fields, collectedField{tag: t, goName: fld.Name(), typ: fld.Type(), exported: fld.Exported()})
	}
	for i := range st.NumFields() {
		fld := st.Field(i)
		if fld.Exported() && !seen[fld.Name()] {
			return fieldErr(display, fld.Name(), "the source gave no fact for this field, so no rule decided it")
		}
	}

	r := &reader{pkg: msgPkg, req: Request{Type: typeName}, eql: eqlTypes, imports: newImportSet(), outPkgName: outName, outPkgPath: outPath}
	gf, err := r.build(collected, display, named, st, true, nil)
	if err != nil {
		return err
	}
	if err := cfg.engine.Check(cfg.ctx, gf.decl); err != nil {
		return err
	}
	src, err := emit(gf)
	if err != nil {
		return err
	}
	for _, n := range gf.stderrNotices() {
		fmt.Fprintln(cfg.notices, n)
	}
	return (&File{Path: cfg.output, Content: src}).Write()
}

// structFields indexes a struct's fields by the proto name in their protobuf
// tag and by Go name.
func structFields(st *types.Struct) (byProtoName, byGoName map[string]*types.Var) {
	byProtoName, byGoName = map[string]*types.Var{}, map[string]*types.Var{}
	for i := range st.NumFields() {
		fld := st.Field(i)
		byGoName[fld.Name()] = fld
		if tag, ok := lookupTag(st.Tag(i), "protobuf"); ok {
			for _, part := range strings.Split(tag, ",") {
				if name, ok := strings.CutPrefix(part, "name="); ok {
					byProtoName[name] = fld
				}
			}
		}
	}
	return byProtoName, byGoName
}

// outputPackage finds the name and import path of the package in dir. A
// directory with no Go files yet is named after itself.
func outputPackage(ctx context.Context, dir string) (name, path string, err error) {
	cfg := &packages.Config{Context: ctx, Dir: dir, Mode: packages.NeedName}
	pkgs, err := packages.Load(cfg, ".")
	if err != nil {
		return "", "", fmt.Errorf("stashgen: the output directory %s: %w", dir, err)
	}
	if len(pkgs) != 1 || pkgs[0].PkgPath == "" {
		return "", "", fmt.Errorf("stashgen: the output directory %s is not one package in a module", dir)
	}
	name = pkgs[0].Name
	if name == "" {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return "", "", err
		}
		name = filepath.Base(abs)
	}
	return name, pkgs[0].PkgPath, nil
}

// loadImport loads one import path from the module in dir.
func loadImport(ctx context.Context, dir, importPath string) (*packages.Package, error) {
	cfg := &packages.Config{
		Context: ctx,
		Dir:     dir,
		Mode:    packages.NeedName | packages.NeedTypes | packages.NeedImports | packages.NeedSyntax,
	}
	pkgs, err := packages.Load(cfg, importPath)
	if err != nil {
		return nil, fmt.Errorf("stashgen: load %s: %w", importPath, err)
	}
	if len(pkgs) != 1 || pkgs[0].Types == nil {
		return nil, fmt.Errorf("stashgen: %s did not load as one package from %s", importPath, dir)
	}
	return pkgs[0], nil
}
