package stashgen_test

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/stashgen"
	"github.com/cipherstash/stack/languages/golang/stashgen/enginetest"
)

// Users commit the generated file, so it documents their package, and
// linters skip it because it is marked as generated. These tests hold it to
// the conventions a linter would otherwise check.

// TestGeneratedFilesFollowGoConventions checks the output of every golden
// case.
func TestGeneratedFilesFollowGoConventions(t *testing.T) {
	for name, c := range goldenCases {
		t.Run(name, func(t *testing.T) {
			module := name
			if name == "refunds" {
				module = "orders"
			}
			req := c.req
			req.Dir = filepath.Join("testdata", "cases", module, c.dir)
			file, err := stashgen.FromTags(context.Background(), enginetest.Static{}, req)
			if err != nil {
				t.Fatalf("FromTags: %v", err)
			}
			checkConventions(t, file.Content)
		})
	}
	t.Run("policy", func(t *testing.T) {
		src, err := os.ReadFile(filepath.Join("testdata", "policy_individual_stash.go.golden"))
		if err != nil {
			t.Fatal(err)
		}
		checkConventions(t, src)
	})
	// The module's own generated files, which go generate writes with the
	// real engine.
	err := filepath.WalkDir(filepath.Join("..", "encrypt"), func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, "_stash.go") {
			return err
		}
		t.Run(path, func(t *testing.T) {
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			checkConventions(t, src)
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestParametersAreNotNamedForThePackage generates into packages named
// after each parameter the generated functions would otherwise take, and
// into package main.
func TestParametersAreNotNamedForThePackage(t *testing.T) {
	for _, pkg := range []string{"main", "users", "values", "encrypted", "models", "rows", "ctx", "cipher", "d"} {
		t.Run(pkg, func(t *testing.T) {
			dir := writeModule(t, map[string]string{
				"model.go": "package " + pkg + "\n\nimport \"github.com/cipherstash/stack/languages/golang/encrypt/eql\"\n\n" +
					"type User struct {\n\t_     struct{} `stash:\"context=users\"`\n\tID    int64    `stash:\"id,passthrough\"`\n\tEmail string   `stash:\"email,encrypt_into=TextEq\"`\n}\n\n" +
					"type Row struct {\n\tID    int64      `stash:\"id\"`\n\tEmail eql.TextEq `stash:\"email\"`\n}\n",
			})
			file, err := stashgen.FromTags(context.Background(), enginetest.Static{}, stashgen.Request{Dir: dir, Type: "User", Models: []stashgen.ModelRequest{{Name: "Rows", Type: "Row"}}})
			if err != nil {
				t.Fatalf("FromTags: %v", err)
			}
			checkConventions(t, file.Content)
			if err := file.Write(); err != nil {
				t.Fatal(err)
			}
			build(t, dir)
		})
	}
}

// checkConventions parses a generated file and reports each exported name
// without a doc comment that starts with the name, each return of a value
// together with an error, each function parameter named for the package,
// and each comment attached to no declaration.
func checkConventions(t *testing.T, src []byte) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "generated.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pkg := file.Name.Name
	at := func(n ast.Node) string { return fset.Position(n.Pos()).String() }

	documented := map[*ast.CommentGroup]bool{}
	checkDoc := func(n ast.Node, name string, doc *ast.CommentGroup) {
		if doc == nil {
			t.Errorf("%s: %s has no doc comment", at(n), name)
			return
		}
		documented[doc] = true
		if text := doc.Text(); !strings.HasPrefix(text, name+" ") {
			t.Errorf("%s: the doc comment of %s does not start with its name: %q", at(n), name, firstLine(text))
		}
	}

	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			if d.Doc != nil {
				documented[d.Doc] = true
			}
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					if s.Name.IsExported() {
						checkDoc(s, s.Name.Name, docOf(d.Doc, s.Doc))
					}
				case *ast.ValueSpec:
					for _, n := range s.Names {
						if n.IsExported() {
							checkDoc(s, n.Name, docOf(d.Doc, s.Doc))
						}
					}
				}
			}
		case *ast.FuncDecl:
			if d.Doc != nil {
				documented[d.Doc] = true
			}
			if d.Name.IsExported() && (d.Recv == nil || receiverExported(d.Recv)) {
				checkDoc(d, d.Name.Name, d.Doc)
			}
			if d.Recv == nil {
				for _, field := range d.Type.Params.List {
					for _, n := range field.Names {
						if n.Name == pkg {
							t.Errorf("%s: %s has a parameter named %s, the package's name", at(n), d.Name.Name, n.Name)
						}
					}
				}
			}
		}
	}

	ast.Inspect(file, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) < 2 {
			return true
		}
		if last, ok := ret.Results[len(ret.Results)-1].(*ast.Ident); !ok || last.Name != "err" {
			return true
		}
		for _, r := range ret.Results[:len(ret.Results)-1] {
			if !isZero(r) {
				t.Errorf("%s: returns %s together with an error, not the zero value", at(r), src[fset.Position(r.Pos()).Offset:fset.Position(r.End()).Offset])
			}
		}
		return true
	})

	for i, group := range file.Comments {
		if i == 0 || documented[group] {
			continue // the first is "Code generated by stashgen. DO NOT EDIT."
		}
		inside := false
		for _, decl := range file.Decls {
			if decl.Pos() <= group.Pos() && group.End() <= decl.End() {
				inside = true
				break
			}
		}
		if !inside {
			t.Errorf("%s: the comment %q is attached to no declaration", at(group), firstLine(group.Text()))
		}
	}
}

func docOf(groupDoc, specDoc *ast.CommentGroup) *ast.CommentGroup {
	if specDoc != nil {
		return specDoc
	}
	return groupDoc
}

func receiverExported(recv *ast.FieldList) bool {
	expr := recv.List[0].Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	switch e := expr.(type) {
	case *ast.Ident:
		return e.IsExported()
	case *ast.IndexExpr:
		id, ok := e.X.(*ast.Ident)
		return ok && id.IsExported()
	case *ast.IndexListExpr:
		id, ok := e.X.(*ast.Ident)
		return ok && id.IsExported()
	}
	return false
}

// isZero reports whether e is written as a zero value: nil, an empty
// composite literal, 0, "" or false.
func isZero(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name == "nil" || v.Name == "false"
	case *ast.CompositeLit:
		return len(v.Elts) == 0
	case *ast.BasicLit:
		return v.Value == "0" || v.Value == `""`
	}
	return false
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}
