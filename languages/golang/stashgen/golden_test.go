package stashgen_test

import (
	"bytes"
	"context"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/stashgen"
	"github.com/cipherstash/stack/languages/golang/stashgen/enginetest"
)

var update = flag.Bool("update", false, "rewrite the golden files from the generator's output")

// goldenCase is one module under testdata/cases: the example input, the flags
// its go:generate line carries, and the golden file the generator must write.
type goldenCase struct {
	dir    string // the package directory, relative to the case module
	req    stashgen.Request
	golden string
}

var goldenCases = map[string]goldenCase{
	"users":     {req: stashgen.Request{Type: "User"}, golden: "user_stash.go.golden"},
	"accounts":  {req: stashgen.Request{Type: "Account", Redact: true}, golden: "account_stash.go.golden"},
	"contacts":  {req: stashgen.Request{Type: "contactStash", For: "crm.Contact", Models: []stashgen.ModelRequest{{Name: "Rows", Type: "ContactRow"}}}, golden: "contactstash_stash.go.golden"},
	"documents": {req: stashgen.Request{Type: "Document"}, golden: "document_stash.go.golden"},
	// Beyond the plan's examples: -name beside an unnamed struct in one
	// package, separate columns on an integer, an embedded struct of the same
	// package, and -for a type with unexported fields.
	"orders":   {req: stashgen.Request{Type: "Order", Name: "Order"}, golden: "order_stash.go.golden"},
	"refunds":  {dir: "", req: stashgen.Request{Type: "Refund"}, golden: "refund_stash.go.golden"},
	"embedded": {req: stashgen.Request{Type: "Patient"}, golden: "patient_stash.go.golden"},
	// A struct whose context is one of its fields, with a model that binds
	// the context field to a column.
	"tenants": {req: stashgen.Request{Type: "Note", Models: []stashgen.ModelRequest{{Name: "Rows", Type: "NoteRow"}}}, golden: "note_stash.go.golden"},
	"foreign": {req: stashgen.Request{Type: "individualStash", For: "pb.Individual"}, golden: "individualstash_stash.go.golden"},
}

func TestGolden(t *testing.T) {
	for name, c := range goldenCases {
		t.Run(name, func(t *testing.T) {
			module := name
			if name == "refunds" {
				module = "orders"
			}
			caseDir := filepath.Join("testdata", "cases", module)
			req := c.req
			req.Dir = filepath.Join(caseDir, c.dir)
			file, err := stashgen.FromTags(context.Background(), enginetest.Static{}, req)
			if err != nil {
				t.Fatalf("FromTags: %v", err)
			}
			goldenPath := filepath.Join(caseDir, c.dir, c.golden)
			if *update {
				if err := os.WriteFile(goldenPath, file.Content, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("read golden: %v (run with -update to write it)", err)
			}
			if !bytes.Equal(file.Content, want) {
				t.Errorf("generated file differs from %s (run with -update to rewrite it):\n%s", goldenPath, diff(string(want), string(file.Content)))
			}
			if got := filepath.Base(file.Path); got+".golden" != c.golden {
				t.Errorf("output path %q, want %q", got, strings.TrimSuffix(c.golden, ".golden"))
			}
			compileCase(t, caseDir, c.dir, filepath.Base(file.Path), file.Content)
		})
	}
}

// compileCase copies the case module to a temp dir with the generated file in
// it and builds it against the stub SDK, so uncompilable output fails here.
func compileCase(t *testing.T, caseDir, pkgDir, fileName string, content []byte) {
	t.Helper()
	tmp := t.TempDir()
	if err := copyTree(caseDir, tmp); err != nil {
		t.Fatal(err)
	}
	// The case's go.mod replaces the SDK and gorm with relative paths; from
	// the temp dir those must be absolute.
	testdata, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatal(err)
	}
	gomod, err := os.ReadFile(filepath.Join(tmp, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	gomod = bytes.ReplaceAll(gomod, []byte("../../stubsdk"), []byte(filepath.Join(testdata, "stubsdk")))
	gomod = bytes.ReplaceAll(gomod, []byte("../../stubgorm"), []byte(filepath.Join(testdata, "stubgorm")))
	if err := os.WriteFile(filepath.Join(tmp, "go.mod"), gomod, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, pkgDir, fileName), content, 0o600); err != nil {
		t.Fatal(err)
	}
	// A module with two tagged structs builds only with both generated files.
	goldens, _ := filepath.Glob(filepath.Join(caseDir, pkgDir, "*.golden"))
	for _, g := range goldens {
		name := strings.TrimSuffix(filepath.Base(g), ".golden")
		if name == fileName {
			continue
		}
		data, err := os.ReadFile(g)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(tmp, pkgDir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("go", "vet", "./...")
	cmd.Dir = tmp
	cmd.Env = append(os.Environ(), "GOPROXY=off", "GOWORK=off", "GOFLAGS=-mod=mod", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generated code does not build: %v\n%s", err, out)
	}
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o750)
		}
		if strings.HasSuffix(path, ".golden") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600)
	})
}

// diff is a line diff good enough to read a golden mismatch.
func diff(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	var b strings.Builder
	for i := 0; i < len(w) || i < len(g); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl != gl {
			b.WriteString("-" + wl + "\n+" + gl + "\n")
		}
	}
	return b.String()
}

// A field added to an embedded struct stops the build, as one added to the
// outer struct does: the outer shape embeds the same named type, so only
// the embedded struct's own shape notices.
func TestAFieldAddedToAnEmbeddedStructStopsTheBuild(t *testing.T) {
	caseDir := filepath.Join("testdata", "cases", "embedded")
	golden, err := os.ReadFile(filepath.Join(caseDir, "patient_stash.go.golden"))
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	if err := copyTree(caseDir, tmp); err != nil {
		t.Fatal(err)
	}
	testdata, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatal(err)
	}
	gomod, err := os.ReadFile(filepath.Join(tmp, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	gomod = bytes.ReplaceAll(gomod, []byte("../../stubsdk"), []byte(filepath.Join(testdata, "stubsdk")))
	gomod = bytes.ReplaceAll(gomod, []byte("../../stubgorm"), []byte(filepath.Join(testdata, "stubgorm")))
	src, err := os.ReadFile(filepath.Join(tmp, "embedded.go"))
	if err != nil {
		t.Fatal(err)
	}
	grown := bytes.Replace(src, []byte("\tnotes string\n"), []byte("\tnotes string\n\tPhone string `stash:\"phone,encrypt\"`\n"), 1)
	if bytes.Equal(grown, src) {
		t.Fatal("the case's Person changed; update this test")
	}
	for name, data := range map[string][]byte{"go.mod": gomod, "embedded.go": grown, "patient_stash.go": golden} {
		if err := os.WriteFile(filepath.Join(tmp, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("go", "build", "./...")
	cmd.Dir = tmp
	cmd.Env = append(os.Environ(), "GOPROXY=off", "GOWORK=off", "GOFLAGS=-mod=mod", "CGO_ENABLED=0")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("the stale file still compiles after Person gained a field")
	}
	if !strings.Contains(string(out), "patientShapePerson") {
		t.Fatalf("the build failed, but not at the embedded shape:\n%s", out)
	}
}
