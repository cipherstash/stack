package stashgen_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt/policy"
	"github.com/cipherstash/stack/languages/golang/stashgen"
	"github.com/cipherstash/stack/languages/golang/stashgen/enginetest"
)

var category = policy.Key("classification.data_categories")

// individualFacts is what protosource would read from individual.proto.
func individualFacts(any) ([]policy.Fact, error) {
	f := func(name, goName, kind string, categories ...string) policy.Fact {
		fact := policy.Fact{Message: "individuals.Individual", Name: name, GoName: goName, Kind: kind}
		if len(categories) > 0 {
			fact.Annotations = []policy.Annotation{{Key: string(category), Values: categories}}
		}
		return fact
	}
	return []policy.Fact{
		f("id", "Id", "int64"),
		f("name", "Name", "string", "user.name"),
		f("email", "Email", "string", "user.contact.email"),
		f("medicare_no", "MedicareNo", "string", "user.government_id"),
		f("nickname", "Nickname", "string"),
	}, nil
}

var base = policy.FirstOf(
	policy.When(category.Under("user.government_id"), policy.EncryptInto("TextEq")),
	policy.When(category.Under("user.contact.email"), policy.EncryptIndex(policy.Equality, policy.Match())),
	policy.When(category.Under("user"), policy.Encrypt()),
)

func individualRules(extra ...policy.Rule) policy.Message {
	rules := policy.FirstOf(
		policy.When(policy.Field("medicare_no"), policy.EncryptInto("TextEq"), policy.Name("medicare_number")),
		policy.When(policy.Field("id"), policy.Passthrough()),
		policy.When(policy.Field("nickname"), policy.Passthrough()),
	)
	rules = append(rules, extra...)
	return policy.ForMessage(struct{}{}, policy.Context("individuals"), rules.OrElse(base))
}

// policyModule copies the foreign case, whose pb package stands in for
// protoc-gen-go output, and adds an empty individuals directory.
func policyModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join("testdata", "cases", "foreign")
	for _, name := range []string{"go.mod", "pb/individual.go"} {
		data, err := os.ReadFile(filepath.Join(src, name))
		if err != nil {
			t.Fatal(err)
		}
		if name == "go.mod" {
			testdata, _ := filepath.Abs("testdata")
			data = bytes.ReplaceAll(data, []byte("../../stubsdk"), []byte(filepath.Join(testdata, "stubsdk")))
			data = bytes.ReplaceAll(data, []byte("../../stubgorm"), []byte(filepath.Join(testdata, "stubgorm")))
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "individuals"), 0o750); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestGenerateFromAPolicy(t *testing.T) {
	dir := policyModule(t)
	out := filepath.Join(dir, "individuals", "individual_stash.go")
	var notices bytes.Buffer
	err := stashgen.GenerateFor(context.Background(), enginetest.Static{}, &notices, out, policy.SourceFunc(individualFacts), individualRules(), "example.com/app/pb", "Individual")
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "policy_individual_stash.go.golden")
	if *update {
		if err := os.WriteFile(golden, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run with -update to write it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("generated file differs from %s:\n%s", golden, got)
	}
	if !strings.Contains(notices.String(), "pb.Individual prints its sealed fields in the clear") {
		t.Errorf("notices = %q", notices.String())
	}
	// The policy path and the tag path write the same file for the same
	// declaration, but for the header comments the tag path cannot know.
	tagged, err := os.ReadFile(filepath.Join("testdata", "cases", "foreign", "individualstash_stash.go.golden"))
	if err != nil {
		t.Fatal(err)
	}
	if body(string(got)) != body(string(tagged)) {
		t.Errorf("the policy path and the tag path disagree:\n%s", diff(body(string(tagged)), body(string(got))))
	}
}

// body drops everything before the encrypted type: the package clause, the
// imports and the notices, which the two paths word differently.
func body(src string) string {
	i := strings.Index(src, "\ntype Encrypted")
	if i < 0 {
		return src
	}
	return src[i:]
}

func TestGenerateRefusals(t *testing.T) {
	dir := policyModule(t)
	out := filepath.Join(dir, "individuals", "individual_stash.go")
	cases := []struct {
		name    string
		source  policy.Source
		message policy.Message
		want    string
	}{
		{"a field no rule decides", policy.SourceFunc(individualFacts),
			policy.ForMessage(struct{}{}, "individuals", policy.When(policy.Field("id"), policy.Passthrough())),
			`pb.Individual.Name: no rule decides individuals.Individual.name (string; classification.data_categories = user.name)`},
		{"a field a rule refuses", policy.SourceFunc(individualFacts),
			individualRules(policy.When(policy.Field("name"), policy.Fail("names are not stored"))),
			"pb.Individual.Name: refused by the policy: names are not stored"},
		{"a fact for a field the struct lacks", policy.SourceFunc(func(any) ([]policy.Fact, error) {
			return []policy.Fact{{Message: "m", Name: "shoe_size", GoName: "ShoeSize", Kind: "int32"}}, nil
		}), individualRules(policy.Otherwise(policy.Passthrough())), `the source names the field "shoe_size", and the struct has no such field`},
		{"a struct field with no fact", policy.SourceFunc(func(any) ([]policy.Fact, error) {
			return []policy.Fact{{Message: "m", Name: "id", GoName: "Id", Kind: "int64"}}, nil
		}), individualRules(policy.Otherwise(policy.Passthrough())), "pb.Individual.Name: the source gave no fact for this field"},
		{"no context", policy.SourceFunc(individualFacts), policy.ForMessage(struct{}{}, "", base), "ForMessage needs a Context"},
		{"an index the engine refuses", policy.SourceFunc(individualFacts),
			individualRules(policy.When(policy.Field("name"), policy.EncryptIndex(policy.Match(policy.IndexOption{Key: "k", Value: "3"})))),
			"pb.Individual.Name: index match(k=3): the engine cannot carry index options"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := stashgen.GenerateFor(context.Background(), enginetest.Static{}, &bytes.Buffer{}, out, c.source, c.message, "example.com/app/pb", "Individual")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %v, want one containing %q", err, c.want)
			}
			if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
				t.Fatal("a file was written after a refusal")
			}
		})
	}
}

func TestGenerateNeedsOutputAndAMessage(t *testing.T) {
	if err := stashgen.Generate(policy.SourceFunc(individualFacts), individualRules()); err == nil || !strings.Contains(err.Error(), "needs Output") {
		t.Fatalf("err = %v", err)
	}
	type local struct{ A int }
	pkgPath, name, err := stashgen.MessageType(&local{})
	if err != nil || name != "local" || !strings.HasSuffix(pkgPath, "/stashgen_test") {
		t.Fatalf("messageType = %q %q %v", pkgPath, name, err)
	}
	if _, _, err := stashgen.MessageType(nil); err == nil {
		t.Fatal("nil message accepted")
	}
	if _, _, err := stashgen.MessageType(42); err == nil {
		t.Fatal("an int accepted as a message")
	}
	// With no WithEngine the embedded guest answers; the output directory
	// is no module, so the run stops there or, with no guest built, before.
	err = stashgen.Generate(policy.SourceFunc(individualFacts), policy.ForMessage(&local{}, "c", base), stashgen.Output(filepath.Join(t.TempDir(), "x_stash.go")))
	if err == nil {
		t.Fatal("a message in no module generated")
	}
}
