// Command genmember writes testpolicy's generated file from a policy: the
// stashgen.Generate path, over testmember.Member, with the declaration
// testusers.User carries as tags. go generate runs it from the testpolicy
// directory, so the file lands there and CI's generate-and-diff check
// covers it like every other generated file.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testmember"
	"github.com/cipherstash/stack/languages/golang/encrypt/policy"
	"github.com/cipherstash/stack/languages/golang/stashgen"
)

// facts is what a schema source would say about Member: a fact per field,
// with no annotations, so the rules decide by field name.
func facts(any) ([]policy.Fact, error) {
	f := func(name, goName, kind string) policy.Fact {
		return policy.Fact{Message: "testmember.Member", Name: name, GoName: goName, Kind: kind}
	}
	return []policy.Fact{
		f("id", "ID", "int64"),
		f("age", "Age", "uint32"),
		f("email", "Email", "string"),
		f("notes", "Notes", "string"),
	}, nil
}

// rules is testusers.User's declaration as a policy.
var rules = policy.ForMessage(&testmember.Member{}, policy.Context("users"), policy.FirstOf(
	policy.When(policy.Field("id"), policy.Passthrough()),
	policy.When(policy.Field("age"), policy.EncryptIndex(policy.Equality, policy.Ore)),
	policy.When(policy.Field("email"), policy.EncryptIndex(policy.Equality, policy.Match())),
	policy.When(policy.Field("notes"), policy.Encrypt()),
))

func main() {
	if err := stashgen.Generate(context.Background(), policy.SourceFunc(facts), rules, "member_stash.go"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
