// Command genplans runs the policy at go generate time.
package main

import (
	"log"

	"example.com/app/policy"
	"github.com/cipherstash/stack/languages/golang/stashgen"
)

func main() {
	if err := stashgen.Generate(policy.Source, policy.Individuals, stashgen.Output("individual_stash.go")); err != nil {
		log.Fatal(err)
	}
}
