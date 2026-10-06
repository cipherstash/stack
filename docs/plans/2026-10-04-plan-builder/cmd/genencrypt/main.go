// Command genencrypt runs the rules at go generate time.
package main

import (
	"log"

	"example.com/app/rules"
	"github.com/cipherstash/stack/languages/golang/encrypt/policy/protosource"
	"github.com/cipherstash/stack/languages/golang/stashgen"
)

func main() {
	err := stashgen.Generate(protosource.New(), rules.Individuals,
		stashgen.Output("../individuals/individual_stash.go"))
	if err != nil {
		log.Fatal(err)
	}
}
