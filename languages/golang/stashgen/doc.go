// Package stashgen is the Stack Encrypt code generator for Go, as a library.
//
// A struct's stash tags declare how each field is encrypted. [FromTags] reads
// those tags through go/packages and go/types, checks the declaration with an
// [Engine], and returns the file that the command stashgen writes beside the
// struct: the encrypted type, Encrypt, Decrypt, Fields and the print methods.
// The command at languages/golang/cmd/stashgen is the go:generate front end
// for this package.
//
// The generator reads types, not text, and runs none of the package's code.
// It ignores its own output file when it loads the package, so a stale
// generated file does not stop it. The same input always gives the same file:
// fields keep their declared order, and the file carries no version and no
// time beyond the gensupport.GeneratedVersion1 constant it names.
//
// [Generate] writes the same file for a type that cannot carry tags, from a
// policy in package encrypt/policy: a source gives the facts about each field
// and the policy's rules decide them. A decision spells itself in the tag
// grammar, so both paths go through one parser and one emitter.
//
// Every refusal about an index, an EQL type or a field type comes from the
// Engine. The generator holds no copy of the engine's rules.
package stashgen
