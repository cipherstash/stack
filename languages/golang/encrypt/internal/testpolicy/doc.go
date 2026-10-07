// Package testpolicy holds the file stashgen.Generate writes for
// testmember.Member from a policy (see internal/genmember): the generated
// Encrypt, Decrypt and Fields over *testmember.Member, with the declaration
// testusers.User carries as tags. The encrypt tests run it against the
// deterministic guest beside the tag path and the -for path, so code from
// a policy is executed, not only compiled. `go generate ./...` rewrites
// member_stash.go, and CI fails when that changes it.
package testpolicy

//go:generate go run github.com/cipherstash/stack/languages/golang/encrypt/internal/genmember
