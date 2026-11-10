package testusers

//go:generate go run github.com/cipherstash/stack/languages/golang/cmd/stashgen -type LiteralNote -name LiteralNote -redact

// LiteralNote exercises the declared base used by context conformance.
type LiteralNote struct {
	_    struct{} `stash:"context=tenants/acme"`
	Text string   `stash:"text,encrypt,index=equality"`
}
