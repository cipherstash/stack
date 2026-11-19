// Command sqlc-gen-stash is a sqlc process plugin that writes a Go
// package, as sqlc-gen-go does, and CipherStash encryption code for it. It
// runs a copy of sqlc-gen-go, which gives each column whose type is an EQL
// v4 domain its encrypt/eql type, and from the Go names that run works out,
// writes a package of its own with plaintext companions and batch Encrypt
// and Decrypt functions for the models and query rows that hold those
// columns and, with stash.emit_table_fields, a value for every column of
// every table, with query methods for the encrypted ones.
package main

import (
	"github.com/sqlc-dev/plugin-sdk-go/codegen"

	"github.com/cipherstash/stack/languages/golang/cmd/sqlc-gen-stash/genstash"
)

func main() {
	codegen.Run(genstash.Generate)
}
