package eql

import (
	"embed"

	"github.com/cipherstash/stack/languages/golang/encrypt/internal/eqlguest"
)

// The guest module with the EQL types is a build artefact of the Rust
// crate in ../guest with its `eql` feature, copied here by
// `mise run wasm:guest:build:eql`. It is embedded as a directory so the
// package compiles without it; encrypt.NewClient reports its absence. Its
// deterministic-kms test build lives under encrypt/testdata with the other
// test build: nothing test-only is embedded.
//
//go:embed wasm
var guestFS embed.FS

const guestPath = "wasm/stack_encrypt_guest_eql.wasm"

// Linking this package selects the build of the engine that holds the EQL
// types, and only that build: a program whose generated code names an EQL
// type must not fall back to the build without them, where every
// encrypt_into call would fail. The registration cannot fail; an absent
// module registers nil, and encrypt.NewClient reports ErrEQLGuestNotBuilt.
func init() {
	wasm, err := guestFS.ReadFile(guestPath)
	if err != nil {
		wasm = nil
	}
	eqlguest.Register(wasm)
}
