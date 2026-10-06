// Package eqlguest is where package eql hands the guest build with the EQL
// types to package encrypt. Package encrypt embeds the build without them
// and cannot import eql (eql imports encrypt), so eql registers its module
// here on import and encrypt's embeddedGuest reads it first. Registration
// cannot fail: it is two assignments at program start.
package eqlguest

var module []byte

// Register installs the eql guest build. Called once, by package eql's init.
func Register(wasm []byte) { module = wasm }

// Module is the registered eql guest build, or nil when package eql is not
// linked or its module was not built.
func Module() []byte { return module }
