// Package eqlguest is where package eql hands the guest build with the EQL
// types to package encrypt. Package encrypt embeds the build without them
// and cannot import eql (eql imports encrypt), so eql registers its module
// here on import and encrypt's embeddedGuest reads it first. Registration
// cannot fail: it is two assignments at program start.
package eqlguest

var (
	linked bool
	module []byte
)

// Register says package eql is linked and installs its guest build, nil
// when the module was not built. Called once, by package eql's init.
func Register(wasm []byte) {
	linked = true
	module = wasm
}

// Linked reports whether package eql is linked: the program names an EQL
// type, so it must run the build that holds them and never the other.
func Linked() bool { return linked }

// Module is the registered eql guest build, or nil when package eql is not
// linked or its module was not built.
func Module() []byte { return module }
