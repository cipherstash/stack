package vcvalue

// Plain marks a value that must travel through the cipher **unencrypted and
// unauthenticated** — the reflection-encode opt-in for passthrough. Wrap a
// non-secret value (Plain{V: id}) and the vcencrypt
// encoder records it via its Passthrough channel instead of sealing it. Passthrough never
// happens implicitly: only an explicit Plain (or a direct
// enc.Passthrough() call) produces it.
//
// A decoded passthrough field surfaces back as Plain{V: <decoded value>},
// so the marking round-trips and a caller can tell which fields were in the
// clear. See the package docs — non-sensitive fields only.
type Plain struct {
	V any
}

// Object is the decode result for a map-mode value: an ordered list of
// fields mirroring the wire order. Decoding uses this (rather than a Go map)
// so entry order is preserved and results compare deterministically. Encode
// takes any/struct/map instead — this type is decode-only.
type Object []Field

// Field is one entry of a decoded Object.
type Field struct {
	Key   string
	Value any
}
