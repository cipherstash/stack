package frame

// Plain marks a passthrough value. A passthrough value is neither encrypted
// nor authenticated, so use Plain only for a value that is not secret.
//
// To make a value passthrough, wrap it, as in Plain{V: id}. The encoder then
// writes the value through [Encoder.Passthrough] and does not seal it. The
// codec never makes a value passthrough by itself. Only a Plain, or a direct
// call to [Encoder.Passthrough], does that.
//
// A passthrough value decodes as Plain{V: v}, where v is the decoded value.
// The caller can therefore tell which values were not encrypted. A decoded
// Plain encodes as a passthrough value again.
type Plain struct {
	V any
}

// Object is what a map decodes as: the map's fields, in the order they were
// encoded. The decoders return an Object and not a Go map, because a Go map
// has no order. Two decodes of the same bytes therefore give equal Objects.
//
// To encode a map, pass a struct or a Go map. Encode also accepts an Object
// that a decoder returned.
type Object []Field

// Field is one entry of a decoded Object.
type Field struct {
	Key   string
	Value any
}
