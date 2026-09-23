package guest

import "fmt"

// ClientKey is the ZeroKMS client key: long-lived key material that lives
// for the process. It is opaque on purpose. A string is immutable and
// cannot be wiped; a byte slice prints its contents under %v. This type
// prints a redaction under every verb, whether formatted as a value or a
// pointer, hands its bytes only to this package tree, and is wiped once
// consumed (see ADR-0005, decision 5).
//
// stackauth reads one out of the developer profile; stackencrypt takes it
// in its Config (from CIP-4118 on) and wipes it once the key is in guest
// memory. Both expose this type as an alias, so a key read by one is the
// type the other takes, with neither package importing the other.
//
// The public packages alias the type, and an alias carries every exported
// method with it — Go's internal rule stops the import, not the call. So
// the accessor is a function of this package, KeyBytes, not a method: a
// caller outside internal can construct, wipe and print a key, and nothing
// else.
type ClientKey struct {
	bytes []byte
}

// NewClientKey wraps key material. It takes ownership of b: the caller must
// not keep or reuse the slice, which is wiped along with the key.
func NewClientKey(b []byte) *ClientKey {
	return &ClientKey{bytes: b}
}

// KeyBytes is the key material, for the package that marshals it into
// guest memory. The slice is the key's own: do not retain it, and call
// Wipe once it has been copied where it is going. A function rather than
// a method so it does not travel with the alias (see ClientKey).
func KeyBytes(k *ClientKey) []byte {
	if k == nil {
		return nil
	}
	return k.bytes
}

// Wipe zeroes the key material. A wiped key is empty; a second Wipe is a
// no-op.
func (k *ClientKey) Wipe() {
	if k == nil {
		return
	}
	clear(k.bytes)
	k.bytes = nil
}

// IsZero reports whether the key holds no material: never set, or wiped.
func (k *ClientKey) IsZero() bool {
	return k == nil || len(k.bytes) == 0
}

// Format implements fmt.Formatter, which fmt consults before Stringer and
// GoStringer and for every verb — %d and %x included, which would
// otherwise print the field. A value receiver, so a copied key redacts as
// the pointer does. The one thing fmt prints without asking is a nil
// pointer, as "<nil>"; there is no material behind one.
func (ClientKey) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(redactedClientKey))
}

// String implements fmt.Stringer with the same redaction, for callers that
// call it directly rather than through fmt.
func (ClientKey) String() string { return redactedClientKey }

// GoString implements fmt.GoStringer with the same redaction.
func (ClientKey) GoString() string { return redactedClientKey }

const redactedClientKey = "ClientKey(***)"
