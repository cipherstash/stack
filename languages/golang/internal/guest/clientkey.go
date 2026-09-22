package guest

// ClientKey is the ZeroKMS client key: long-lived key material that lives
// for the process. It is opaque on purpose. A string is immutable and
// cannot be wiped; a byte slice prints its contents under %v. This type
// prints a redaction under every verb, hands its bytes only to the package
// that consumes them, and is wiped once consumed (see ADR-0005, decision 5).
//
// stackauth reads one out of the developer profile; stackencrypt takes it
// in its Config and wipes it once the key is in guest memory. Both expose
// this type as an alias, so a key read by one is the type the other takes,
// with neither package importing the other.
type ClientKey struct {
	bytes []byte
}

// NewClientKey wraps key material. It takes ownership of b: the caller must
// not keep or reuse the slice, which is wiped along with the key.
func NewClientKey(b []byte) *ClientKey {
	return &ClientKey{bytes: b}
}

// Bytes is the key material, for the package that marshals it into guest
// memory. The slice is the key's own: do not retain it, and call Wipe once
// it has been copied where it is going. Outside this module tree the type
// has no accessor; internal visibility is what keeps it that way.
func (k *ClientKey) Bytes() []byte {
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

// String implements fmt.Stringer with a redaction, so the key never reaches
// a log through %v or %s.
func (k *ClientKey) String() string { return redactedClientKey }

// GoString implements fmt.GoStringer with the same redaction, for %#v.
func (k *ClientKey) GoString() string { return redactedClientKey }

const redactedClientKey = "ClientKey(***)"
