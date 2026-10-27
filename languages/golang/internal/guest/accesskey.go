package guest

import "fmt"

// AccessKey is opaque CTS access-key material. Public packages alias this
// type; the byte accessor is a package function so it does not travel with
// the alias. Like ClientKey, it must not be copied or used concurrently.
type AccessKey struct{ bytes []byte }

// NewAccessKey takes ownership of b. Do not retain or reuse b.
func NewAccessKey(b []byte) *AccessKey { return &AccessKey{bytes: b} }

// AccessKeyBytes lends the owned bytes to the credential guest marshaler.
// Do not retain them; Wipe the key after transferring it, even on failure.
func AccessKeyBytes(k *AccessKey) []byte {
	if k == nil {
		return nil
	}
	return k.bytes
}

// Wipe clears the owned bytes. Repeated calls and nil receivers are safe.
func (k *AccessKey) Wipe() {
	if k == nil {
		return
	}
	clear(k.bytes)
	k.bytes = nil
}

// IsZero reports an absent, empty or consumed key.
func (k *AccessKey) IsZero() bool { return k == nil || len(k.bytes) == 0 }

// Format redacts values and pointers under every formatting verb.
func (AccessKey) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte("AccessKey(***)")) }
func (AccessKey) String() string             { return "AccessKey(***)" }
func (AccessKey) GoString() string           { return "AccessKey(***)" }
