package stackauth

import "github.com/cipherstash/cipherstash-suite/bindings/go/internal/guest"

// ClientKey is the ZeroKMS client key as [ProfileStore.SecretKey] reads it
// out of secretkey.json: opaque (it prints a redaction under every verb and
// hands its bytes to no caller) and wiped once consumed. It is the same
// type as stackencrypt.ClientKey, by identity, so a key read here goes
// straight into a stackencrypt.Config without either package importing the
// other.
type ClientKey = guest.ClientKey
