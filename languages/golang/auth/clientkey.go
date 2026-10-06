package auth

import "github.com/cipherstash/stack/languages/golang/internal/guest"

// ClientKey is the ZeroKMS client key as [ProfileStore.SecretKey] reads it
// out of secretkey.json: opaque (it prints a redaction under every verb and
// hands its bytes to no caller) and wiped once consumed. It is the same
// type as encrypt.ClientKey, by identity, so a key read here goes
// straight into encrypt.NewCredentials. This package does not import
// encrypt: a binary that only wants the profile does not carry the
// crypto guest. (encrypt imports this one, for AutoCredentials.)
type ClientKey = guest.ClientKey
