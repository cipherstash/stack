// Package guest is what the Go packages over the WASI guests share and
// neither should own: the locked, non-dumpable memory a guest instance runs
// in; the status table every guest reports through, the errors it decodes
// to and the Diagnostic behind each; and the opaque client key one package
// reads and the other consumes.
//
// It sits under internal so that encrypt and auth expose what they need of
// it — the error sentinels, the Diagnostic and ClientKey types — as their
// own identifiers (aliases, not copies: an error from either package is the
// same value, and a key read by one is the type the other takes) without
// either package importing the other. A binary that wants only the profile
// must not carry the crypto guest, and this is the seam that makes that
// true. See ADR-0005 in packages/stack-encrypt/docs/adr.
package guest
