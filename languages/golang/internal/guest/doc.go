// Package guest is what the Go packages over the WASI guests share and
// neither should own: the locked, non-dumpable memory a guest instance runs
// in; the status table every guest reports through, the errors it decodes
// to and the Diagnostic behind each; and the opaque client key one package
// reads and the other consumes.
//
// It sits under internal so that encrypt and auth expose what they need of
// it — the error sentinels, the Diagnostic and ClientKey types — as their
// own identifiers (aliases, not copies: a key read by one is the type the
// other takes) without either package importing the other. Where both
// packages give a name to the same sentinel, as ErrEncoding, ErrState,
// ErrInternal and ErrMemoryLock, it is one value. ErrNotFound and
// ErrTransport name different sentinels in each package: ErrNotFound and
// ErrTransport in encrypt, ErrProfileNotFound and ErrAuthTransport in auth. A binary that wants only the profile
// must not carry the crypto guest, and this is the seam that makes that
// true. See ADR-0005 in packages/stack-encrypt/docs/adr.
package guest
