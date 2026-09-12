// Package stackencrypt is the Go binding of stack-encrypt: ZeroKMS-backed
// field-level encryption with searchable index terms, running the Rust
// crate unmodified inside a WASI guest under wazero (CGO_ENABLED=0).
//
// # Shape
//
// A [Client] is one wasm instance and one ZeroKMS client: [NewClient]
// instantiates the embedded guest, hands it the client key once, and loads
// the client's default keyset. Every keyset the client uses after that is
// selected per call through a [KeysetSelector] and loaded on first use by
// the guest's own bounded cache; nothing the host could allocate, alias or
// free crosses the boundary. [Client.Close] runs the guest's shutdown so the
// client key and every loaded index key are wiped before the instance is
// freed — closing a wasm instance runs no Rust destructors on its own.
//
// A [Cipher] is the client bound to one keyset ([Client.Cipher],
// [Client.DefaultCipher]): it seals values, derives terms and encrypts
// records under that keyset, and opens only that keyset's ciphertexts. The
// [Client] itself opens ciphertexts from any keyset ([Client.Decrypt] and
// friends), fetching one batched key retrieval per keyset the leaves were
// sealed under.
//
// # Values
//
// Values cross the boundary in vitaminc's FFI codec ([vcffi]) and are
// modelled as Go natives ([vcvalue]): builtins, slices, maps and structs
// seal by reflection, [vcvalue.Plain] marks a passthrough field, and a
// type implementing [vcffi.Encryptable] drives its own encoding. A
// ciphertext is the same dynamic shape with [Sealed] leaves — a distinct
// type from vcvalue's, because a stack-encrypt leaf is not a vitaminc leaf
// and must never scan or marshal where one belongs. The leaf bytes are the
// frozen stack-encrypt storage format; the transport encoding is not.
//
// # Records and terms
//
// [Cipher.EncryptRecords] is the runtime form of the Rust derive: a struct's
// `stash` tags say, per field, which context to bind and which index terms
// to produce, and one call seals every row of a slice from one batched key
// request. Terms ([EqualityTerm], [MatchTerm], [OreTerm], [OpeTerm]) are
// byte-equal to the ones the Rust crate derives, so a probe from
// [Cipher.Term] compares against a stored term from any language.
// [Cipher.Term] takes a context and returns an error from day one: term
// derivation may be a ZeroKMS round trip.
//
// # Transport and auth
//
// The guest imports exactly two host functions: an HTTP send, served by any
// [net/http.RoundTripper], and a bearer-token fetch, served by a
// [TokenSource]. What crosses per ZeroKMS call is what would cross TLS
// anyway; derived key material never leaves the guest.
//
// # Host runtime
//
// The guest also imports WASI random_get and clock_time_get, and the
// cipher's security rests on the first: ZeroKMS IVs and AEAD nonces are
// drawn from it. wazero's defaults for both are deterministic, so every
// instance is configured with the process CSPRNG ([crypto/rand.Reader])
// and the system clocks. An embedder that instantiates the guest module
// under its own wazero configuration must do the same.
package stackencrypt
