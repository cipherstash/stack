// Package vcffi is the shared FFI transport codec of the vitaminc Go
// bindings: the wire encoding that carries a value tree into a wasm guest
// and a ciphertext tree back out, together with the Encryptable/Encoder
// extension point for types that control their own encoding.
//
// It exists as its own module so every binding that owns a wasm boundary
// speaks the same bytes from one implementation — vcencrypt (the
// vitaminc-encrypt reference binding) and the stack-encrypt Go SDK are the
// intended consumers. Forking the codec per binding is exactly the failure
// mode this module prevents: one codec, one hostile-input test suite, one
// fuzz corpus.
//
// # Transport, and one storage profile
//
// The transport bytes are an FFI detail with no compatibility commitment:
// nothing [Marshal], [Encode] or [MarshalCipherText] writes should ever be
// persisted. The one exception is the storage profile, [MarshalStorage] and
// [UnmarshalStorage], which write and read a value as a versioned blob for
// bytes that are kept. Its format is shared with the Rust module
// vitaminc_aead_frame::storage, specified in packages/aead-frame/STORAGE.md,
// frozen at version 1, and pinned by the golden corpus in
// packages/aead-frame/testdata/storage-v1.json, which this package's tests
// read. Use it, and only it, for bytes that outlive the process that wrote
// them. The other frozen format is the sealed leaf inside the AEAD envelope
// (see vcvalue.Sealed and the Rust crate vitaminc-aead's leaf codec).
//
// # Values and ciphertexts
//
// [Marshal] and [Unmarshal] carry the plaintext value model (Go natives,
// vcvalue.Object for maps, vcvalue.Plain for passthrough): Marshal walks
// ordinary Go values with encoding/json-style rules, consulting
// [Encryptable] first so a user type can drive the [Encoder] channels
// itself.
//
// [MarshalCipherText] and [UnmarshalCipherText] carry the ciphertext tree.
// Its structural nodes ([]any, map[string]any, vcvalue.Plain) are common to
// every binding, but the sealed-leaf marker types are deliberately not: each
// binding supplies a [LeafSet] mapping its own leaf types onto the framing,
// so a leaf sealed by one cipher is a distinct Go type from a leaf sealed by
// another and can never scan or marshal where the other belongs.
// [VCValueLeaves] is the set for the vcvalue model types.
//
// # Hostile input
//
// The decoders treat their input as untrusted: recursion depth, length
// prefixes and item counts are bounded, strings are UTF-8 validated,
// duplicate map keys are rejected, and every malformed input fails with
// [ErrMalformed] rather than panicking or over-allocating. The fuzz targets
// in this package pin that contract.
//
// [ErrMalformed] covers hostile bytes, not caller mistakes: a [LeafSet] that
// is partially wired, or that does not materialize a kind the buffer carries,
// fails with its own attributable error, so errors.Is(err, [ErrMalformed]) is
// a test for bad input rather than a total branch over decode failures.
package vcffi
