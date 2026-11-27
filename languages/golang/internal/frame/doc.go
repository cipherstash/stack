// Package frame is the Go half of the frame codec: the bytes that carry a
// value into the Stack Encrypt guest, the bytes that carry a ciphertext tree
// back out, and the storage profile, which writes a value as a blob that is
// kept. The Rust half is the crate recipher-frame. The two halves share no
// code, only bytes, so both read the same corpora: the value corpus in
// conformance/vitaminc-aead and the storage corpus in
// packages/recipher-frame/testdata.
//
// The package also holds the value model the codec reads and writes: the
// value types (Date, Decimal, Int128, Uint128, UUID), Object and Field for a
// map read back in its wire order, and Plain for a value that travels in
// the clear.
//
// # Transport, and one storage profile
//
// The transport bytes have no compatibility commitment: nothing [Marshal],
// [Encode] or [MarshalCipherText] writes is ever kept. The one exception is
// the storage profile, [MarshalStorage] and [UnmarshalStorage], which write
// and read a value as a versioned blob. Its format is version 1 of
// packages/recipher-frame/STORAGE.md, shared with the Rust module
// recipher_frame::storage, frozen, and pinned by the storage corpus, which
// this package's tests read. Use it, and only it, for bytes that outlive
// the process that wrote them.
//
// # Values and ciphertexts
//
// [Marshal] and [Unmarshal] carry a value: Go's own scalars, the value
// types, []any for a list, [Object] for a map read back, and [Plain] for
// passthrough. Marshal walks other Go values with encoding/json-style rules,
// and asks [Encryptable] first, so a type can write itself through an
// [Encoder].
//
// [MarshalCipherText] and [UnmarshalCipherText] carry the ciphertext tree.
// Its structural nodes ([]any, map[string]any, [Plain]) are the codec's. Its
// sealed leaves are the caller's own types, which a [LeafSet] maps onto the
// framing, so a leaf is a type no other value can be mistaken for.
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
package frame
