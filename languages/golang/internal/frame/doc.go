// Package frame encodes and decodes the bytes that the Go module exchanges
// with its guests. A guest is a WebAssembly module that the Go module runs.
// The Stack Encrypt guest is the guest that encrypts and decrypts.
//
// A frame is the bytes that encode one value. The package has three
// encodings:
//
//   - The value encoding is for a value that crosses between Go and a guest.
//     [Marshal] writes it and [Unmarshal] reads it.
//   - The ciphertext encoding is for a ciphertext tree that crosses between
//     Go and the Stack Encrypt guest. [MarshalCipherText] writes it and
//     [UnmarshalCipherText] reads it.
//   - The storage profile is for a value that a program stores, as a blob.
//     [MarshalStorage] writes it and [UnmarshalStorage] reads it.
//
// The Rust crate recipher-frame implements the same encodings. The Go code
// and the Rust code share nothing. The tests of both read the same two files
// of expected bytes: the value corpus in conformance/vitaminc-aead, and the
// storage corpus in packages/recipher-frame/testdata.
//
// The package also declares the types that the codec reads and writes:
//
//   - The value types [Date], [Decimal], [Int128], [Uint128], and [UUID].
//   - [Object] and [Field], for a decoded map. The fields are in the order
//     they were encoded.
//   - [Plain], for a passthrough value. A passthrough value is neither
//     encrypted nor authenticated.
//
// # Transport bytes and the storage profile
//
// Never store the bytes that [Marshal], [Encode], or [MarshalCipherText]
// writes. Those are transport bytes. Transport bytes exist only while a call
// crosses into or out of a guest. A later release can change their encoding.
//
// Store only the bytes of the storage profile. [MarshalStorage] writes a
// value as a versioned blob, and [UnmarshalStorage] reads one. The format is
// version 1 of packages/recipher-frame/STORAGE.md, and that version never
// changes. The Rust module recipher_frame::storage reads and writes the same
// format. The tests of this package check the format against the storage
// corpus.
//
// # Values and ciphertexts
//
// [Marshal] and [Unmarshal] encode and decode a value. A value is one of
// these:
//
//   - a Go scalar
//   - a value type
//   - a []any, for a list
//   - an [Object], for a decoded map
//   - a [Plain], for a passthrough value
//
// Marshal encodes any other Go value by reflection, with rules like those of
// encoding/json. Before Marshal uses reflection, it checks whether the value
// implements the published Encryptable interface. A type that implements
// Encryptable writes itself through an [Encoder]. See [PublishEncryptable].
//
// [MarshalCipherText] and [UnmarshalCipherText] encode and decode a
// ciphertext tree. The codec defines the structural nodes of the tree:
// []any, map[string]any, and [Plain]. The caller defines the types of the
// sealed leaves. A sealed leaf is one encrypted value in the tree.
//
// The caller gives the codec a [LeafSet]. The LeafSet converts between the
// caller's leaf types and the encoded leaves. A leaf therefore has a Go type
// of its own. No other value can be used in place of a leaf.
//
// # Hostile input
//
// The decoders treat their input as untrusted. Every decoder applies these
// rules:
//
//   - The nesting depth, every length prefix, and every item count have a
//     limit.
//   - Every string must be valid UTF-8.
//   - A map must not have a duplicate key.
//
// A decoder returns [ErrMalformed] for every malformed input. A decoder
// never panics, and never allocates more memory than its input can fill. The
// fuzz targets in this package test these rules.
//
// [ErrMalformed] means that the bytes are bad. A mistake by the caller fails
// with a different error. That error names the mistake. There are two such
// mistakes:
//
//   - A [LeafSet] has a nil function.
//   - The Make function of a LeafSet returns nil for a kind of leaf that the
//     input contains.
//
// So errors.Is(err, [ErrMalformed]) tests for bad input. That test is not
// true for every decode failure.
package frame
