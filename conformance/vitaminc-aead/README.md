# Value conformance corpus

`value-conformance.json` contains shared value-level transport vectors for
Rust, Node, the Go codec and the Go WASM encryption guest. Payload bytes are
frozen by `aead-value`'s scalar tag table: fixed-width integers and float bits
are little-endian, dates count days from CE, timestamps carry seconds plus
nanoseconds, and decimals retain their flags and 96-bit coefficient.

Each valid vector gives a name, kind, expected host value and hexadecimal
transport bytes. Integer and decimal values are strings to avoid JSON number
rounding. Bytes are hexadecimal. `js_date` selects a native JavaScript Date;
other timestamps retain their nanoseconds in a wrapper, spelled RFC 3339 for
years 0000-9999 and with an ISO 8601 expanded year (`+12000-…`) otherwise. `malformed` vectors
must be refused by the decoders.

Rust re-encodes every valid vector byte-for-byte. The optional `js_reencode`
and `go_reencode` fields record established host projections explicitly:
JavaScript Float32 becomes Number/Float64; Go undefined becomes nil/null.
New vectors should state any additional projection rather than skipping it.

These are the scalar/value-level vectors needed by #375. The wider #332
cross-language ciphertext, guest-object and SDK corpus remains separate work.
