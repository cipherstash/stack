package auth

import (
	"strconv"

	"github.com/cipherstash/stack/languages/golang/internal/guest"
)

// AccessKey is an opaque CTS credential. It redacts formatting and is wiped
// when ProfileStore.AccessKey consumes it, including on failure.
type AccessKey = guest.AccessKey

// NewAccessKey takes ownership of key. Do not retain or reuse the slice.
func NewAccessKey(key []byte) *AccessKey { return guest.NewAccessKey(key) }

// Encode bytes as a JSON array (Rust Vec<u8>), without an immutable Go
// string copy of the credential. Both this buffer and the final config
// are wiped after serialization/transfer. encoding/json may retain its own
// scratch copies, as with the existing client-key configuration path.
func encodeAccessKey(b []byte) []byte {
	out := make([]byte, 0, len(b)*4+2)
	out = append(out, '[')
	for i, v := range b {
		if i > 0 {
			out = append(out, ',')
		}
		out = strconv.AppendUint(out, uint64(v), 10)
	}
	return append(out, ']')
}
