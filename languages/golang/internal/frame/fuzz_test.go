package vcffi

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"slices"
	"testing"
)

// Unmarshal and UnmarshalCipherText are the package's entire hostile-input
// surface: arbitrary bytes from the wasm boundary or a database column. The
// fuzz targets assert the decoders never panic, and that anything they accept
// re-encodes to the same bytes (see requireCanonical) — errors are fine,
// crashes and drift are not. Run in CI as ordinary tests over the seed corpus,
// nightly as real fuzzing (.github/workflows/fuzz.yml), and with
// `go test -fuzz` locally for exploration.

// addCorpusSeeds seeds a fuzz target with every valid and malformed vector in
// the shared value corpus, so the fuzzer starts from each scalar tag.
func addCorpusSeeds(f *testing.F, wrap func([]byte) []byte) {
	data, err := os.ReadFile("../../../testdata/value-conformance.json")
	if err != nil {
		f.Fatal(err)
	}
	var corpus struct {
		Vectors, Malformed, Normalized []struct{ Transport string }
		CiphertextMalformed            []struct{ Transport string } `json:"ciphertext_malformed"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		f.Fatal(err)
	}
	rows := append(append(corpus.Vectors, corpus.Malformed...), corpus.Normalized...)
	for _, row := range rows {
		raw, err := hex.DecodeString(row.Transport)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(wrap(raw))
	}
	// The malformed ciphertext transports are seeds as they are: the
	// ciphertext targets must refuse them, and the value targets must not
	// read them as a value either.
	for _, row := range corpus.CiphertextMalformed {
		raw, err := hex.DecodeString(row.Transport)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
}

// canonicalForm is what an accepted value encoding re-encodes as. Four
// things may legitimately change, and nothing else: an Undefined tag (0x01)
// comes back as Null (0x00), Go's documented projection; a typed null comes
// back as Null too, as Rust's frame writer writes it; a decimal negative
// zero comes back as zero with its scale kept (ADR 0001); and a timestamp in
// the 0xF3 envelope (seconds, milliseconds or microseconds) comes back in
// the shorthand nanosecond form, because Go reads it as a time.Time. The
// walker follows the transport format independently of the decoder, so a
// walk that falls out of step with it produces the wrong bytes and fails
// requireCanonical rather than passing.
func canonicalForm(data []byte) []byte {
	r := &reader{buf: data}
	var out []byte
	canonicalValue(r, &out)
	return out
}

func requireCanonical(t *testing.T, data, out, want []byte) {
	t.Helper()
	if !bytes.Equal(out, want) {
		t.Fatalf("accepted %x re-encoded as %x, want %x", data, out, want)
	}
}

func canonicalValue(r *reader, out *[]byte) {
	tag, _ := r.byteTag()
	switch tag {
	case tagUndefined:
		*out = append(*out, tagNull)
	case tagDecimal:
		b, _ := r.take(16)
		b = bytes.Clone(b)
		// flags(4) then the coefficient(12): a set sign bit over a zero
		// coefficient is a negative zero, read back as zero.
		if len(b) == 16 && bytes.Equal(b[4:], make([]byte, 12)) {
			b[3] &^= 0x80
		}
		*out = append(append(*out, tag), b...)
	case tagEnvelope:
		header, _ := r.take(2)
		if len(header) == 2 && header[0] == logicalTimestamp && header[1] <= unitMicros {
			if shorthand, ok := shorthandTimestamp(r, header[1]); ok {
				*out = append(*out, shorthand...)
				return
			}
		}
		*out = append(append(*out, tag), header...)
		canonicalValue(r, out)
	case tagInt32, tagUint32, tagFloat32:
		b, _ := r.take(4)
		*out = append(append(*out, tag), b...)
	case tagInt64, tagUint64, tagFloat64:
		b, _ := r.take(8)
		*out = append(append(*out, tag), b...)
	case tagString, tagBytes:
		start := r.pos
		n, _ := r.count()
		_, _ = r.take(n)
		*out = append(append(*out, tag), r.buf[start:r.pos]...)
	case tagArray:
		start := r.pos
		n, _ := r.count()
		*out = append(append(*out, tag), r.buf[start:r.pos]...)
		for range n {
			canonicalValue(r, out)
		}
	case tagObject:
		start := r.pos
		n, _ := r.count()
		*out = append(append(*out, tag), r.buf[start:r.pos]...)
		for range n {
			start := r.pos
			_, _ = r.str()
			*out = append(*out, r.buf[start:r.pos]...)
			canonicalValue(r, out)
		}
	case tagPassthrough:
		*out = append(*out, tag)
		canonicalValue(r, out)
	case tagTypedNull:
		// The header names the type, which fixes the padding; it all comes
		// back as the plain null.
		header, _ := r.byteTag()
		width := fixedWidth(header)
		if header == tagEnvelope {
			b, _ := r.take(3)
			if len(b) == 3 {
				width = fixedWidth(b[2])
				if b[2] == tagBytes {
					width = 16
				}
			}
		}
		_, _ = r.take(width - 1)
		*out = append(*out, tagNull)
	default:
		// Null, booleans and the fixed-width extended scalars.
		b, _ := r.take(fixedWidth(tag))
		*out = append(append(*out, tag), b...)
	}
}

// shorthandTimestamp reads the int the envelope carries and writes the
// instant as the shorthand Timestamp tag: i64 seconds then u32 nanoseconds.
// Follows the int encodings by width rather than the decoder.
func shorthandTimestamp(r *reader, unit byte) ([]byte, bool) {
	tag, _ := r.byteTag()
	var count *big.Int
	switch tag {
	case tagInt8, tagInt16, tagInt32, tagInt64, tagInt128:
		b, _ := r.take(fixedWidth(tag))
		if len(b) == 0 {
			return nil, false
		}
		count = signedLittle(b)
	case tagUint8, tagUint16, tagUint32, tagUint64, tagUint128:
		b, _ := r.take(fixedWidth(tag))
		if len(b) == 0 {
			return nil, false
		}
		count = unsignedLittle(b)
	default:
		return nil, false
	}
	per := map[byte]int64{unitSeconds: 1_000_000_000, unitMillis: 1_000_000, unitMicros: 1_000}[unit]
	nanos := new(big.Int).Mul(count, big.NewInt(per))
	seconds, sub := new(big.Int).DivMod(nanos, big.NewInt(1_000_000_000), new(big.Int))
	if !seconds.IsInt64() {
		return nil, false
	}
	out := []byte{tagTimestamp}
	out = binary.LittleEndian.AppendUint64(out, uint64(seconds.Int64()))
	return binary.LittleEndian.AppendUint32(out, uint32(sub.Int64())), true
}

func unsignedLittle(b []byte) *big.Int {
	be := make([]byte, len(b))
	for i, x := range b {
		be[len(b)-1-i] = x
	}
	return new(big.Int).SetBytes(be)
}

func signedLittle(b []byte) *big.Int {
	v := unsignedLittle(b)
	if b[len(b)-1]&0x80 != 0 {
		v.Sub(v, new(big.Int).Lsh(big.NewInt(1), uint(8*len(b))))
	}
	return v
}

// cipherCanonicalForm is canonicalForm for an accepted ciphertext tree,
// where a value can only appear inside passthrough nodes. One more thing
// may change here: the entries of a map come back sorted by key. Rust
// writes a map's entries in the order it holds them (a struct's field
// order, say), while Go reads a map into map[string]any, which keeps no
// order, and writes it back with the keys sorted. Entry order is not
// authenticated, so the decoder accepts either and the walker sorts.
func cipherCanonicalForm(data []byte) []byte {
	r := &reader{buf: data}
	var out []byte
	var walk func()
	walk = func() {
		tag, _ := r.byteTag()
		if _, ok := leafKind(tag); ok {
			start := r.pos
			n, _ := r.count()
			_, _ = r.take(n)
			out = append(append(out, tag), r.buf[start:r.pos]...)
			return
		}
		switch tag {
		case ctSeq:
			start := r.pos
			n, _ := r.count()
			out = append(append(out, tag), r.buf[start:r.pos]...)
			for range n {
				walk()
			}
		case ctMap:
			start := r.pos
			n, _ := r.count()
			out = append(append(out, tag), r.buf[start:r.pos]...)
			// Each entry is walked onto out, then cut back off and kept
			// aside, so the entries can be written in key order.
			type entry struct {
				key   string
				bytes []byte
			}
			var entries []entry
			for range n {
				start := r.pos
				key, _ := r.str()
				mark := len(out)
				out = append(out, r.buf[start:r.pos]...)
				walk()
				entries = append(entries, entry{key, bytes.Clone(out[mark:])})
				out = out[:mark]
			}
			// The same order as encodeCipherText's slices.Sort over the keys.
			slices.SortFunc(entries, func(a, b entry) int { return cmp.Compare(a.key, b.key) })
			for _, e := range entries {
				out = append(out, e.bytes...)
			}
		case ctPassthrough:
			out = append(out, tag)
			canonicalValue(r, &out)
		}
	}
	walk()
	return out
}

func FuzzUnmarshal(f *testing.F) {
	// Seeds: one of each node kind, plus known-hostile shapes.
	f.Add([]byte{0x00})                                    // Null
	f.Add([]byte{0x04, 7, 0, 0, 0})                        // Int32
	f.Add([]byte{0x0A, 2, 0, 0, 0, 'h', 'i'})              // String
	f.Add([]byte{0xF0, 1, 0, 0, 0, 0x03})                  // Array[true]
	f.Add([]byte{0xF1, 1, 0, 0, 0, 1, 0, 0, 0, 'a', 0x00}) // Object{a: null}
	f.Add([]byte{0xF2, 0x05})                              // Passthrough(Int64) truncated
	f.Add([]byte{0xF0, 0xFF, 0xFF, 0xFF, 0xFF})            // hostile count
	f.Add([]byte{0xF1, 2, 0, 0, 0, 1, 0, 0, 0, 'a', 0x00}) // short object
	addCorpusSeeds(f, func(raw []byte) []byte { return raw })
	// Extended scalars nested in containers and passthrough.
	addCorpusSeeds(f, func(raw []byte) []byte { return append([]byte{0xF0, 1, 0, 0, 0}, raw...) })
	addCorpusSeeds(f, func(raw []byte) []byte { return append([]byte{0xF2}, raw...) })

	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := Unmarshal(data)
		if err != nil {
			return
		}
		out, err := Marshal(v)
		if err != nil {
			t.Fatalf("accepted decode failed to re-encode: %v (value %#v)", err, v)
		}
		requireCanonical(t, data, out, canonicalForm(data))
		// The re-encoding is canonical, so it must be a fixed point.
		again, err := Unmarshal(out)
		if err != nil {
			t.Fatalf("re-encoding %x does not decode: %v", out, err)
		}
		if twice, err := Marshal(again); err != nil || !bytes.Equal(twice, out) {
			t.Fatalf("re-encoding %x is not stable: %x (%v)", out, twice, err)
		}
	})
}

func FuzzUnmarshalCipherText(f *testing.F) {
	f.Add([]byte{0x01, 1, 0, 0, 0, 0xAB})                                    // ctSingle leaf
	f.Add([]byte{0x02, 1, 0, 0, 0, 0xAB})                                    // the retired ctNone: malformed
	f.Add([]byte{0x03, 1, 0, 0, 0, 0x01, 1, 0, 0, 0, 0xAB})                  // ctSeq[leaf]
	f.Add([]byte{0x04, 1, 0, 0, 0, 1, 0, 0, 0, 'a', 0x01, 1, 0, 0, 0, 0xAB}) // ctMap{a: leaf}
	f.Add([]byte{0x06, 1, 0, 0, 0, 0xAB})                                    // ctEmptySeq
	f.Add([]byte{0x07, 1, 0, 0, 0, 0xAB})                                    // ctEmptyMap
	f.Add([]byte{0x05, 0x00})                                                // ctPassthrough(Null)
	f.Add([]byte{0x03, 0xFF, 0xFF, 0xFF, 0xFF})                              // hostile count
	// Extended scalars as clear passthrough nodes inside a ciphertext.
	addCorpusSeeds(f, func(raw []byte) []byte { return append([]byte{0x05}, raw...) })

	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := UnmarshalCipherText(VCValueLeaves(), data)
		if err != nil {
			return
		}
		out, err := MarshalCipherText(VCValueLeaves(), v)
		if err != nil {
			t.Fatalf("accepted ciphertext decode failed to re-encode: %v (value %#v)", err, v)
		}
		requireCanonical(t, data, out, cipherCanonicalForm(data))
	})
}

// The walkers decide what may legitimately change, so pin that they rewrite
// nested Undefined tags, negative-zero signs, envelope timestamps and
// ciphertext map entry order and nothing else.
func TestCanonicalWalkers(t *testing.T) {
	negativeZero := []byte{0x14, 0, 0, 2, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	zero := []byte{0x14, 0, 0, 2, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	negativeOne := []byte{0x14, 0, 0, 2, 0x80, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	millis := []byte{0xF3, 3, 1, 0x05, 0x7b, 0, 0, 0, 0, 0, 0, 0}         // 123 ms
	nanos := []byte{0x13, 0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0xd4, 0x54, 0x07} // 0 s, 123000000 ns
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	ctMapHeader := []byte{0x04, 2, 0, 0, 0}                   // ctMap of two entries
	entryA := []byte{1, 0, 0, 0, 'a', 0x01, 1, 0, 0, 0, 0xAA} // "a": sealed leaf AA
	entryB := []byte{1, 0, 0, 0, 'b', 0x01, 1, 0, 0, 0, 0xBB} // "b": sealed leaf BB
	for _, tc := range []struct {
		name string
		walk func([]byte) []byte
		data []byte
		want []byte
	}{
		{"bare", canonicalForm, []byte{0x01}, []byte{0x00}},
		{"bytes payload of 0x01", canonicalForm, []byte{0x0B, 1, 0, 0, 0, 0x01}, []byte{0x0B, 1, 0, 0, 0, 0x01}},
		{"array", canonicalForm, []byte{0xF0, 2, 0, 0, 0, 0x0B, 1, 0, 0, 0, 0x01, 0x01}, []byte{0xF0, 2, 0, 0, 0, 0x0B, 1, 0, 0, 0, 0x01, 0x00}},
		{"object", canonicalForm, []byte{0xF1, 1, 0, 0, 0, 1, 0, 0, 0, 0x01, 0x01}, []byte{0xF1, 1, 0, 0, 0, 1, 0, 0, 0, 0x01, 0x00}},
		{"passthrough", canonicalForm, []byte{0xF2, 0x01}, []byte{0xF2, 0x00}},
		{"extended scalar", canonicalForm, []byte{0xF0, 2, 0, 0, 0, 0x0D, 0x01, 0x01}, []byte{0xF0, 2, 0, 0, 0, 0x0D, 0x01, 0x00}},
		{"unknown envelope", canonicalForm, []byte{0xF3, 200, 9, 0x06, 34, 0, 0, 0}, []byte{0xF3, 200, 9, 0x06, 34, 0, 0, 0}},
		{"uuid envelope", canonicalForm, cat([]byte{0xF3, 5, 0, 0x0B, 2, 0, 0, 0, 0x01, 0x01}), cat([]byte{0xF3, 5, 0, 0x0B, 2, 0, 0, 0, 0x01, 0x01})},
		{"negative zero", canonicalForm, negativeZero, zero},
		{"negative zero in an array", canonicalForm, cat([]byte{0xF0, 1, 0, 0, 0}, negativeZero), cat([]byte{0xF0, 1, 0, 0, 0}, zero)},
		{"negative one", canonicalForm, negativeOne, negativeOne},
		{"millisecond envelope", canonicalForm, millis, nanos},
		{"millisecond envelope in an object", canonicalForm, cat([]byte{0xF1, 1, 0, 0, 0, 1, 0, 0, 0, 'k'}, millis), cat([]byte{0xF1, 1, 0, 0, 0, 1, 0, 0, 0, 'k'}, nanos)},
		{"second envelope over an i8", canonicalForm, []byte{0xF3, 3, 0, 0x0C, 10}, []byte{0x13, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"sealed leaf of 0x01", cipherCanonicalForm, []byte{0x01, 1, 0, 0, 0, 0x01}, []byte{0x01, 1, 0, 0, 0, 0x01}},
		{"ciphertext passthrough", cipherCanonicalForm, []byte{0x03, 1, 0, 0, 0, 0x05, 0xF0, 1, 0, 0, 0, 0x01}, []byte{0x03, 1, 0, 0, 0, 0x05, 0xF0, 1, 0, 0, 0, 0x00}},
		{"ciphertext passthrough negative zero", cipherCanonicalForm, cat([]byte{0x05}, negativeZero), cat([]byte{0x05}, zero)},
		{"ciphertext map in key order", cipherCanonicalForm, cat(ctMapHeader, entryA, entryB), cat(ctMapHeader, entryA, entryB)},
		{"ciphertext map out of key order", cipherCanonicalForm, cat(ctMapHeader, entryB, entryA), cat(ctMapHeader, entryA, entryB)},
		{"ciphertext map nested in a sequence", cipherCanonicalForm, cat([]byte{0x03, 1, 0, 0, 0}, ctMapHeader, entryB, entryA), cat([]byte{0x03, 1, 0, 0, 0}, ctMapHeader, entryA, entryB)},
		{"ciphertext map entries keep their own children", cipherCanonicalForm, cat(ctMapHeader, entryB, cat([]byte{1, 0, 0, 0, 'a', 0x05}, negativeZero)), cat(ctMapHeader, cat([]byte{1, 0, 0, 0, 'a', 0x05}, zero), entryB)},
	} {
		if got := tc.walk(tc.data); !bytes.Equal(got, tc.want) {
			t.Errorf("%s: got %x, want %x", tc.name, got, tc.want)
		}
	}
}
