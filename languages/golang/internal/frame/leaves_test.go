package frame

// The leaf types and the LeafSet of these tests. The codec has no leaf types
// of its own, so each caller supplies a LeafSet. The LeafSet of the SDK is
// in package encrypt. The three types here take the place of a caller's
// types, with one type for each LeafKind.
type (
	sealed         []byte
	sealedEmptySeq []byte
	sealedEmptyMap []byte
)

func testLeaves() LeafSet {
	return LeafSet{
		Classify: func(v any) (LeafKind, []byte, bool) {
			switch n := v.(type) {
			case sealed:
				return LeafSingle, n, true
			case sealedEmptySeq:
				return LeafEmptySeq, n, true
			case sealedEmptyMap:
				return LeafEmptyMap, n, true
			default:
				return 0, nil, false
			}
		},
		Make: func(kind LeafKind, bytes []byte) any {
			switch kind {
			case LeafSingle:
				return sealed(bytes)
			case LeafEmptySeq:
				return sealedEmptySeq(bytes)
			case LeafEmptyMap:
				return sealedEmptyMap(bytes)
			default:
				// A kind that is not listed is refused with nil, as leafTag
				// refuses one when it encodes.
				return nil
			}
		},
	}
}

// testEncryptable is the Encryptable interface that these tests publish, as
// package encrypt publishes its own. The codec declares none.
type testEncryptable interface {
	EncryptValue(enc Encoder) error
}

func init() {
	PublishEncryptable(func(v testEncryptable, enc Encoder) error { return v.EncryptValue(enc) })
}
