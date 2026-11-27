package frame

// The leaf types and leaf set of these tests. The codec has no leaf types of
// its own: each caller brings a LeafSet, and the SDK's is in package
// encrypt. These three stand for a caller's, one type for each LeafKind.
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
				// An unlisted kind is rejected (nil), as leafTag refuses
				// one on the encode side.
				return nil
			}
		},
	}
}

// testEncryptable is the Encryptable these tests publish, as package encrypt
// publishes its own: the codec has none of its own.
type testEncryptable interface {
	EncryptValue(enc Encoder) error
}

func init() {
	PublishEncryptable(func(v testEncryptable, enc Encoder) error { return v.EncryptValue(enc) })
}
