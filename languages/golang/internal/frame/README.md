# vcffi — the shared FFI transport codec

`vcffi` is the wire encoding that carries a **value tree** into a wasm guest
and a **ciphertext tree** back out, plus the `Encryptable`/`Encoder`
extension point for types that control their own encoding. It exists as its
own module so every binding that owns a wasm boundary speaks the same bytes
from one implementation — one codec, one hostile-input test suite, one fuzz
corpus. Consumers: [`vcencrypt`](../vcencrypt) (the `vitaminc-encrypt`
reference binding) and the stack-encrypt Go SDK.

```
import "github.com/cipherstash/vitaminc/bindings/go/vcffi"
```

Depends only on the sibling [`vcvalue`](../vcvalue) module (the value model —
`Plain`, `Object`, the sealed leaf family), via a local `replace` directive.
No wazero, no crypto.

## Transport, and one storage profile

The transport bytes are an FFI detail with **no compatibility commitment**:
nothing `Marshal`, `Encode` or `MarshalCipherText` writes should ever be
persisted. The one exception is the **storage profile**, `MarshalStorage` and
`UnmarshalStorage`, which write and read a value as a versioned blob for bytes
that are kept. Its format is shared with the Rust module
`vitaminc_aead_frame::storage`, specified in
[`packages/aead-frame/STORAGE.md`](../../../packages/aead-frame/STORAGE.md),
frozen at version 1, and pinned by the golden corpus
[`storage-v1.json`](../../../packages/aead-frame/testdata/storage-v1.json),
which `storage_test.go` reads row by row. The other frozen format is the
sealed leaf inside the AEAD envelope (see `vcvalue.Sealed` and the Rust crate
`vitaminc-aead`'s leaf codec).

```go
blob, err := vcffi.MarshalStorage(record)     // "VCS", version 1, then the value
var back Record
err = vcffi.UnmarshalStorage(blob, &back)     // errors.Is(err, vcffi.ErrUnsupportedVersion) …
```

A Go struct is an object (field names from `vc` tags, as in the transport), a
map is a map whose keys keep their kind, `[]byte` and `[N]byte` are bytes, and
an `encoding.TextMarshaler` such as `time.Time` is text. A pointer is written
as `encoding/json` writes it: nil is null, and anything else is its value, so
Rust reads it into an `Option<T>` or a plain `T` alike. Only a pointer to a
value that is itself written as null or marked present (a nil pointer, or a
pointer to one) is marked present, so every level reads back. Reading
follows Rust's rules: an integer reads into any integer type it fits, a
pointer reads a value marked present or not, unknown keys are ignored, and a
missing field is refused unless it is a pointer or tagged `vc:"name,default"`,
which reads it as its zero value, as Rust's `#[serde(default)]` does.
`default` is the only tag option: any other is refused, in a blob and in the
transport, so a misspelt one is not quietly ignored. A pointer costs no depth
unless it is marked, so Go nests as deep as the blob does. Go's `[]uint8` is `[]byte`, so it is always
bytes; a Rust type sharing a value with Go keeps its `Vec<u8>` as bytes with
`serde_bytes`. Go has no enums and no unit type, so the corpus rows that read
those are not run here. `FuzzUnmarshalStorage` holds the reader to the
hostile-input contract below, and requires every blob it reads to write back
byte for byte.

## The `LeafSet` parameter

The ciphertext codec's structural nodes (`[]any`, `map[string]any`,
`vcvalue.Plain`) are common to every binding, but the sealed-leaf marker
types are deliberately **not**: each binding hands the codec a `LeafSet`
mapping its own leaf types onto the framing. A stack-encrypt leaf is not
decryptable by `vitaminc-encrypt`, and keeping the Go types distinct means
one can never scan or marshal where the other belongs. `VCValueLeaves` is
the set for the `vcvalue` model types.

The seam stops at the leaves. The structural nodes — including
`vcvalue.Plain` and the `vcvalue.Object` decode shape — are shared and **not**
parameterised: a binding brings its own leaves, not its own model. That is
deliberate. `Plain` is cleartext with no key binding, so none of the "a leaf
sealed by one cipher must never be mistaken for another's" reasoning applies
to it, and a second model would fork the wire encoding this module exists to
keep single.

## Hostile input

`Unmarshal` and `UnmarshalCipherText` treat their input as untrusted:
recursion depth, length prefixes and item counts are bounded, strings are
UTF-8 validated, duplicate map keys are rejected, and every malformed input
fails with `ErrMalformed` rather than panicking or over-allocating. The fuzz
targets in this package pin that contract, and also require anything accepted
to re-encode to the same bytes (Undefined becoming Null is the one allowed
difference). PR CI runs them over their seeds, which include every shared
corpus vector, and the whole suite on 32-bit GOARCH, where the u32-bound
guards are load-bearing. `.github/workflows/fuzz.yml` fuzzes them nightly
and records a failure on an open issue labelled `fuzz`; commit the failing
input attached to that run under `testdata/fuzz` as a regression seed.
vcencrypt's differential fuzz targets check the same decoders against the
Rust ones in its wasm guest (see its README).

`ErrMalformed` covers hostile bytes, not caller mistakes: a `LeafSet` that is
partially wired, or that does not materialize a kind the buffer carries,
fails with its own attributable error. So `errors.Is(err, ErrMalformed)` is a
test for bad input, not a total branch over decode failures. Encode-side
depth exhaustion has its own sentinel, `ErrTooDeep`.

## Usage

### Value tree in, ciphertext tree out

`Marshal` encodes a Go value into the bytes a wasm guest expects;
`UnmarshalCipherText` decodes what comes back, materializing sealed leaves
through the caller's `LeafSet`.

```go
type User struct {
	Email string `vc:"email"`
	Age   int    `vc:"age"`
	Notes string `vc:"-"` // never leaves the process
}

buf, err := vcffi.Marshal(User{Email: "a@example.com", Age: 42})
if err != nil {
	return err
}

// ... hand buf to the guest, get ciphertext bytes back ...

ct, err := vcffi.UnmarshalCipherText(vcffi.VCValueLeaves(), ctBytes)
if err != nil {
	return err // errors.Is(err, vcffi.ErrMalformed) for hostile input
}
sealed := ct.(map[string]any)["email"].(vcvalue.Sealed)
```

The reverse pair is `MarshalCipherText` (ciphertext tree to bytes, for the
decrypt call) and `Unmarshal` (guest response to a plaintext tree).

### A type that controls its own encoding

Implement `Encryptable` when reflection is not the encoding you want. The
`Encoder` writes exactly one value: one terminal channel, or one container
closed with `End`.

```go
type Money struct {
	Cents    int64
	Currency string
}

func (m Money) EncryptValue(enc vcffi.Encoder) error {
	mp := enc.Map()
	mp.Field("cents").Int64(m.Cents)
	// Currency is not a secret — mark it so it travels in the clear.
	mp.Field("currency").Passthrough().String(m.Currency)
	return mp.End()
}
```

Errors accumulate on the encoder, so writes chain without a check after each
one; `End` (or `Marshal`) surfaces the first failure. A zero-value
`vcffi.Encoder` is unusable — usable ones only ever arrive as the argument to
`EncryptValue` or from `Passthrough`, `Elem` and `Field`.

### A binding's own leaf types

A second binding defines its own sealed-leaf types and maps them onto the
framing, so its leaves can never be mistaken for another cipher's.

```go
type stackSealed []byte

var stackLeaves = vcffi.LeafSet{
	Classify: func(v any) (vcffi.LeafKind, []byte, bool) {
		if s, ok := v.(stackSealed); ok {
			return vcffi.LeafSingle, s, true
		}
		return 0, nil, false // not ours — the codec handles the rest
	},
	Make: func(kind vcffi.LeafKind, b []byte) any {
		if kind == vcffi.LeafSingle {
			return stackSealed(b)
		}
		return nil // an unwired kind is an error, never a nil node
	},
}
```

`Classify` is offered only non-structural values, so it cannot claim `[]any`,
`map[string]any` or `vcvalue.Plain`. A real binding covers all four kinds
(`LeafSingle`, `LeafEmptySeq`, `LeafEmptyMap`); returning nil for
a kind the wire carries fails the decode attributably rather than injecting an
untyped nil.

## Scalar mappings and shared vectors

Fixed integer widths remain exact (`int8`→Int8, `uint16`→UInt16, and so on).
`vcvalue.Int128`, `Uint128`, `Date`, `Decimal`, `UUID` and `Tagged` are
intercepted before reflection, including inside structs, pointers and
containers. `time.Time` encodes a nanosecond Timestamp; a timestamp that
arrives in the `0xF3` envelope in seconds, milliseconds or microseconds
decodes to `time.Time` too, and so re-encodes in the nanosecond form. A leap
second is refused in both directions, and a decimal negative zero reads back
as zero (ADR 0001). `UUID` and `Tagged` travel in the `0xF3` envelope.
Another UUID type, such as `github.com/google/uuid.UUID`, is a plain
`[16]byte` and is written as bytes: convert it with `vcvalue.UUID(id)` first
so that Rust and Node read it as a UUID.
Matching explicit Encoder channels are available for custom `Encryptable`
implementations.

### Absent values

AES-GCM keeps the plaintext's length, so a one-byte null sealed in place of a
date would show which rows have no date. A nil pointer to a fixed-width type
(`*int32`, `*float64`, `*time.Time`, `*vcvalue.Date`, `*vcvalue.Decimal`,
`*vcvalue.UUID`, and so on, and a named int or float type such as
`type Age int32`) is therefore
written as a **typed null**, padded to the length of a value of that type, as
Rust writes an `Option<T>`'s `None` (vitaminc#493):

```go
type Person struct {
	Name string
	Born *vcvalue.Date // nil seals as long as a date
}
```

A nil with no fixed-width type to go by is the plain null: a nil interface, a
nil `*bool` (a bool is already as short as a null), a nil `*string` or
`*[]byte` (variable width), a nil pointer to an `Encryptable`, whose
encoding is its own, and a named type over a `vcvalue` or `time` type (`type
Birthday vcvalue.Date`), which reflection writes field by field, not as a
date. Where the Go type cannot say what is missing (a nil in a
`map[string]any`), write `vcvalue.TypedNull{Type: vcvalue.TypeDate}`, or call
`Encoder.TypedNull` from an `Encryptable`.

An `Encryptable` whose `EncryptValue` always writes one value of one
fixed-width type can say so by implementing `FixedWidth`, the Go side of
Rust's `Encrypt::FIXED`. A nil pointer to it is then a typed null of that
type:

```go
type Money struct{ cents int64 }

func (m Money) EncryptValue(enc vcffi.Encoder) error { enc.Int64(m.cents); return nil }
func (Money) FixedType() vcvalue.FixedType            { return vcvalue.TypeInt64 }

type Order struct {
	Refund *Money // nil seals as long as a Money
}
```

`FixedType` is called once per type, on a pointer to a zero value, so it must
answer from the type alone. A type that returns an invalid `FixedType` fails
the encode with `vcvalue.ErrInvalidFixedType` rather than write the plain
null in its place.

A typed null decodes as `nil`, like every null. Out of the seal the padding
means nothing, and Rust's frame writer writes it back as the plain null, so
Go does too. A decrypted value therefore no longer says what type an absent
field was: hold optional fields in a typed struct (`Born *vcvalue.Date`)
before encrypting again. A value re-encrypted from `any` or `vcvalue.Object`
seals its nils as the plain null, and its absent values show by length.

Reading a typed null takes a guest built from the vitaminc release that adds
it (vitaminc#493); an older one refuses the frame. A binding that ships its
own guest must update it together with this module.

The codec reads `testdata/value-conformance.json` from the repo root directly,
as do Rust and Node. Invalid scalar widths, date ranges, nanoseconds, decimal
flags and scales return `ErrMalformed`. Value construction errors retain the
typed `vcvalue` errors. The broader #332 guest-object corpus remains separate.
