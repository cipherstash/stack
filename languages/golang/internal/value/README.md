# vcvalue — the durable value layer

`vcvalue` is the Go materialization of vitaminc's **frozen data model**: the
value types application code holds and stores — `Plain`, the sealed leaf
family, and the ordered `Object` decode shape.

It has **zero dependencies** — no wazero, no crypto, and (deliberately) no
wire format. It is the module a future stack-encrypt Go SDK is expected to
import. Keeping it dependency-free is the point: the wasm reference harness
(`vcencrypt`, next door) is just *one* consumer, and neither its
wazero/crypto dependencies nor its FFI wire encoding may leak into the layer
real applications depend on.

```
import "github.com/cipherstash/vitaminc/bindings/go/vcvalue"
```

## The model, not this package

The cross-language contract is the frozen sealed-leaf tag table
(`[tag] ++ payload`, sealed **inside** the AEAD envelope, defined in the Rust
crate `vitaminc-aead`'s leaf codec) — not any language's types. This package's types
*implement* that model; they are not the contract. A new tag is added only
when a value class cannot be represented in the existing model, and needs a
defined decode mapping in every supported language before it ships.

The transport codec — the wire encoding that hands a tree across an FFI
boundary in one copy — is **not part of this module**. It lives in the
sibling module `vcffi`, shared by the bindings that own such a boundary
(`vcencrypt` for the wasm harness, the stack-encrypt Go SDK), because it is
transport-only and carries no storage commitment: the only bytes an
application should ever persist are the sealed leaves. The
`Encryptable`/`Encoder` encoding extension point lives with the codec in
`vcffi` for the same reason.

## Passthrough — fields in the clear

Some fields are not secret and should travel unencrypted alongside the sealed
ones. The model carries them as **passthrough**: unencrypted *and*
unauthenticated, non-sensitive fields only. Passthrough never happens
implicitly — you opt in by wrapping the value in `Plain`:

```go
value := map[string]any{
    "id":    vcvalue.Plain{V: int64(42)}, // in the clear
    "email": "ada@example.com",           // sealed
}
```

On decode a passthrough field surfaces back as `Plain{V: <decoded value>}`, so
the marking round-trips and a caller can tell which fields were in the clear.
A passthrough field inside a *ciphertext* is likewise a `Plain` — legible with
no key.

## Ciphertexts are ordinary Go values

There is no ciphertext tree type and no conversion step. A ciphertext has the
same dynamic shape as decoded plaintext, with marker types naming what is
sealed:

| value             | meaning                                                              |
| ----------------- | -------------------------------------------------------------------- |
| `Sealed`          | one encrypted leaf: `version(1) \|\| nonce \|\| ciphertext \|\| tag` |
| `SealedEmptySeq`  | the authenticated marker for an empty sequence                       |
| `SealedEmptyMap`  | the authenticated marker for an empty map                            |
| `Plain{V: ...}`   | a passthrough field, readable without the key                        |
| `map[string]any`  | a record of named nodes (clear keys, bound into AAD)                 |
| `[]any`           | a sequence of nodes                                                  |

Every leaf-shaped type starts with a one-byte wire version, which is also
authenticated into the leaf's AAD — a relabeled version byte fails the tag,
not just the parse. All four leaf types share that byte layout: the *kind* of
a leaf is authenticated through domain-separated AAD, not written into the
bytes, so a stored leaf's kind must be tracked by the schema (see the note on
the marker types' `Scan`).

The `Sealed` family here is **vitaminc-encrypt's** materialization of the
model. Another binding — a stack-encrypt SDK, say — defines its own distinct
sealed-leaf types and wires them to the codec via `vcffi.LeafSet`, so its
leaves can never scan or marshal where these belong: a stack-encrypt leaf is
never a `vcvalue.Sealed`.

The sealed leaf types and `Plain` implement `driver.Valuer`, and the sealed
types `sql.Scanner`, so a record-shaped ciphertext binds straight into a
database as named parameters and sealed columns scan straight back out — no
adapter layer. Because a record is a plain map, any subset of its fields can
be handed back for decryption: there is no whole-map seal, and each key is
bound into its own value's AAD.

## Decoding

Decryption (in `vcencrypt`) returns Go natives at the exact numeric widths
(`nil`, `bool`, `int8`, `int16`, `int32`, `int64`, `uint8`, `uint16`, `uint32`, `uint64`, `float32`, `float64`,
`string`, `[]byte`, `[]any`), this package's ordered `Object` for maps, and
`Plain` for passthrough. A reflection-based decode into caller structs (the
mirror of the reflection encode) is future work.


## Extended scalars

`Int128` and `Uint128` are 16-byte little-endian values, with exact decimal
`ParseInt128` / `ParseUint128` constructors and `String` methods. Out-of-range
inputs return `ErrIntegerRange`.

`Date{Year, Month, Day}` is a Gregorian calendar date in the wire's range,
years -9999 through 9999. `time.Time` maps to Timestamp with nanoseconds and
decodes in UTC, without its location or monotonic reading, from
-009999-01-02T01:59:59Z through 9999-12-30T22:00:00.999999999Z. These ranges
are jiff's, in every binding, so a value one binding seals, every binding
opens. `time.Time` itself reaches far wider, and a value outside the range is
refused.
`Timestamp{Seconds, Nanoseconds}` encodes an instant from its parts. A leap
second has no count since the epoch and is refused everywhere in the model
(ADR 0001). Invalid calendar/timestamp inputs return `ErrInvalidDate` or
`ErrInvalidTimestamp`.

`UUID` is sixteen bytes under the Uuid logical type, spelled as hyphenated
hexadecimal by `ParseUUID` and `String`. `Tagged{ID, Param, V}` carries a
physical scalar under a logical id this build does not know, so a value
from a newer client is read and re-encoded unchanged rather than dropped.

`ParseDecimal("1.50")` constructs a finite 96-bit coefficient with scale 0–28,
retaining trailing zeroes. A zero has no sign: `-0.00` is `0.00` with its
scale kept (ADR 0001). Exponents and rounding are not
accepted. NaN and infinities return `ErrNonFiniteDecimal`; malformed or
out-of-range text returns `ErrInvalidDecimal`. Match these with `errors.Is`.
