# Value conformance corpus

`value-conformance.json` holds the shared vectors that Rust, Node, the Go
codec and the Go WASM encryption guest all check. Payload bytes are frozen by
`vitaminc-aead`'s scalar tag table and leaf codec (ADR 0001 section 3):
fixed-width integers and float bits are little-endian, dates count days from
CE, timestamps carry seconds plus nanoseconds, decimals retain their flags and
96-bit coefficient, and a logical type with no tag of its own travels in the
`0xF3` envelope (id, one-byte parameter, physical scalar).

## Sections

| Section                | Rust | Node | Go  | What it pins                                                        |
| ---------------------- | ---- | ---- | --- | ------------------------------------------------------------------- |
| `vectors`              | yes  | yes  | yes | A valid value: decodes to the host value, encodes back to the bytes |
| `normalized`           | yes  | yes  | yes | A valid value that reads back as a different canonical value        |
| `malformed`            | yes  | yes  | yes | Bytes every decoder must refuse                                     |
| `ciphertext_malformed` | yes  | no   | yes | Ciphertext transport bytes the codec must refuse                    |
| `leaf_type_aad`        | yes  | no   | no  | The `LeafTypeAad` context bytes for a (base, kind, logical) triple  |

Node has no ciphertext transport codec, and neither binding exposes
`LeafTypeAad`, so those two sections are asserted where the code is. A new
section is consumed by every language that has the code it describes; the
table above is the record of who asserts what, so keep it current.

## Fields

Every row has a `name`. A row that follows an ADR 0001 rule states it in a
`rule` field, so a failing vector says which rule it pins.

`vectors`: `kind`, `value` and the hexadecimal `transport` bytes. Integer and
decimal values are strings to avoid JSON number rounding. Bytes are
hexadecimal. A timestamp row may carry a `unit` (`seconds`, `millis`,
`micros`; nanoseconds is the shorthand tag); `js_date` selects a native
JavaScript Date, and other timestamps keep their nanoseconds in a wrapper,
spelled RFC 3339 for years 0000-9999 and with an ISO 8601 expanded year
(`+12000-…`) otherwise. An `unknown` kind carries `{id, param, kind, value}`
for the envelope's physical scalar.

`normalized`: as `vectors`, plus `reencode` (the canonical bytes every
language writes back) and `reencode_value` (the host value it reads as).

`ciphertext_malformed`: `transport` bytes of a ciphertext tree.

`leaf_type_aad`: `base`, `kind` (the physical kind), an optional `logical`
`{id, param}`, and the `context` bytes; its `rule` spells out the encoding so
another language can build the bytes from the corpus alone.

## Host projections

Rust re-encodes every valid vector byte for byte. A host language whose
value model cannot hold a vector as it is says so in an explicit field rather
than skipping the row:

- `js_reencode`: JavaScript Float32 becomes a Number and re-encodes as
  Float64.
- `go_reencode`: Go has two projections. `undefined` becomes nil and
  re-encodes as null. A timestamp in the envelope (seconds, milliseconds or
  microseconds) is read as a `time.Time` and re-encodes in the nanosecond
  shorthand, which is safe because `LeafTypeAad` binds the kind and the
  logical id but not the unit, and the equality terms put every unit in one
  timestamp domain.
- `js: "refused"`: Node has no value for this row and refuses it. Today that
  is the `unknown-logical` envelope, a Node limitation tracked in #446, not a
  rule of the format; Rust and Go read and re-encode it unchanged.

New vectors state any additional projection the same way.

## How each language checks a vector

Rust, Go and Node each build the expected host value from `kind` and `value`
without their transport decoder, then check both directions: decoding the
bytes gives that value, and encoding that value gives the bytes. A bug that
decodes and encodes symmetrically wrong therefore still fails. Adding a kind
means teaching each language's `expected` helper to build it. The Go fuzz
targets seed themselves from `vectors`, `malformed`, `normalized` and
`ciphertext_malformed`, so every row is also a starting point for the
differential run against the guest.

These are the scalar/value-level vectors needed by #375 and #414. The wider
#332 cross-language ciphertext, guest-object and SDK corpus remains separate
work.
