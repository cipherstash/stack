# Storage profile, version 1

A blob is one value as bytes that are kept: written once, read back by
later releases, possibly in another language. It reuses the transport
frame's container layout and the sealed leaf's scalar table, and adds
three things the transport does not have: a header naming the profile and
its version, a marker for a present optional value, and a promise that the
bytes keep their meaning.

The words MUST, MUST NOT and MAY are used as in RFC 2119.

## Stability boundary

Stable, and covered by this specification:

- the bytes of a blob, as laid out below;
- `storage::to_vec` and `storage::from_slice`, which write and read them;
- `storage::HEADER`, `storage::MAGIC`, `storage::VERSION` and
  `storage::SOME`.

Not stable, and not covered: everything else in `vitaminc-aead-frame`.
The transport frame (`Frame`, `FrameWriter`, `to_frame`), the transport
serde format (`serde::to_vec`, `serde::from_slice`, `serde::from_frame`)
and the ciphertext codec are for a host and a guest that ship together,
and MAY change in any release. A transport frame is not a blob, and a blob
is not a transport frame: neither reads as the other.

Error messages are not part of the format. They are fixed text, and never
contain a value or a key from the blob.

## Layout

All lengths and counts are unsigned 32-bit little-endian integers.

```text
blob    = header node
header  = 0x56 0x43 0x53 version      ; "VCS", then the version
version = 0x01

node    = scalar / array / object / some
array   = 0xF0 count node{count}
object  = 0xF1 count entry{count}
entry   = length utf8{length} node     ; the key, then its value
some    = 0xF5 node
```

A scalar is one tag byte and its payload:

| Tag    | Scalar | Payload                                      |
| ------ | ------ | -------------------------------------------- |
| `0x00` | null   | none                                         |
| `0x02` | false  | none                                         |
| `0x03` | true   | none                                         |
| `0x0C` | i8     | 1 byte, two's complement                     |
| `0x0E` | i16    | 2 bytes, two's complement, little-endian     |
| `0x04` | i32    | 4 bytes, two's complement, little-endian     |
| `0x05` | i64    | 8 bytes, two's complement, little-endian     |
| `0x10` | i128   | 16 bytes, two's complement, little-endian    |
| `0x0D` | u8     | 1 byte                                       |
| `0x0F` | u16    | 2 bytes, little-endian                       |
| `0x06` | u32    | 4 bytes, little-endian                       |
| `0x07` | u64    | 8 bytes, little-endian                       |
| `0x11` | u128   | 16 bytes, little-endian                      |
| `0x08` | f32    | 4 bytes, IEEE 754 binary32 bits, little-endian |
| `0x09` | f64    | 8 bytes, IEEE 754 binary64 bits, little-endian |
| `0x0A` | text   | `length`, then that many bytes of UTF-8      |
| `0x0B` | bytes  | `length`, then that many bytes               |

These are the sealed leaf's frozen tags and payloads (`vitaminc_aead::tags`)
in the frame's form, where text and bytes carry a length. No other byte
starts a node. In particular the tags the frame and the sealed leaf know
but this profile does not are refused: `0x01` (JavaScript `undefined`),
`0x12` to `0x15` (date, timestamp, decimal, typed null), `0xF2`
(passthrough), `0xF3` and `0xF4` (logical-type envelopes). Floats are
their raw bits, so a NaN's payload and the sign of zero are kept.

### Depth

The root node is at depth 0. An element of an array, the value of an
object's entry, and the node after `some` are one level deeper than the
node that holds them. A node deeper than 128 is refused.

## Reading

A reader MUST refuse a blob, and produce no value, if:

1. it is shorter than four bytes, or does not start with `"VCS"`: it is not
   a blob;
2. its version is one the reader does not read: this is reported apart from
   every other refusal, so a caller can tell a reader that needs upgrading
   from a corrupt blob;
3. the body after the header is not exactly one node: it is truncated, or
   bytes follow the node;
4. a node starts with a byte that is not in the grammar above;
5. a length or count runs past the end of the blob;
6. a key or a text scalar is not valid UTF-8;
7. one object has two entries whose keys are the same bytes;
8. a node is deeper than 128.

`from_slice` checks the whole blob against these rules before any value is
built.

A writer MUST NOT write a blob that a reader of its version refuses.
`to_vec` refuses a value that would break a rule above (one nested too
deep, a repeated key, text or bytes longer than a `u32` length), and
checks what it wrote as a reader would before returning it.

## The serde mapping

| serde                                | node                                                        |
| ------------------------------------ | ----------------------------------------------------------- |
| bool                                 | false, true                                                 |
| `i8` … `i128`, `u8` … `u128`         | the integer scalar of that exact width                      |
| `f32`, `f64`                         | the float scalar of that width                              |
| `char`, `str`                        | text                                                        |
| bytes (`serialize_bytes`)            | bytes                                                       |
| `None`                               | null                                                        |
| `Some(x)`                            | `some`, then `x`                                            |
| unit, unit struct                    | null                                                        |
| newtype struct                       | its value                                                   |
| sequence, tuple, tuple struct        | array                                                       |
| map                                  | object, entries in the order the map gives them             |
| struct                               | object, fields in the order the type writes them            |
| unit variant                         | text: the variant's name                                    |
| newtype variant                      | object of one entry: the name, then the value               |
| tuple variant                        | object of one entry: the name, then an array                |
| struct variant                       | object of one entry: the name, then an object               |

A field skipped with `skip_serializing_if` is not written. A `Vec<u8>` is a
sequence of `u8` in serde, so it is an array; `serde_bytes` makes it bytes.

`Some` is marked, so an option never reads back as another: `None` is `00`
and `Some(())` is `F5 00`, and in an `Option<Option<()>>`, `Some(None)` is
`F5 00` and `Some(Some(()))` is `F5 F5 00`. The marker is a node of its own, so a type read
through serde's buffering (`#[serde(untagged)]`, `#[serde(tag = "…")]`,
`#[serde(flatten)]`) still sees `Some`.

### Map keys

A key is text. A map key MUST serialize as a string, a `char`, a unit
variant (its name) or a newtype struct around one of those; any other key
is refused when written. When read, a key is handed to the key type as a
string, so a key type that reads only an integer (`HashMap<u32, _>`) is
refused. Integer keys are not part of version 1.

### Reading by type

Reading is directed by the type, and accepts these forms beside the ones
`to_vec` writes. Each reads as the value it would have been written from;
writing that value back gives the form in the table above.

- An integer reads as any integer type it fits; a type that reads through
  `deserialize_any` sees it at its written width.
- An `Option` reads null as `None`, `some` as `Some`, and any other node as
  `Some` holding that node, so a blob written before a field became
  optional reads. A type whose own value is written as null (unit, a unit
  struct, an `Option`) reads its old null as `None` instead.
- An enum reads a variant's name as a unit variant, or as a newtype variant
  whose value is read from null; and an object of one entry whose value is
  null as a unit variant.
- A struct or map reads only an object, a string only text, and bytes only
  bytes. Unknown keys of a struct are ignored unless it denies them, as in
  every serde format.

### Not supported

- 128-bit integers in a type serde buffers (untagged, internally tagged,
  flatten): serde's buffer has no 128-bit integers.
- A type that serializes differently when the format is human readable gets
  its compact form here (`is_human_readable` is `false`): a `uuid::Uuid` is
  16 bytes. Changing that impl, in a dependency say, changes what is
  written for the type, as any change to a `Serialize` impl does.

## Determinism

`to_vec` is a function of the calls a `Serialize` impl makes: the same calls
give the same bytes, in every release that writes version 1. A struct, a
sequence, a `BTreeMap` and every scalar are therefore written the same way
each time. A `HashMap` or `HashSet` is not, since its order is not fixed,
nor is a hand-written `Serialize` that varies.

There is no canonical form beyond that. Equal values of different types
write different bytes (`1u8` and `1u32`), NaN payloads are kept, and a
reader accepts the extra forms listed above. Compare values, not blobs,
unless the type is one whose bytes are fixed.

## Versions

The version names both the byte grammar and the serde mapping. Version 1
is frozen: no release changes what a version 1 blob reads as, or makes a
version 1 reader refuse a blob a version 1 writer could have written.

A change to either is a new version, introduced in two steps:

1. A release reads the new version and the old, and still writes the old.
2. A later release writes the new version, once every reader that will see
   its blobs reads it.

A reader keeps reading every version it ever read. Version numbers are never
reused.

The golden corpus in `testdata/storage-v1.json` pins version 1. Its rows
are never edited or removed, and CI checks that; rows MAY be added.

## The format's version and the application's schema

The version covers how a value becomes bytes. It does not cover the type
the value has. Changing that type is the application's schema evolution,
and serde's attributes govern it:

| Change to the type                              | An old blob                                      |
| ----------------------------------------------- | ------------------------------------------------ |
| Add a field with `#[serde(default)]`            | reads, with the default                          |
| Add a field without a default                   | is refused: missing field                        |
| Remove a field                                  | reads, unless the type denies unknown fields     |
| Rename a field                                  | reads with `#[serde(alias = "…")]`               |
| `T` to `Option<T>`                              | reads as `Some`, unless `T` is written as null   |
| `Option<T>` to `T`                              | is refused if it held `Some` or `None`           |
| Add an enum variant                             | reads; an older reader refuses the new variant   |
| Widen an integer                                | reads; narrowing reads only values that fit      |

An application that needs to tell its own schema versions apart carries
that in the value, as an enum of versions say. The blob header is not for
that, and never changes because the type did.

## The blob inside an outer envelope

A blob is plaintext. The caller seals it whole, under an envelope of its
own (Stack Encrypt's ciphertext), so the header is authenticated with the
value. The envelope and the blob are two formats with two versions: a new
envelope version does not change a blob's bytes, and a new blob version
does not change the envelope. A caller that wants to refuse an unexpected
blob version before it decrypts binds `HEADER` into its envelope's
associated data, and checks it there.

## Memory and timing

The writer grows its buffer into a fresh allocation and wipes the old one,
and wipes everything if writing fails. The reader borrows text and bytes
from the blob rather than copying them. None of it is constant time, and
serde's own impls are not. A `T: Zeroize` does not wipe fields it read
before a later field failed. Improvements to any of this MUST keep the
bytes, which the corpus checks.
