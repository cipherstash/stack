# Storage profile, version 1

A blob is one value as bytes that are kept: written once, read back by
later releases, possibly in another language. It reuses the transport
frame's container layout and the sealed leaf's scalar table, and adds four
things the transport does not have: a header naming the profile and its
version, a marker for a present optional value, a map whose keys keep
their kind, and a promise that the bytes keep their meaning.

The words MUST, MUST NOT and MAY are used as in RFC 2119.

## Why this format

A blob is the plaintext of a ciphertext that is kept. That asks more of a
format than a compact encoding, and the profile is built for it:

- **The plaintext is handled as a secret.** `to_vec` returns the blob
  `Protected`. It grows its buffer into a fresh allocation and wipes the
  old one, writes a `Display` value straight into the blob, keeps no copy
  of a key, and wipes what it wrote if writing fails. The reader borrows
  text and bytes from the blob rather than copying them. See
  [Memory and timing](#memory-and-timing).
- **A refusal never repeats the plaintext.** Error messages are fixed text.
  serde's own messages quote the value they did not expect
  (`invalid type: string "…"`); the profile replaces them with the value's
  kind, so a refusal that is logged after decryption shows nothing of the
  value.
- **The whole blob is checked before any value is built.** Every length is
  checked against the end of the blob, so a forged length cannot cause a
  large allocation. Nesting stops at 128 levels, text must be UTF-8, and a
  repeated key is refused. A type's `Deserialize` impl never sees a blob
  that breaks these rules, so it never builds part of a value from one.
- **Every reader reads the same value.** The envelope's authentication
  shows who sealed a blob, not that every reader agrees on what it says.
  Readers that differ on a repeated key, or that accept several spellings
  of one value, can read one authenticated blob as two different values.
  Here a repeated key is refused, and each tag has one payload layout:
  there are no variable-length integers and no choice of length width. The
  corpus pins the bytes and the refusals that every implementation (this
  crate, and `vcffi` in Go) must match.
- **A value reads back as it was written.** `None`, `Some(None)` and
  `Some(())` are three different blobs. An integer keeps its width, a
  float keeps its bits, and a map key keeps its kind.
- **The version is sealed with the value.** The header names the profile
  and its version, and a reader reports a version it does not read apart
  from a corrupt blob. The header is part of the plaintext, so it is
  encrypted and authenticated with the value.
- **It is self-describing, so the application's types can change.** Each
  node says what kind it is, and objects carry field names. A blob still
  reads after a field is added with a default, removed, renamed with an
  alias, or made optional. A reader without the Rust type, such as one in
  another language or a migration, can still walk it.
- **There is little new code to trust.** The scalar tags are the sealed
  leaf's (`vitaminc_aead::tags`), and the containers are the transport
  frame's, which this workspace already implements in Rust and Go. The
  profile adds no dependency.

It does not give canonical bytes, or constant-time code: see
[Determinism](#determinism) and [Memory and timing](#memory-and-timing).

### Why not MessagePack or Borsh

Both are mature, compact binary formats, with implementations in Rust and
Go. Neither has the properties above without a layer of rules on top, and
that layer would be a format of its own, built on a dependency whose serde
mapping this crate does not control.

**MessagePack** is self-describing and compact, but:

- It has no header or version.
- It has one `nil`, so options collapse as they do in JSON: with
  `rmp-serde`, `Some(None)` reads back as `None`.
- Its specification covers scalars, arrays and maps only. How a struct, an
  enum or an option is written is up to each library. `rmp-serde`'s
  `to_vec` writes a struct as an array of its values, while Go's common
  libraries write a map of field names. A Rust reader and a Go reader agree
  only when both are set up to, and nothing pins that agreement.
- The specification does not say what a repeated map key means. It lets an
  integer be written at any width that holds it, and only recommends the
  smallest. Readers can disagree about a repeated key, and they accept
  several spellings of one value.
- `rmp-serde` writes into a plain `Vec`, which leaves copies of the
  plaintext in memory each time it grows. Its errors carry serde's
  messages, which quote the value.

**Borsh** is strict and canonical: each value has exactly one encoding,
hash maps are sorted, and an option is tagged `0` or `1`. That suits bytes
that are hashed or signed. But:

- It is not self-describing. A blob is the fields' values in declaration
  order, with no names or kinds, so it reads only into the exact type that
  wrote it. Adding, removing or renaming a field, or making one optional,
  leaves the existing blobs unreadable. Swapping two fields of the same
  type is worse: they read back swapped, with no error. A value is kept for
  as long as the customer keeps the row, and over that time its type will
  change.
- It does not use serde. Every sealed type would need Borsh derives,
  including types from other crates (`uuid`, `chrono`), and the serde
  attributes that govern schema evolution here (`default`, `alias`) do not
  apply.
- A reader in another language needs the layout of the Rust type to read
  anything. There is no generic walk.
- It has no header or version.

Canonical bytes are what this profile gives up. A sealed value is compared
after it is opened, not as bytes, so the profile takes evolution instead.

## Stability boundary

Stable, and covered by this specification:

- the bytes of a blob, as laid out below, and what each reads as;
- `storage::to_vec` and `storage::from_slice`, which write and read them;
- `storage::HEADER`, `storage::MAGIC`, `storage::VERSION`, `storage::SOME`
  and `storage::MAP`;
- `storage::ErrorKind`, the class of a refusal.

The Go module `bindings/go/vcffi` implements the same format
(`MarshalStorage`, `UnmarshalStorage`), held to the same corpus.

Not stable, and not covered: everything else in `vitaminc-aead-frame`.
The transport frame (`Frame`, `FrameWriter`, `to_frame`), the transport
serde format (`serde::to_vec`, `serde::from_slice`, `serde::from_frame`)
and the ciphertext codec are for a host and a guest that ship together,
and MAY change in any release. A transport frame is not a blob, and a blob
is not a transport frame: neither reads as the other.

Error messages are not part of the format. They are fixed text, and never
contain a value or a key from the blob. A caller that acts on a refusal
matches its `ErrorKind`, never its message.

## Layout

All lengths and counts are unsigned 32-bit little-endian integers.

```text
blob    = header node
header  = 0x56 0x43 0x53 version      ; "VCS", then the version
version = 0x01

node    = scalar / array / object / map / some
array   = 0xF0 count node{count}
object  = 0xF1 count entry{count}
entry   = length utf8{length} node     ; the key, then its value
map     = 0xF6 count (key node){count} ; each key, then its value
key     = integer / text / bytes       ; a scalar of one of those kinds
some    = 0xF5 node
```

An object is a struct, or the one entry that names an enum variant: its
keys are names, and always text. A map is a serde map: its keys are data,
and each is a scalar node of its own, so it keeps its kind.

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
their raw bits, so a NaN's payload and the sign of zero are kept. `0xF5`
and `0xF6` are reserved in `vitaminc_aead::tags` (`STORAGE_SOME`,
`STORAGE_MAP`), so no leaf or transport tag will take them.

### Depth

The root node is at depth 0. An element of an array, the value of an
object's or a map's entry, and the node after `some` are one level deeper
than the node that holds them. A node deeper than 128 is refused.

## Reading

A reader MUST refuse a blob, and produce no value, if:

1. it is shorter than four bytes, or does not start with `"VCS"`: it is not
   a blob (`ErrorKind::NotABlob`);
2. its version is one the reader does not read
   (`ErrorKind::UnsupportedVersion`): this is reported apart from every
   other refusal, so a caller can tell a reader that needs upgrading from a
   corrupt blob;
3. the body after the header is not exactly one node: it is truncated, or
   bytes follow the node;
4. a node, or a map's key, starts with a byte the grammar above does not
   allow there;
5. a length or count runs past the end of the blob;
6. an object's key or a text scalar is not valid UTF-8;
7. one object has two entries whose keys are the same bytes;
8. one map has two equal keys: two integers of the same value, whatever
   their widths (`1u8` and `1u64`, `5i8` and `5u128`), or two text keys, or
   two bytes keys, with the same bytes. Text and bytes never equal each
   other or an integer;
9. a node is deeper than 128.

Rules 3 to 9 are `ErrorKind::Malformed`. `from_slice` checks the whole
blob against these rules before any value is built. A blob that passes, but
holds a value the type does not read, is `ErrorKind::Mismatch`.

A writer MUST NOT write a blob that a reader of its version refuses.
`to_vec` refuses a value that would break a rule above (one nested too
deep, a repeated key, text or bytes longer than a `u32` length) as
`ErrorKind::Unwritable`, and checks what it wrote as a reader would before
returning it.

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
| map                                  | map, entries in the order the map gives them                |
| struct                               | object, fields in the order the type writes them            |
| unit variant                         | text: the variant's name                                    |
| newtype variant                      | object of one entry: the name, then the value               |
| tuple variant                        | object of one entry: the name, then an array                |
| struct variant                       | object of one entry: the name, then an object               |

A field skipped with `skip_serializing_if` is not written. A `Vec<u8>` is a
sequence of `u8` in serde, so it is an array; `serde_bytes` makes it bytes.
Go's `[]byte` is always bytes, so a type whose values Go also reads keeps its
byte strings as bytes.
serde writes a struct with a `#[serde(flatten)]` field as a map, so it is a
map node whose keys are text. A value serialized through `Display`
(`collect_str`) is text.

`Some` is marked, so an option never reads back as another: `None` is `00`
and `Some(())` is `F5 00`, and in an `Option<Option<()>>`, `Some(None)` is
`F5 00` and `Some(Some(()))` is `F5 F5 00`. The marker is a node of its
own, so an option inside a type read through serde's buffering
(`#[serde(untagged)]`, `#[serde(tag = "…")]`, a struct with
`#[serde(flatten)]`) still reads as `Some`. An `Option` field that is
itself flattened is the exception: see [Not supported](#not-supported).

### Map keys

A map key MUST serialize as an integer of any width, a string, bytes, a
`char` or a unit variant (both text), a value written through `Display`
(text), or a newtype struct around one of those. Any other key (a bool, a
float, `None` or `Some`, unit, a sequence, a map, a struct, a variant with
a payload) is refused when written. A key type with a compact form uses it,
as a value does: a `uuid::Uuid` key is its 16 bytes.

When read, a key node is handed to the key type as a value of its kind
would be: an integer to an integer type that it fits, text to a string type
or an enum, bytes to a bytes type. A text key is never parsed as a number,
nor an integer formatted as text.

### Reading by type

Reading is directed by the type, and accepts these forms beside the ones
`to_vec` writes. Each reads as the value it would have been written from;
writing that value back gives the form in the table above.

- An integer reads as any integer type it fits; a type that reads through
  `deserialize_any` sees it at its written width. A float type reads a
  float or an integer, as serde's float types do; an integer type never
  reads a float.
- An `Option` reads null as `None`, `some` as `Some`, and any other node as
  `Some` holding that node, so a blob written before a field became
  optional reads. A type whose own value is written as null (unit, a unit
  struct, an `Option`) reads its old null as `None` instead.
- An enum reads a variant's name as a unit variant, or as a newtype variant
  whose value is read from null; and an object of one entry whose value is
  null as a unit variant. A map of one entry is not a variant.
- A struct reads an object, or a map whose keys are all text. A map reads
  a map or an object. A sequence reads only an array, a string only text,
  and bytes only bytes. A struct ignores unknown keys unless it denies
  them, and reads a missing `Option` field as `None`, as serde's derive
  does.

The corpus's `reads` rows pin these: each is a blob, a type described in
the corpus's own terms, and what that type reads it as, or that it refuses
it. They are frozen with the rest of version 1.

### Not supported

- A `#[serde(flatten)]` field of type `Option<T>`. serde writes its `Some`
  without telling the format, so no marker is written, and reads it back
  as `Some` whenever `T` can be read from the entries left over, which a
  `T` whose fields are all optional always can: `None` reads back as
  `Some(T { .. })`. serde does this in every format, JSON included. Put the
  `Option` inside the flattened type, or do not flatten it.
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

Writers in other languages make the same choice. Go's `vcffi` writes a
non-nil pointer as its value, unmarked, as `encoding/json` does, where Rust
writes `Some(x)` as `some`, then `x`. So `&int32(5)` in Go and
`Some(5i32)` in Rust are different blobs. Both readers read both forms, as
the same value.

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

The golden corpus in `testdata/storage-v1.json` pins version 1: values
and their bytes (`vectors`), blobs and their refusal classes (`refused`),
and blobs read by types (`reads`). Its rows are never edited or removed,
and CI checks that with `scripts/storage_corpus_append_only.py`; rows MAY
be added. `tests/storage_coverage.rs` fails if a tag, a map key kind, a
part of a numbered rule in [Reading](#reading), or a clause of
[Reading by type](#reading-by-type) or of [Map keys](#map-keys) on reading,
has no row that shows it. It holds
those rules and clauses, and the grammar they refer to, word for word, so
a change to them here fails it until the change has a row. A reader in another language passes
when it reads every vector as its value and refuses every refused row by
its class; one that maps blobs onto types also reads every `reads` row as
it says.

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
| `Option<T>` to `T`                              | is refused if it held `Some`; `None` is refused unless `T` reads null |
| Add an enum variant                             | reads; an older reader refuses the new variant   |
| Widen an integer                                | reads; narrowing reads only values that fit      |
| `HashMap<String, V>` to a struct                | reads, if every key is a field or ignored        |
| A struct to `HashMap<String, V>`                | reads                                            |

An application that needs to tell its own schema versions apart carries
that in the value, as an enum of versions say. The blob header is not for
that, and never changes because the type did.

## The blob inside an outer envelope

A blob is plaintext, and `to_vec` returns it `Protected`. The caller seals
it whole, header included, under an envelope of its own (Stack Encrypt's
ciphertext). The header is therefore encrypted with the value: nothing
about the blob, its version included, can be seen before decryption, and
the envelope's authentication covers the header as it covers the value.

The envelope and the blob are two formats with two versions: a new
envelope version does not change a blob's bytes, and a new blob version
does not change the envelope. A reader that meets a blob version it does
not read decrypts, and gets `ErrorKind::UnsupportedVersion`.

An envelope that wants the blob's version visible before decryption, to
refuse it without a decryption or a key lookup, records the version in its
own clear metadata, and passes it as associated data when it seals and
opens, so a changed version fails authentication. That is the envelope's
choice, and needs nothing from this profile.

## Memory and timing

The writer grows its buffer into a fresh allocation and wipes the old one,
formats a `Display` value straight into the blob, keeps no copy of a key,
and wipes everything if writing fails. The blob it returns is `Protected`,
and wiped when dropped. The reader borrows text and bytes from the blob
rather than copying them, and finds a repeated map key by comparing keys
where they lie in the blob. None of it is constant time, and
serde's own impls are not. A `T: Zeroize` does not wipe fields it read
before a later field failed. Improvements to any of this MUST keep the
bytes, which the corpus checks.
