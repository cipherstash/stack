---
status: accepted
date: 2026-11-13
extends: ADR-0010, ADR-0011
---

# A JSON document is one text leaf, holding its JSON text

## Decision

To encrypt a JSON document as one ciphertext, the caller wraps a
`serde_json::Value` in `JsonPlaintext`. The document is written as JSON
text. The text is sealed as one text leaf of the ordinary envelope.
Decrypting authenticates the leaf first, then parses the text by the
engine's strict JSON rules.

## Context

EQL has a storage-only JSON type, `public.eql_v4_json`. Its payload is
`{v, i, c}`, where `c` holds one sealed leaf. Until this decision, no
plaintext type sealed a JSON document as one leaf, so nothing could write
the type.

The existing ways to encrypt a JSON document did something different:

- The JSON index seals one entry per node, and stores selectors and
  tokens beside them so that the document can be searched. The stored
  column shows which rows have which paths, and is many times the size of
  the plaintext.
- `OpaqueBlob<T>` (ADR-0011) seals a whole value as one leaf. It encodes
  the value with Vitamin C's storage profile, which follows serde's data
  model.

An application that stores a JSON document, and never searches it, needs
neither the index's cost nor a format that depends on one language's
types.

## The parts of the decision

### The stored plaintext is JSON text

The leaf holds the text `serde_json` writes for the document: no
whitespace between tokens, each number in its shortest form that reads
back as the same number, and an object's members in the order the `Value`
holds them.

JSON text is the one form of a JSON document that every language reads
the same way. A document that the Go SDK seals and another SDK opens is
the same JSON value on both sides.

The document is stored as values, not as the caller's text. Whitespace,
member order and the spelling of a number are not kept. The JSON index
makes the same promise, so a document read back from either stored form
is the same value.

### The leaf is a text leaf

JSON text is UTF-8 text, and a text leaf says so. The ciphertext is the
same as sealing a `String` that holds the text. Sealing a document adds no
new envelope, no new kind of key request and no new AAD. `SealedValue` v1
does not change.

### Decryption authenticates first, and uses the strict parser

The leaf is opened first. Only then is the text parsed, by
`json::parse_text`. That parser reads a number as a 64-bit integer or a
double, refuses an object that names a member twice, and refuses text
that is not valid Unicode. So a document read back never depends on which
JSON parser a language uses.

A leaf that opens but does not hold a JSON document is
`Error::OpenedType`. This covers a leaf that is not text, and text the
parser refuses. As ADR-0010 says, that refusal means the data was written
as something else. It does not mean the data was tampered with. A leaf
that does not open is `Error::Aead`.

### A document is sealed only if it will open

A `serde_json::Value` can hold a document the strict parser refuses: one
nested deeper than 127 levels, or, with `serde_json`'s
`arbitrary_precision` feature, a number that is not a 64-bit integer or a
double. Sealing such a document would store a ciphertext that never opens.

So the text is parsed by the same rules before it is sealed. A document
they refuse is not sealed, and no key is requested. The refusal is
`Error::Aead`, as it is for any value that cannot be sealed as given, such
as a record nested deeper than the envelope carries.

The check is the parser itself, not a second set of rules. So what is
sealed and what opens cannot drift apart. It costs one more pass over the
text for each document sealed.

### A document is a scalar to the cipher

`JsonPlaintext` implements Vitamin C's `Encrypt`, `Scalar` and
`FromScalar`. So every API that takes a single value takes a document:
`KeysetCipher::encrypt`, a ciphertext field of a record, and an EQL type
that holds one ciphertext.

`serde_json::Value` does not implement `Zeroize`, and Rust's orphan rule
stops this crate adding it. `JsonPlaintext` holds the `Value` and wipes it
when it is dropped, as `value::Date` stands in for chrono's date.

### An absent document is not a document

A JSON `null` is a document, and is sealed like any other. An absent
value is an `Option` that is `None`. Text has no fixed length, so a `None`
is sealed with no padding, and its length can show that the value is
absent. A data plan stores an absent `json` field as SQL `NULL`.

### An equality term is the term of the text

The engine derives an equality term from any single value. So a target
that declares one for a document gets the equality term of its JSON text,
the same term a `String` holding that text has. No EQL type declares one:
`Json` has a ciphertext and nothing else.

Equal documents have one term when `serde_json` keeps an object's members
in key order, which is its default. With its `preserve_order` feature, two
objects with the same members in a different order are equal values with
different texts and different terms. A target that needs document equality
under that feature is not served by this term.

## What is not claimed

- **Length hiding.** The ciphertext is as long as the JSON text, plus a
  constant. Padding is the application's job.
- **A marker for JSON.** Nothing in the leaf says its text is JSON. A
  document decrypted as a `String` gives the JSON text. A `String` that
  holds JSON text decrypts as a document. The AEAD binds the context in
  both cases, so neither lets a caller read data they could not read
  before.
- **Search or partial reads.** Nothing inside the ciphertext can be
  queried or read on its own. The JSON index is for those needs.
- **A named refusal on encrypt.** A document that would not open is
  refused as `Error::Aead`, which does not say why. `JsonPlaintext::parse`
  names the reason when a document is built from text.
- **The caller's text.** A document is stored as values. Two texts that
  parse to the same value are stored as the same text.

## Alternatives considered

- **`OpaqueBlob<serde_json::Value>`.** Rejected. The storage profile
  records the width of every number and follows serde's data model. A
  document written by one SDK and read by another would not be the same
  JSON value, and each SDK would need a mapping from the profile to JSON.
- **A JSON index document with no index terms.** Rejected. It is a
  different payload shape, and `public.eql_v4_json` checks for the flat
  `{v, i, c}` shape. It would also keep the index's per-node entries.
- **A bytes leaf.** Rejected. The text is UTF-8, and a text leaf lets a
  reader of the leaf know that. A text column that already holds JSON
  text can then be read as a document with no rewrite.
- **A header inside the text, as a blob has.** Rejected. JSON text needs
  no version: the format is the JSON standard, and the strict parser's
  rules only narrow what is accepted. A header would also stop any other
  JSON reader opening the text.

## Consequences

- `stack_encrypt::json::JsonPlaintext` is public. The dynamic interface's
  `JsonPlaintext` is the same type.
- EQL's storage-only `Json` type is produced from a `JsonPlaintext`, and a
  data plan can name it as a field target.
- The stored text is `serde_json`'s output. A change to how the engine
  writes JSON text changes new ciphertexts only. Every ciphertext written
  earlier still reads, because reading uses the parser and not a byte
  comparison.
