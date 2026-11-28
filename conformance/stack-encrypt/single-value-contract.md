# Single-value profile

`single-value-v1` is the conformance profile for one value encrypted as one
ciphertext. The profile describes the cases in
`v1/single-value-v1.cases.json`. The cases run through the run-time interface
of the engine, `stack_encrypt::dynamic::value`. The profile is an experimental
test contract.

The run-time interface takes a value as a frame, with a declared kind. The
typed Rust interface must decrypt the result. The run-time interface must
decrypt a ciphertext that the typed Rust interface made. So every language
can decrypt a value that one language encrypted.

## Terms

- A frame is one value written as bytes, in the format that the engine reads.
- A kind is the name of what a value is, such as `string` or `uint64`. The
  declared kind is the kind that the caller says the value has.
- A leaf is the encrypted form of one scalar. A ciphertext of one value
  contains one leaf.
- To seal a value is to encrypt and authenticate it. To open a ciphertext is
  to decrypt it and check it.
- A passthrough is a value that a record stores without encrypting it.
- A refusal is an error that the engine returns for a value it does not
  accept.
- The typed interface is the Rust API for a value of a Rust type:
  `keyset.encrypt` and `keyset.decrypt`.

## Runners

The Rust runner is `packages/stack-encrypt/tests/single_value_conformance.rs`.
The Go runner is pending. The Go runner will be written with the single-value
calls of the Go SDK (issue #2010). The Python and TypeScript runners are
pending too. A missing runner is not a passing result.

## Cases

The file has three parts: a public `seed` for the deterministic key provider,
a list of `cases`, and a list of `batches`. Each case has these keys:

| Key | Meaning |
|---|---|
| `id` | The name of the case |
| `kind` | The name of the declared kind, or empty for no declared kind |
| `context` | The parts of the context, or an empty list for the empty context |
| `input` | The value, in the `{type, text}` form that the [value profile](values-contract.md#cases) defines |
| `stored` | The value in the ciphertext, where it differs from the input |
| `opens_as` | Kinds that the ciphertext must open as, other than the declared kind. Each entry has the `value` that the ciphertext opens to. |
| `refused_as` | Kinds that the ciphertext must not open as |
| `expected_error` | For a refused case, the `code` and `reason` of the refusal |

A context of two parts is a pair. For example, `["conformance", "value"]` is
the Rust context `("conformance", "value")`. For an empty list, a runner calls
the form with no context. For any other list, a runner calls the form with a
context.

This profile adds two input types to those of the value profile:

| `type` | `text` |
|---|---|
| `uuid` | The UUID in lowercase hex, in groups of 8, 4, 4, 4, and 12 digits |
| `shape` | The name of a value that `{type, text}` cannot spell. The next table lists the names. |

| Shape | The value |
|---|---|
| `array` | The array of the two strings `a` and `b` |
| `empty_array` | The array with no elements |
| `object` | The object with one member, `a`, the `uint32` 1 |
| `passthrough` | A passthrough of the string `clear` |
| `typed_null` | A typed null of `int64` |

Some host languages cannot build every shape. A runner in such a language
sends the frame that the artifact file records for the case.

## Artifacts

The Rust runner writes `v1/single-value-v1.expected.rust-native.json`. The
file has one entry for each case:

- `frame`: the frame of the input, in hex. Every case has one.
- `leaf`: the plaintext that the leaf of the ciphertext is sealed with, in
  hex. That plaintext is the type tag of the leaf and its payload. Only an
  accepted case has one.
- `ciphertext`: a ciphertext of the value, in hex. Only an accepted case has
  one.

The typed Rust interface made each `ciphertext` where a Rust type spells the
stored value. No Rust type spells a lone `uint8`, so the run-time interface
made the ciphertext of that case.

A runner never compares whole ciphertexts. Each sealed leaf has a random
AES-GCM nonce, so two ciphertexts of one value differ. A runner compares the
parts of a ciphertext that the nonce does not change:

- the keyset
- the IV and tag of the data key
- the length of the ciphertext
- the plaintext of the leaf

The deterministic provider derives a data key from the seed, the context, and
a counter. So a runner makes a new provider for each ciphertext it compares.

Regenerate the artifacts deliberately, with `STACK_ENCRYPT_UPDATE_FIXTURES=1`
and the native runner. Review the diff of the cases and the diff of the
artifacts together.

An update keeps the frozen ciphertext of a case whose frame and leaf have not
changed. The update checks that ciphertext as any run does. So a ciphertext
stays frozen from one update to the next, and the diff shows only the cases
that changed.

## Required behavior

### An accepted case

A case with no `expected_error` is an accepted case. For each one:

1. The frame of the input equals the frozen `frame`.
2. The run-time encrypt accepts the value with the declared kind and the
   context. The plaintext of the leaf that it seals equals the frozen `leaf`.
3. The new ciphertext and the frozen `ciphertext` agree in every part that
   the nonce does not change.
4. Each of the two ciphertexts opens under the same context, with no declared
   kind. The result is `stored`, or the input where the case has no `stored`.
5. Each of the two ciphertexts opens under the same context, with the
   declared kind, to the same value. With the kind `json`, the result is the
   stored JSON text as a bytes value.
6. Each ciphertext opens as each kind in `opens_as`, to the `value` of that
   entry.
7. Each ciphertext is refused when it is opened as a kind in `refused_as`.
   The code of the refusal is `stack_encrypt::opened_type`. The `expected`
   field of the refusal is the name of the kind. The refusal never says what
   the value opened as.
8. Each ciphertext is refused under the context `["conformance", "wrong"]`.
   The deterministic provider refuses the key request as forbidden, as
   ZeroKMS does. Other providers can report a wrong context differently.

Native Rust also checks two things. The typed interface seals the same parts
for the stored value. The typed decrypt opens both ciphertexts.

### Conversions

A case with `stored` is a conversion. The engine seals a number of another
width or kind as the value of the declared kind, when the conversion is exact.
The conversion rules are the ones that a typed field of a record uses. The
engine seals a document with the kind `json` as its compact JSON text.

### Strings and JSON documents

`json` is a declared kind and not a stored kind. A `string` and a document
have one stored form: text. So a check of the stored kind cannot distinguish
them. Three groups of cases pin the consequences:

- `json-given-string`: a sealed document opens as `string`, to the JSON text
  that was sealed.
- `string-json-number-text` and `string-json-spaced-text`: a sealed string
  whose text is a JSON document opens as `json`. Decrypt as `json` checks that
  the text parses. Decrypt then returns the document as the engine writes it,
  as a bytes value. So `{ "b" : [ 1 , null ], "a" : true }` comes back as
  `{"a":true,"b":[1,null]}`.
- `string-not-json-text`: a sealed string whose text is not a JSON document is
  refused as `json`.

### A refused case

A case with `expected_error` is a refused case. The run-time encrypt refuses
the value before any key request, with the diagnostic `code` and `reason` of
the case. The code of every such refusal is `stack_encrypt::dynamic_value`. A
single value has its own refusal, with no record, plan, or field in it.

The cases cover these values:

- An array, an object, a passthrough, a plain null, and a typed null. Each is
  tested with no declared kind and with one. The reason names what was found:
  `array`, `object`, `passthrough`, or `null`.
- JavaScript's `undefined`, with a declared kind and with none. The reason is
  `undefined`.
- A value of another kind that does not convert exactly. The reason is
  `field_type`.
- Text that is not a JSON document, with the kind `json`. The reason is
  `json_syntax`, `json_duplicate_key`, or `json_integer_range`.

The engine refuses `undefined` with any declared kind. An `undefined` value is
most often a misspelt property name. No typed call could read it back.

A host language with no `undefined` has two options for those cases. The
runner can send the frame that the artifact file records. Or the runner can
check that the cases are well formed, and skip them.

## Batches

The run-time interface has no batch call. To encrypt many values, a binding
makes one single-value call for each value. The binding then merges the
pending calls into one key request. In Rust, `Pending::all` merges the calls.
A binding decrypts many ciphertexts the same way.

Each call has its own declared kind, so one batch can contain values of
different kinds. Each entry of `batches` has three keys:

- `inputs`: a list of values
- `kinds`: the declared kind for each input, or empty for none
- `context`: one context for all the inputs

A runner seals and opens each entry as a binding does:

- An accepted batch seals in one key request and opens in one key request.
  The values come back in the order of the inputs. The expected values are
  `stored` where the batch has one, and the inputs otherwise.
- An empty batch makes no key request.
- In a batch with `expected_error`, the single-value call refuses one of the
  values with that `code` and `reason`. The batch then makes no key request.

The counts of key requests are native observations: the Rust runner counts
them on its key source.

## Scope and remaining work

The profile covers every scalar kind, the exact conversions, JSON documents,
and the refusals of the run-time encrypt. The profile does not cover these:

- A ciphertext of a null. Only the tree interface seals one.
- A scalar of a logical type that the engine does not define. The
  `{type, text}` form cannot spell one. With no declared kind, the engine
  seals such a scalar as it arrived.
  `packages/stack-encrypt/tests/single_value.rs` tests that natively.
- Decrypt limited to one keyset.
  `packages/stack-encrypt/tests/single_value.rs` tests that natively.
- New ciphertexts exchanged between languages. That needs a second runner.
