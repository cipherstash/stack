# Single-value profile

`single-value-v1` describes the cases in `v1/single-value-v1.cases.json`: one
value encrypted into one ciphertext, and decrypted from one, through the
engine's run-time interface (`stack_encrypt::dynamic::value`). It is an
experimental test contract.

The run-time interface takes a value as a transport frame, with the kind the
caller declares for it. It must return the ciphertext the typed Rust interface
(`keyset.encrypt`) returns for the same value, so that a value one language
encrypts, every other language decrypts.

The Rust runner is `packages/stack-encrypt/tests/single_value_conformance.rs`.
The Go runner is pending: it comes with the Go SDK's single-value calls
(#2010). Python and TypeScript runners are pending too. A missing runner is not
a passing result.

## Cases

The file has a public deterministic-provider `seed`, a list of `cases` and a
list of `batches`. Each case has:

| Key | Meaning |
|---|---|
| `id` | The case's name |
| `kind` | The name of the declared kind, or empty for no declared kind |
| `context` | The context's parts, or an empty list for the empty context |
| `input` | The value, in the `{type, text}` form the [value profile](values-contract.md#cases) defines |
| `stored` | The value the ciphertext holds, where it is not the input |
| `opens_as` | Kinds the ciphertext must open as, beside the declared one, each with the `value` it opens to |
| `refused_as` | Kinds the ciphertext must refuse to open as |
| `expected_error` | For a refused case, the refusal's `code` and `reason` |

A context of two parts is the pair of them: `["conformance", "value"]` is the
Rust context `("conformance", "value")`. A runner calls the form with no
context for an empty list, and the form with a context otherwise.

This profile adds two input types to the value profile's:

| `type` | `text` |
|---|---|
| `uuid` | The UUID in lowercase hex, in groups of 8, 4, 4, 4 and 12 digits |
| `shape` | The name of a value that `{type, text}` cannot spell (below) |

| Shape | The value |
|---|---|
| `array` | The array of the two strings `a` and `b` |
| `empty_array` | The array with no elements |
| `object` | The object with one member, `a`, the `uint32` 1 |
| `passthrough` | A passthrough of the string `clear` |
| `typed_null` | A typed null of `int64` |

A runner that cannot build a shape in its host language sends the frame the
artifact file records for the case.

## Artifacts

`v1/single-value-v1.expected.rust-native.json` holds one entry for each case,
written by the Rust runner:

- `frame`: the input's transport frame, in hex. Every case has one.
- `leaf`: the plaintext the ciphertext's leaf is sealed with, in hex: the
  leaf's type tag and its payload. Only an accepted case has one.
- `ciphertext`: a ciphertext of the value, in hex. Only an accepted case has
  one. The typed Rust interface made it, where a Rust type spells the stored
  value. No Rust type spells a lone `uint8`, so the run-time interface made
  that one.

Ciphertext bytes are never compared whole. Each sealed leaf carries a random
AES-GCM nonce, so two ciphertexts of one value differ. A runner compares the
parts of a ciphertext that the nonce does not change: the keyset, the data
key's IV and tag, the ciphertext's length, and the plaintext of the leaf.
The deterministic provider derives a data key from the seed, the context and
a counter. So a runner makes a fresh provider for each ciphertext it compares.

Regenerate the artifacts deliberately, with `STACK_ENCRYPT_UPDATE_FIXTURES=1`
and the native runner, and review the case and artifact diff together. An
update keeps the frozen ciphertext of a case whose frame and leaf have not
changed, and checks it as any run does. So a ciphertext stays frozen from one
update to the next, and the diff shows only the cases that changed.

## Required behavior

For a case with no `expected_error`:

1. The input's frame equals the frozen `frame`.
2. The run-time encrypt accepts the value under the declared kind and the
   context. The plaintext of the leaf it seals equals the frozen `leaf`.
3. The fresh ciphertext and the frozen `ciphertext` agree in every part that
   the nonce does not change.
4. Each of the two ciphertexts opens, under the same context:
   - with no declared kind, to `stored` (or to the input, where the case has
     no `stored`);
   - with the declared kind, to the same value. Under `json` it opens to the
     stored JSON text in a bytes leaf.
5. Each ciphertext opens as each kind in `opens_as`, to that entry's `value`.
6. Each ciphertext is refused when opened as a kind in `refused_as`. The
   refusal's code is `stack_encrypt::opened_type`, and its `expected` field is
   the kind's name. The refusal never says what the value opened as.
7. Each ciphertext is refused under the context `["conformance", "wrong"]`.
   The deterministic provider refuses the key request as forbidden, which
   models ZeroKMS. Other providers may report a wrong context differently.

Native Rust also checks that the typed interface seals the same parts for the
stored value, and that the typed decrypt opens both ciphertexts.

A case with `stored` is a conversion. A number of another width or kind is
sealed as the declared kind's value when the conversion is exact, by the rules
a record's typed field uses. A document under `json` is sealed as its compact
JSON text, in a text leaf.

`json` is a declared kind, and not a stored one. A `string` and a document
share one stored form, a text leaf, so a kind check cannot tell them apart.
Three cases pin what follows from that:

- `json-given-string`: a sealed document opens as `string`, to the JSON text
  that was sealed.
- `string-json-number-text` and `string-json-spaced-text`: a sealed string
  whose text is a JSON document opens as `json`. Decrypt as `json` checks that
  the text parses, and returns the document as the engine writes it, in a
  bytes leaf. So `{ "b" : [ 1 , null ], "a" : true }` comes back as
  `{"a":true,"b":[1,null]}`.
- `string-not-json-text`: a sealed string whose text is not a JSON document is
  refused as `json`.

For a case with `expected_error`, the run-time encrypt refuses the value
before any key request, with the diagnostic `code` and `reason`. The refusal
names no field. The cases cover:

- an array, an object, a passthrough, a plain null and a typed null, each with
  no declared kind and with one: the reason says what was found (`array`,
  `object`, `passthrough`, `null`);
- JavaScript's `undefined`, with a declared kind and with none (`undefined`);
- a value of another kind that does not convert exactly (`field_type`);
- text that is not a JSON document, under `json` (`json_syntax`,
  `json_duplicate_key`, `json_integer_range`).

`undefined` is refused whatever kind is declared. It is most often a property
name spelt wrong, and no typed call could read it back. A host with no
`undefined` sends the frame the artifact file records for those cases, or
checks their shape and skips them.

## Batches

The run-time interface has no batch call. A binding encrypts many values by
making one single-value call for each value, and merging the pending calls
into one key request. In Rust the merge is `Pending::all`. It decrypts many
ciphertexts the same way. Each call has its own declared kind, so one batch
can hold values of different kinds.

Each entry of `batches` has a list of `inputs`, a list of `kinds` with the
kind declared for each input (empty for none), and a `context` for all of
them. A runner seals and opens each entry as a binding does. An accepted
batch seals in one key request and opens in one, and the values come back in
the order of the inputs: `stored` where the batch has one, the inputs
otherwise. An empty batch makes no key request. In a batch with
`expected_error`, the single-value call refuses one of the values with that
`code` and `reason`, and the batch makes no key request.

The key-request counts are native observations: the Rust runner counts them
on its key source.

## Scope and remaining work

The profile covers every scalar kind, the exact conversions, JSON documents
and the refusals of the run-time encrypt. It does not cover:

- a ciphertext that holds a null, which only the tree interface seals;
- a scalar of a logical type the engine does not know, which `{type, text}`
  cannot spell. With no declared kind the engine seals it as it arrived, and
  `packages/stack-encrypt/tests/single_value.rs` pins that natively;
- keyset confinement on decrypt, which
  `packages/stack-encrypt/tests/single_value.rs` covers natively;
- fresh ciphertexts exchanged between languages. That comes with the first
  second runner.
