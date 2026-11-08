# Record raw-frame profile and error classes

`record-raw-frames-v1` describes the cases in `v1/record-raw-frames-v1.cases.json`: stored
record batches supplied as transport bytes (`frame_hex`), so both runners
hand the decoder the same bytes, including what no map-based tree encoder
can write. It is an experimental test contract for native Rust and Go WASI.
Python and TypeScript runners remain pending.

The read profile builds stored records from real ciphertext and mutates the
tree. Its Go runner encodes that tree through the host's tree codec, which
refuses a repeated key, so repeated keys and malformed leaves could not be
shared there. This profile is the explicit raw-byte path the read profile
deferred.

The runners are `packages/stack-encrypt/tests/raw_frame_conformance.rs`
and `languages/golang/encrypt/raw_frame_conformance_test.go`. Go reaches
the guest through a test-only hook that takes the encoded batch directly
(`OpenFrameForTest`), keeping cipher validation, context, production
decoding and buffer cleanup; the uninitialised checker observes the guest's
preflight alone.

## Error classes

A read can fail at five points. Each class is the stage, not the message,
and a case's `class` names where its frame stops:

| `class` | Where it stops | Native observation | Go observation |
|---|---|---|---|
| `transport` | The bytes are not a ciphertext tree in the transport codec | `decode_ciphertext` fails; the codec reports no code | `stack_guest_abi::malformed_input`, the corpus-wide `boundary_error`, as `ErrEncoding`, from the checker and the cipher |
| `leaf` | The tree decodes and a sealed leaf is not in the leaf byte format | `SealedValue::from_bytes` fails with its code and payload | The same code and payload as `ErrEncoding` |
| `shape` | Leaves are well formed and the tree does not fit the plan | `check_record` and `decrypt` refuse with `stack_encrypt::dynamic_record` before any pending operation | The same diagnostic from the checker and the cipher |
| `authenticated` | The tree fits, the leaf is opened, and what it holds is not what the plan reads | The pending opener fails after one retrieval | The checker reaches `ErrState`; the cipher reports the diagnostic |
| `success` | The record opens | Typed rows, one retrieval | Typed rows |

Two more classes live in other profiles and are listed here so the five
are read together. An **invalid declaration** stops before any record: the
declaration grammar's cases report `stack_encrypt::dynamic_plan`, and a
malformed plan frame reports the same `malformed_input` boundary. An
**unsupported host conversion** stops before the engine: the value profile's
`host_conversions` report the host's own `ErrEncoding` with no engine
diagnostic.

Within `authenticated`, two outcomes are distinguished. A leaf sealed as an
`int32` and read as `int64` or `string` authenticates and then fails the
declared type: `stack_encrypt::plan_field_type` naming the field and the
expected kind, as the read profile's authenticated cases do. A leaf moved
into another role (the single leaf under an empty-sequence tag) fails
authentication itself: `stack_encrypt::aead`, which Go reports as
`ErrAuthentication` carrying that code. Both runners compare the code and
fields of either outcome, as they do for every refusal. Neither is a shape refusal: a container's membership
and order are not authenticated, so a tree that fits the plan passes
preflight and is judged leaf by leaf.

## Repeated keys

The transport codec refuses a map with a repeated key, in the frame a
binding writes and in the frame a guest reads, so a stored record with the
same field or output twice is a `transport` refusal in both runners. It
never reaches the engine's own `field_repeated` and `repeated_key` reasons.

Those reasons still guard a tree built in native Rust without the codec.
`native_tree` records what the engine says of the same bytes when a reader
admits the repeated key and keeps every other codec rule: the runner reads
the frame leniently, checks the tree against the plan, and compares the
diagnostic. A separate test holds that reader to the codec on every frame
the codec accepts. Go parses `native_tree` and does not execute it: a
binding cannot reach the engine with such a tree.

## Cases

`frame_hex` is the complete batch: one row, one field `value` with `c` and
`eq`. The well-formed leaf is the scalar profile's frozen `i32-max`
ciphertext under seed zero and context `["conformance", "value"]`, with its
frozen equality term as the passthrough. `read` names the declaration the
batch is read under. `retrievals` is `1` for `authenticated` and `success`
and `0` otherwise; a read never generates a key. The counts are a native
observation: Go checks that `retrievals` agrees with the class, and its
checker's stop at the state boundary stands in for "nothing retrieved
before preflight".

| Case | Class | What the bytes do |
|---|---|---|
| `success-frozen-leaf` | success | The frozen leaf read as `int32` |
| `authenticated-int64`, `authenticated-string` | authenticated | The frozen leaf read as another kind |
| `authenticated-c-empty-sequence` | authenticated | The frozen leaf under the empty-sequence tag |
| `shape-c-passthrough` | shape | A plaintext passthrough where the ciphertext must be |
| `leaf-unknown-version` | leaf | The leaf's version byte is 9 |
| `leaf-truncated` | leaf | Two leaf bytes |
| `transport-repeated-field` | transport | `value` twice in the row; natively `field_repeated` |
| `transport-repeated-output` | transport | `c` twice in the field; natively `repeated_key` |
| `transport-retired-none-tag` | transport | The retired absence marker as a node |
| `transport-trailing-byte` | transport | A byte after a complete tree |
| `transport-truncated-count` | transport | A sequence count of two with one row |
| `transport-not-a-tree` | transport | One byte that is no tag |

Both runners reject a case whose expectations contradict its class, and a
transport case whose frame the codec accepts. Go additionally shows that
its own tree codec refuses every transport frame, so none of them is a
batch the host could have written.

## Scope and remaining work

The frames hold one row and one field. Depth and size bounds, context
fields, other output kinds and repeated keys inside passthrough payloads
stay with the codec's own tests and the read profile. Python and
TypeScript consumers should feed the same `frame_hex` to their decoders.
No existing test is removed.
