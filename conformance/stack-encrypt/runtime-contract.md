# Record runtime profile

`record-runtime-v1` describes the behavior exercised by `v1/runtime.json`.
It is an experimental test contract for native Rust and Go WASI, with no EQL
resolver. Python and TypeScript runners remain pending.

Each case uses one field, `value`, with ciphertext (`c`) and equality (`eq`)
outputs, under context `["conformance", "value"]`. `kind` declares its type;
`null` is empty for a required value, `sql`, or `sealed`. Values use the scalar
profile's `{type, text}` representation, extended with `float64` decimal text.
Runners construct typed values before calling the engine.

## Write and read

The `seal` operation receives an ordered `rows` array of field maps. An absent
map key is missing; `{ "type": "null", "text": "" }` is an explicit null.
These are separate inputs, including in languages that offer a nil-like value.

Successful cases specify `expected_rows` and `expected_stored`. The former
describes opened values with their types and order. The latter states whether
each row stores the field at all. Both must have the input row count.

- Required fields reject missing values and explicit nulls.
- SQL-null fields accept both, omit the stored field, and open as explicit null.
- Sealed-null fields require the key to exist. An explicit null stores both
  ciphertext and equality, then opens as null.
- Runtime writes require the declared numeric type. A losslessly convertible
  value of another width is still refused on this path.
- Unknown fields are refused; they cannot be silently dropped.
- An invalid later row rejects the whole batch before data-key generation.
- An empty batch succeeds with no data-key calls.

Every stored equality term must match a query for its expected opened value.
`equal_lengths` additionally requires all stored ciphertexts in the case to
have equal lengths. Mixed sealed-null/value cases exercise this requirement
for int32, int64, uint64 and float64. This is not a claim about all types.
Boolean equality is not admitted; existing native null tests cover boolean
ciphertext separately.

## Equality queries

The `query` operation receives `input` and either `expected_value` or
`expected_error`. A successful query's term must equal the term stored by
encrypting `expected_value` through the same declaration. That value is
independent expected data, not a conversion computed by the runner.

Cases cover signed narrowing bounds, integral and fractional float inputs,
negative-to-unsigned refusal, and exact versus rounded integer-to-float
conversion around 2^53. Text and boolean values are not parsed as numbers.
A null equality query succeeds only for sealed-null fields.

## Refusals and observations

`expected_error` specifies the engine diagnostic `code`, `reason`, and `field`.
Native Rust must reject before producing a pending operation. Go must expose
`ErrEncoding` and the same diagnostic when the request reaches the guest.

Missing and unknown fields are rejected earlier by Go's record adapter.
Those cases additionally specify `go_message`, an exact adapter regression
observation, and require no engine diagnostic. This prose is not a portable
engine error contract. A future SDK should report equivalent semantics at its
earliest supported stage, without adopting Go's wording.

The native runner instruments data-key generation and retrieval calls. A
successful batch makes one of each when it stores ciphertext, and zero when
every field is omitted. Refused writes and all queries make neither call.
The query oracle's separate encryption is counted separately. These assertions
exclude index-key initialization and do not establish Go provider-call counts.
Go runs the same semantic cases through its deterministic WASI guest; that
guest's lack of network requests is not proof of logical key-call counts.

## Scope and remaining work

The 37 cases cover runtime writes, corresponding reads, and equality queries.
They do not cover malformed stored records, authenticated type mismatches on
read, context composition/preflight, provider failures, or other operators.
Fresh cross-language artifact exchange remains the scalar profile's coverage.

Existing `value_kinds.json` and `query_operators.json` fixtures remain the
shared evidence for their wider type/operator matrices. Existing generated
Go null tests retain pointer mapping and EQL assertions. Native null tests
retain their wider kinds and lower-level padding assertions. No tests are
deleted by this slice; consolidation requires matching those assertions first.
