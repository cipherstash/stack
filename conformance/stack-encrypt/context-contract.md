# Context composition

`record-contexts-v1` (`v1/contexts.json`) specifies composition for the current
record API. `context-boundaries-v1` (`v1/context-boundaries.json`) specifies
stored-context expectations and refusal boundaries. Both are required in Rust
and Go. Python and TypeScript must implement these profiles when their runners
are added; their absence is not conformance evidence.

## Current semantics

A field's base is a plain label: the record's declared label followed by the
field's identity. A context-field record obtains the record label from each
row's stored field. A Rust plan built without a context can instead take that
label from the call. Go generated types declare either a literal context or a
context field; they do not expose Rust's contextless saved-plan builder.

Caller input has two distinct purposes:

- A **base label** supplies a missing base for a query or a contextless Rust plan.
  For a record storing its own context, an expected label checks that stored
  value. It does not replace or extend it. A caller label on a plan with a
  literal base is refused.
- An **extension** appends to the resolved field context for encryption,
  decryption and search. Each call appends in order. Rust
  `.extend(7u64).extend(nonempty!("eu"))` and Go
  `.Extend(uint64(7)).Extend("eu")` produce `((label)/7u64)/eu`.
  Rust `.extend(())` and Go `.Extend()` append nothing. A Rust
  `DeclaredContext` containing several parts appends all of those parts.

Grouping is significant. Rust `.extend(NonEmpty::from(7u64).with("eu"))` adds
one composite part, producing `(label)/(7u64/eu)`. This has different AAD and
terms from separate extensions. Nested `ContextPiece` values are supported by
Rust's lower-level context APIs; the dynamic record grammar and Go `Extend`
accept scalar extension parts only. Their refusal of a grouped extension is
part of the supported API boundary, not permission to flatten it.

Previously, repeated Rust chain extensions replaced earlier parts. Records
written by those chains still require the
**last extension alone** when opening them; callers must explicitly retain that
old context when reading and querying old records. A query using repeated
extensions now succeeds with different terms, silently missing old rows.
Re-encrypt and re-index old rows to adopt the appended context. This change
does not rewrite ciphertext or migrate stored terms.

The native base and each appended scalar retain their type and structure.
`7i32`, `7i64`, `7u64`, text `eu`, and bytes `6575` do not collapse to one AAD
or PRF context. Descriptor rendering is deliberately coarser in some cases:
text and bytes can render alike, as can positive signed and unsigned integers.
A matching descriptor alone therefore does not prove matching AAD. Empty text
is accepted by dynamic record/Go extension APIs when the base remains nonempty;
Rust's `NonEmpty` constructor rejects an empty standalone extension. The
composition runner records this API difference instead of bypassing it.

## Composition evidence

Each case has a unique `id`, `base` (`literal` or `field`), nonempty `label`, and
ordered `parts`. Each part is `{ "type": ..., "text": ... }`: string, int32,
int64, uint64, or bytes (hex). Integers are decimal strings, never JSON numbers.
Every case encrypts and queries the string `hello` in the `text` field, using
the public all-zero deterministic-provider test seed.

`v1/contexts-native.json` is keyed by exactly those case IDs. It pins the
resolved context frame, the field context frame sent in a plan, descriptor,
AAD, PRF bytes, one Rust ciphertext and equality term. Rust checks actual descriptors sent to the key provider, fresh typed and
dynamic writes, queries, opens, and frozen ciphertexts. The typed chain calls
`extend` repeatedly, including a final no-op, so replacement behavior cannot
regress unnoticed.

Go observes the actual plan buffer at the `se_encrypt_record` WASM boundary
through a test-only function wrapper. It compares the field context in those
bytes with the frozen native plan-context frame, then opens the Rust ciphertext.
It compares fresh stored and query terms, both variadic and repeated extensions,
and generated `Note` (field base) and `LiteralNote` (literal base) methods.
Go does not expose a separate descriptor/AAD encoder: matching the actual plan
and successful authenticated cross-opening provide indirect evidence for those
observations. Native Rust checks the canonical descriptor/AAD/PRF bytes directly.
Ciphertext bytes are randomized and are not compared for equality.

Regenerate deliberately with `STACK_ENCRYPT_UPDATE_FIXTURES=1` and the native
`context_conformance` binary. Required conformance rejects fixture updates.
Changes to frozen context encodings require compatibility review.

## Expectations and boundaries

Boundary cases specify rows' `tenants`, the caller's `expected` label (the empty
string explicitly means no expectation in this corpus), a mutation of the last
stored row, an `outcome`, and `native_retrievals`. All properties are required;
null is not an alternative spelling for omission or the empty string.

Cases cover unrestricted reads, matching expectations, late mismatches, empty
batches, changed stored labels with and without matching expectations, and
missing/empty stored contexts late in a batch. A two-row ciphertext-tampering
case reaches AEAD after retrieval in both languages and returns no partial
plaintext. Typed Rust opening and generated Go opening exercise the boundary
cases too, except that an absent member cannot be represented by a generated Go
struct and is tested at the raw-tree boundary.

The separate `queries` array specifies a caller `context`, an `outcome` and
whether the query `matches` the stored term for `tenants/acme`. Missing and
invalid contexts refuse; another tenant produces a valid nonmatching query.
Rust typed query chains and generated Go query methods execute these cases.
Key-independent refusals must make no retrieval. An empty valid batch also makes none. Changing the stored
label does not confer permission to open the ciphertext even if the caller's
expectation matches the replacement label.

Native `CountingSource` checks exact data-key call counts. Its fake provider
does not authenticate descriptors, so a tampered context fails AEAD after one
retrieval. Go's deterministic provider authenticates the descriptor and refuses
the same tampering with `ErrForbidden`. An uninitialised Go checker separately
proves the key-free preflight boundary. This is not a claim that Go exposes
provider call counters.

The earlier read profile continues to cover context storage shape and exact
structured diagnostics. The enrolled `record-context-fields-v1` fixture
retains generated Go expectation, query, tampering and single-field update
checks and Rust typed/dynamic cross-opening. The required native `plan_grammar`
binary additionally covers missing caller bases, conflicting sources, invalid
labels, caller-derived queries and empty-batch validation before keyset loading.

## Future roles

This profile describes the current shared context: it feeds the data-key
descriptor, ciphertext AAD and index PRF context. It does not introduce separate
ciphertext-binding and search-scope contexts. That API design remains separate work;
any future split needs explicit compatibility rules and new profile coverage.
It also does not assert plaintext erasure in Go, Python or TypeScript heaps.
