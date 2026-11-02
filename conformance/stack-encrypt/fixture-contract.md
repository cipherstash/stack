# Enrolled fixture profiles

`record-value-kinds-v1`, `record-query-operators-v1` and
`record-context-fields-v1` enroll the existing
Rust/Go fixtures in the conformance contract. They are experimental profiles
of the cases those fixtures contain, not exhaustive type/operator certification.
They use the plain record resolver (`NoTargets`), with public deterministic
keys and no database or live credentials.

The fixtures remain at their existing paths:

- [`value_kinds.json`](../../packages/stack-encrypt/tests/fixtures/value_kinds.json)
- [`query_operators.json`](../../packages/stack-encrypt/tests/fixtures/query_operators.json)

Their [existing schema documentation](../../packages/stack-encrypt/tests/fixtures/README.md)
continues to own the formats. No expected frames, ciphertexts, terms, verified
pages or fetch limits are copied into this directory.

[`v1/fixture-profiles.json`](v1/fixture-profiles.json) maps stable requirement IDs
to the existing Rust test functions and Go tests that provide their evidence.
It is an enrollment index, not another input corpus or a runtime capability
negotiation format. The CI wiring test checks fixture paths, source declarations,
requirement documentation and exact command selection. Rust also checks each
binary’s compiled test inventory and rejects missing or ignored enrolled tests.
The Go missing-guest regression checks each indexed test’s actual failure/skip
outcome, so a test excluded from compilation cannot silently pass enrollment.
Both language implementations are mandatory for these profiles; Python and TypeScript remain pending.

## Value-kind requirements

The fixture represents int8, int16, uint8, uint16, int128, uint128, date,
timestamp and decimal values. It includes the signed 128-bit minimum and
unsigned 128-bit maximum. These are representative cases, not every boundary
of every type. Values use the fixture's `type` and `text` with a frozen `frame`;
128-bit integers must never pass through a floating-point JSON number.

| Requirement ID | Required observation | Fixture evidence |
|---|---|---|
| `values.typed-frames` | The actual host value encodes to the exact frozen typed frame, preserving integer width, decimal scale and timestamp nanoseconds. | Every `values` entry |
| `values.frozen-open` | The committed Rust record opens to those values and types, retaining decimal scale and timestamp precision. | `record` and `values` |
| `values.stored-terms` | Fresh records round-trip and store the frozen equality/order terms. Queries for their values derive the corresponding stored terms. Randomized ciphertext bytes are not compared. | Every non-`c` output in `record`, under `plan` |
| `values.normalized-queries` | Decimal queries differing only in trailing zeros and timestamp queries truncated to microseconds derive the stored equality and order terms, while the opened values retain their original precision. | Every `queries` entry and its field's order output |

Rust additionally compares dynamic execution with typed term derivation and
retains its wrong-width write refusal test. Go runs the real generated
`testusers.ValueKinds` encrypt/decrypt and field-query methods, including its
field-context substitution refusal. These assertions stay in their owning
tests. The separate Go invalid-date/decimal/timestamp tests remain in the full
Go suite; they are not claimed as shared fixture requirements here.

## Query-operator requirements

The fixture covers equality on text and uint32, scalar/range ordering on uint32
and float64, and probabilistic text matching. Its operators are `eq`, `lt`,
`lte`, `gt`, `gte`, `between` and `matches`, in the combinations declared by
the fixture. It does not claim every operator for every kind or index.

| Requirement ID | Required observation | Fixture evidence |
|---|---|---|
| `queries.term-contract` | Derive the frozen operand bytes and metadata: operator, fidelity, index, domain, and scalar versus ordered low/high range shape. | Every `queries` entry |
| `queries.match-verification` | Verify the complete page in input order, including matches, nonmatches and null; results agree with the frozen boolean vector. | `verify` |
| `queries.fetch-limits` | Given the frozen match term, requested count and statistics, return the recorded bounded row count or explicit unbounded result. | Every `target_limit` entry |

Rust compares the dynamic path with typed query chains, `MatchQuery::verify`
and typed fetch sizing, and checks that the fixture contains both verification
outcomes and both bounded/unbounded limits. Go exercises the record interface
and generated query methods. Generated string-page verification omits null,
which the record-interface test covers. Its existing SQL parameter conversion,
empty-page, zero-query, inverted-range and floating-point ordering assertions
remain in those selected tests. Wider operator refusal and secret-diagnostic
tests remain in the full suites; this slice does not turn them into shared
negative cases. In Go, `TestVerifyAndTargetLimitRefuseWhatIsNotAMatchQuery` and
`TestAMatchesQueryNeverPrintsItsText` share the fixture client, so they also
fail on a missing guest in required mode. They remain outside the aggregate
selection and the shared requirements; the missing-guest regression covers them.

## Running and maintaining the profiles

`mise run test:conformance` selects the existing `value_kinds` and
`query_operators` Rust binaries and the Go tests listed in the enrollment index,
alongside the earlier profiles. The Go selection is generated from the index;
adding an enrolled Go test does not require editing a shell regular expression.
Fixture assertions stay in their owning tests; the separate missing-guest probes
stop at client creation. The ordinary Rust and Go
CI suites already run these tests, so enrollment adds no duplicate CI suite.

When `STACK_CONFORMANCE_REQUIRED=1`, a missing deterministic guest fails the
enrolled Go tests instead of skipping them. The aggregate command rejects both
`STACK_CONFORMANCE_UPDATE` and `STACK_ENCRYPT_UPDATE_FIXTURES`, even when set to
an empty value. All four Rust fixture writers, including the two record-lowering
writers,
independently reject updates in required mode. A subprocess regression exercises
the guard with absent, empty and nonempty update flags without writing fixtures.
Deliberate fixture maintenance remains available outside
required mode through the existing documented regeneration commands.

Keep requirement IDs stable. Add a new profile version for incompatible
expectations, and review fixture regeneration explicitly. The enrollment
index's `version` is its metadata format, not a production storage version.

This slice consolidates the coverage inventory and execution selection, not
the underlying test assertions. No test or frozen artifact is removed. Fresh
cross-language artifact exchange remains the scalar profile's guarantee;
these wider fixtures prove frozen Rust-to-Go opening, local round trips and
term agreement, not fresh Go-to-Rust opening of every represented kind.

Python and TypeScript should consume these same fixture paths and implement
the listed observations through their own host values and public APIs. Their
integer/decimal/time mappings and actual backends must be specified by those
implementations. EQL domains, JSON operations, all-type boundary matrices,
shared query refusals and supported-release matrices remain separate work.

## Context-field requirements

`record-context-fields-v1` enrolls the context-field section of the existing
`record_lowering.json` fixture. Its format and seed remain owned by that fixture.
The [context contract](context-contract.md) adds composition and boundary cases
without copying these existing vectors.

| Requirement ID | Required observation | Fixture evidence |
|---|---|---|
| `contexts.frozen-open` | Typed and lowered Rust records open through the opposite path and generated Go methods, under their stored context. | `context_field.records` |
| `contexts.expectations` | An expectation checks the stored context; a mismatch refuses it. Generated Go queries name the base context, and tampering does not open. | Fresh records and `context_field` plan |
