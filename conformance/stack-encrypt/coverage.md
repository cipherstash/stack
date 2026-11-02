# Coverage map

Snapshot: PR #1404 at `b684a217e`, including the JSON matching work through #1452.
This is an inventory of evidence, not a claim that every suite was rerun here.
Paths are relative to the repository root. New profile cases run from `v1/`.

| Requirement | Existing evidence | Remaining work |
|---|---|---|
| Scalar value widths and lossless transport | Initial scalar cases, [value-kind requirements](fixture-contract.md#value-kind-requirements) and the [value boundary profile](values-contract.md) (`v1/record-values-v1.cases.json`: every kind's edges, float specials, bytes, decimal and timestamp precision, sealed/SQL nulls per kind, cross-kind write refusals, Go host conversions); every positive case written fresh by each runner and opened by the other ([exchange profile](exchange-contract.md)) | Python/TS mappings; dates before year 1 and the timestamp range ends |
| Owned opaque ciphertext and storage envelope | `packages/stack-encrypt/tests/scalar.rs`, `frozen_bytes.rs`; initial cross-opening cases. Whole-value blobs: `packages/stack-encrypt/tests/opaque_blob.rs` (round trips, the bytes leaf shared with the structural writer, a pinned storage blob and a pinned sealed ciphertext, refusals by class after authentication, source wipe) and `languages/golang/encrypt/gensupport/gensupport_internal_test.go::TestOpaqueReadsARustWrittenBlob`; the storage profile itself is pinned upstream by Vitamin C's golden corpus; fresh sealed blobs exchanged in both directions by the [exchange profile](exchange-contract.md) | Encoded targets; supported version matrix |
| Record declaration and lowering | [Declaration grammar](declaration-grammar.md); `v1/record-declarations-v1.cases.json` shared by native Rust and Go; native normalization observations; existing record lowering suites | EQL-resolver profile; SDK-to-declaration mappings; runtime source/read shapes |
| Context binding and composition | `packages/stack-encrypt/tests/target.rs`, `descriptor.rs`, `record_lowering.rs`; `languages/golang/encrypt/context_field_test.go`; initial wrong-context cases | Shared composition vectors; expected-context and required-input matrix |
| Query terms and diagnostics | [Query-operator requirements](fixture-contract.md#query-operator-requirements), existing Rust/Go runners, initial equality/query-error cases and the [query-refusal profile](query-refusals-contract.md) (`v1/record-query-refusals-v1.cases.json`: every scalar operator against every field capability that does not answer it, the listed range shapes, other-kind values and nulls, by class, with the typed chain's refusal stage) | JSON operator and EQL target refusals; moving the typed chain's value refusals before the keyset |
| Missing, SQL NULL and sealed null | `packages/stack-encrypt/src/dynamic/record.rs` null tests; `languages/golang/encrypt/null_test.go` | Explicit language mappings and common missing/null fixtures |
| Fresh cross-language storage | `.github/workflows/tests-golang.yml` exports fresh Go EQL rows for Rust; initial scalar artifact exchange; fixed storage-blob vectors read by both Rust (`opaque_blob.rs`) and Go (`TestOpaqueReadsARustWrittenBlob`); the [exchange profile](exchange-contract.md): values, records, blobs and EQL rows written fresh and opened in both Rust/Go directions, with producer, engine, backend and storage versions in the report | Python/TypeScript pairs and backends when their runners exist; supported released versions once the compatibility policy is defined; fresh JSON document exchange; a SQL lane storing one language's fresh rows through the other |
| JSON queries, extraction and tampering | `packages/stack-encrypt/tests/json_tree_vectors.rs`; `packages/eql/tests/encryption/tests/json_tree.rs`; `languages/golang/encrypt/json_tree_test.go`, `json_postgres_test.go` | Formal operation profile; JSON vectors consumed by all runners |
| Element and predicate matching | Go `json_elements_test.go`, `json_match_test.go` and corresponding PostgreSQL tests; Rust/SQL predicate suites | Map exact supported grammar and documented semantic differences to case IDs |
| Generated SDK declarations | Go stashgen and generated-code fixture tests | Python and TypeScript public-API runners; compiler/type-checker cases |
| Validation before key I/O and batching | Rust `tests/common::CountingSource` and record/query tests; guest preflight tests | Requirement-by-requirement coverage; common provider observations |
| Binding lifecycle and cleanup | `packages/stack-guest-abi`; Go `cancel_test.go`, `step_test.go`, guest memory tests | Native Python/TS and WASM backend-specific matrices; no blanket host-erasure claim |
| Version/capability negotiation | Existing ABI status table and target/operator discovery | Normative supported-version rules; reject unknown required capabilities |

Python and future TypeScript runners have no evidence in this checkout. Their
absence is a delivery gap, not a test skip that counts toward certification.

## Runtime checkpoint

`v1/record-runtime-v1.cases.json` adds shared cases for typed writes and reads, null storage,
batches, equality queries and lossless numeric conversion. See the
[runtime contract](runtime-contract.md) for exact observations and limits.
Native data-key counters cover zero-call preflight failures and single-call
batches; Go provider-call instrumentation remains open.

| Existing evidence | Shared case IDs | Retained assertions |
|---|---|---|
| Native SQL-null record tests | `sql-missing`, `sql-null`, `sql-mixed-batch`, `sql-all-absent` | Wider declarations and malformed stored-record behavior |
| Native sealed-null padding/equality tests | `sealed-mixed-batch`, `sealed-int64`, `sealed-uint64`, `sealed-float64` | Other integer widths, bool ciphertext, dates, timestamps and decimals |
| Go generated `null_test.go` | Same sealed/SQL semantics | Pointer mapping, generated methods, EQL envelopes, reading null into nonpointer fields |
| Native source validation tests | `late-wrong-type`, `late-missing`, `unknown-field` | Repeated keys, unsupported frame shapes and more output kinds |
| Existing shared value-kind/operator fixtures | Runtime query cases cover selected conversion edges | Full type/operator matrices, generated SDK calls and verification |

## Read checkpoint

`v1/record-reads-v1.cases.json` adds cases for stored-shape validation, authenticated types
and context preflight. The [read contract](read-contract.md) distinguishes native
shape/pending stages and the guest's earlier `check_record` diagnostics. Native
data-key counters and Go's uninitialised guest verify preflight boundaries.

| Existing evidence | Shared case IDs | Retained assertions |
|---|---|---|
| Native `a_stored_record_that_does_not_fit` | `missing-field`, `missing-ciphertext`, `field-not-map`, `plaintext-under-c`, `row-not-map`, `late-missing-field` | Repeated keys, other passthrough fields and output kinds |
| Native typed read/null tests | `authenticated-int32-as-*`, `authenticated-null-as-required`, `authenticated-null-as-sql`, `sql-absent-*` | Wider types and declaration combinations |
| Go `context_field_test.go`, native context tests | `context-unrestricted`, `context-expected`, `context-mismatch`, `context-late-mismatch`, `context-drop-tenant`, `context-tenant-*` | Generated APIs, queries, extension composition and stored-context tampering |
| Native and guest context-source validation | `static-context-with-expectation` | Other source combinations and empty-batch behavior |

These are overlap mappings, not grounds for deleting whole mixed-purpose tests.
Repeated-key trees cannot be emitted by Go's map-based tree encoder; the
[raw-frame profile](raw-frames-contract.md) covers that boundary with
transport bytes both runners decode.

## Consolidation policy

The value-kind/query-operator enrollment adds named requirements for the
existing fixtures through [the enrollment index](v1/fixture-enrollment.json).
The conformance command selects their original runners; CI guards the mapping
and selection. Typed Rust comparisons, generated Go methods, verification and
fetch-limit checks stay in those runners. No fixture is copied and no existing
assertion is removed. Shared negative cases and fresh exchange of the wider
value kinds remain open.

Shared semantic expectations should be maintained once and executed by each
language runner. Conformance can replace duplicate case tables and fixture
maintenance. It does not eliminate the need to execute the Rust and Go paths.
No existing test has been deleted by conformance enrollment.

| Existing evidence | Relationship to conformance | Consolidation action |
|---|---|---|
| Rust `dynamic/record.rs` tests `a_malformed_plan`, `a_null_is_refused_as_its_key`, `a_missing_or_null_index_payload_is_the_default` | Many inputs and diagnostic outcomes are now shared declaration cases | Move the remaining cases and retain any unique display/low-level assertions before removing duplicate rows |
| Rust kind/index admission tests | The corpus has the complete 21-kind/five-index acceptance matrix | Share case data; retain direct tests that compare declaration admission with actual term execution |
| Rust `value_kinds.rs`, Go `value_kinds_test.go` | Enrolled as `record-value-kinds-v1`, retaining the shared fixture and generated SDK calls | Extend the existing fixture/requirements for missing boundaries; retain typed and generated-code assertions |
| Rust `query_operators.rs`, Go `query_test.go` | Enrolled as `record-query-operators-v1`, including verification and target limits | Add shared refusal cases separately; retain host/generated query mapping tests |
| Go checker and host validation tests in `guest_test.go` | Exercise host rejection and diagnostic forwarding through public checker methods | Keep adapter-specific assertions; representable declaration cases also use `Checker.Check`, while raw frames observe the guest boundary |
| Native scalar/record round trips and cross-opening | Some behavior overlaps, but existing tests cover more types and API paths | Replace only exact duplicates after matching requirements and execution paths |

Keep Rust compile-fail, ownership/zeroization, batching, fuzz/property, and
implementation regression tests. Keep Go generation, host type conversion,
error wrapping, cancellation and guest lifecycle tests. Keep independent
PostgreSQL oracles and live-provider tests. These observe guarantees a shared
engine corpus cannot prove by itself.

For each removal, link the old assertion to stable case IDs, compare coverage
and failure behavior, and run both runners in CI. Preserve unrelated assertions
from mixed tests. Enroll Python and TypeScript against the existing corpus so
adding a language does not create another copy of the expected behavior.

## Context checkpoint

The [context contract](context-contract.md) adds 18 shared composition cases and
eleven shared read boundary cases and four query cases, plus enrollment of the
existing record-lowering
context-field fixture. Rust typed write/query/open chains and Go generated
methods execute the composition cases. Required native plan-grammar tests cover
caller-provided bases and empty-batch source validation. Existing context tests
remain: no mixed-purpose Rust or Go test is removed.

Go proves canonical AAD indirectly through its actual guest plan frame and native
ciphertext opening; provider-call instrumentation remains a separate gap.
Nested composite extensions remain a native API capability rather than an
unsupported feature silently advertised by the Go/dynamic record profile.

## EQL/JSON checkpoint

The [EQL/JSON contract](eql-json-contract.md) and its enrollment index cover
resolver/catalog capabilities, JSON writes and queries, request-bound reads,
element-match and predicate-match. Existing Rust, Go and PostgreSQL suites stay
in place. The common document and predicate-refusal tables now live in
`v1/eql-json-v1.cases.json`: Rust and Go execute them, retaining native key-call checks,
Go diagnostic mapping and all extra cases from the original suites.

The database lane preserves independent plaintext oracles and generated
properties. Required test inventory/no-skip checks and engine/guest/SQL identity
reports make enrollment observable. This consolidates data and requirements;
it does not replace adapter tests or claim whole-database authentication.
Fresh JSON artifact exchange, released-version matrices and Python/TypeScript
runners remain open; the scalar EQL rows are exchanged fresh in both
directions by the exchange profile.

## Value, refusal and raw-frame checkpoint

Three shared corpora close the boundary gaps the representative profiles
left: `v1/record-values-v1.cases.json` (the [value contract](values-contract.md)),
`v1/record-query-refusals-v1.cases.json` (the [query-refusal contract](query-refusals-contract.md))
and `v1/record-raw-frames-v1.cases.json` (the [raw-frame contract](raw-frames-contract.md)).
Each runs in native Rust and Go WASI under `test:conformance`.

| Existing evidence | Shared case IDs | Retained assertions |
|---|---|---|
| `value_kinds.json` and its runners | `i8-*`, `u8-*`, `i16-*`, `u16-*`, `u32-*`, `i128-*`, `u128-*`, `f32-*`, `f64-*`, `bytes-*`, `decimal-*`, `date-*`, `timestamp-*`, `sealed-*`, `sql-*`, `*-given-*` | Typed Rust term comparisons and generated Go methods |
| Native `dynamic/query.rs` refusal tests, Go `TestAQueryTheFieldDoesNotAnswerIsRefused` | Every `record-query-refusals-v1` case | Tree-notation inputs, the hand-built match options, generated query methods |
| Native typed refusal tests in `tests/op.rs` | The `typed` entries | Case-sensitivity mismatch, batch and `via` forms, which the API plan removes (its step 3) |
| Native `a_stored_record_that_does_not_fit`, the read profile | `shape-*`, `authenticated-*`, `success-*` | Mutation vocabulary over real ciphertext |
| Guest `test_frame` and `last_error` tests | `transport-*`, `leaf-*` | Plan-frame boundary cases, ABI status mapping |

Unsupported combinations the corpora record rather than skip: the order
index on `bytes` stores a term no operator reads; the typed chain refuses
equality, order and block ORE value refusals only after its keyset loads,
where the binding refuses before any; a repeated key in a stored record is
a transport refusal in both decoders, and the engine's own `field_repeated`
and `repeated_key` guards are reached natively alone; the Go host refuses
the zero `Date`, a decimal scale above 28, a timestamp outside the
decoder's range and non-value Go types before the engine. `NaN` and
negative-zero decimals are excluded as host-dependent.

## Lifecycle checkpoint

The [lifecycle contract](lifecycle-contract.md) enrolls native pending/KMS tests,
heap observations, guest ABI cleanup, Go cancellation/memory tests and public SDK
diagnostics. New probes cover unpolled and in-flight drops, provider failure,
cleanup after a late authenticated type failure, and chunk concurrency/drop.
The owned `Vec<S>` to `Vec<T>` conversion is enrolled under the same
requirements. The conversion's tests cover:

- dropping a collection before it is polled
- dropping a collection while its key request is running
- one logical batch of key requests for each collection, and none for an
  empty collection
- wiping the source `Vec` through its guard
- wiping the elements already decrypted, when a later element fails

The owned conversion is a native Rust API. Go reaches batching through its
record interface, and the runtime profile covers that interface.
Existing runtime/read/context vectors retain their provider-call counters.

This adds required execution and explicit observation limits; it removes no
backend-specific tests. The known Go post-decryption shadow-stack gap and native
heap-observer exclusions stay visible in reports. Logical batching is distinct
from downstream chunking and unobserved live HTTP behavior. Python and TypeScript
lifecycle evidence is pending.

## Exchange checkpoint

The [exchange contract](exchange-contract.md) defines `artifact-exchange-v1`
over `v1/exchange.json`: in one run and a fresh directory, Rust writes and Go
opens, and Go writes and Rust opens, every positive value-boundary case, a
structural record with a passthrough field and equality/order terms, three
opaque blobs and the EQL v4 `profiles` rows. Consumers compare decrypted
values and their own derived query terms; ciphertext bytes are never
compared. The task fails on a missing runner or guest and on an empty fresh
output, and its report records producer SDKs, engines, backends, guests,
lockfiles and storage versions, with a placeholder for released-version
combinations. No frozen artifact changes.

| Direction | Kinds | Consumer evidence |
|---|---|---|
| Go to Rust | `values`, `record`, `blobs`, `eql-rows` | `fresh_artifact_exchange` (`STACK_EXCHANGE_INPUT`), `rows_the_go_sdk_sealed_open_in_rust` (`EQL_V4_ROWS`) |
| Rust to Go | `values`, `record`, `blobs`, `eql-rows` | `TestArtifactExchange` (`STACK_EXCHANGE_INPUT`), `TestV4RowsTheRustSuiteSealedOpenInGo` (`EQL_V4_RUST_ROWS`) |
| Python, TypeScript | none | No runner exists; reported as not enrolled |

Open: fresh JSON document exchange, the remaining EQL types, a SQL lane
that stores one language's fresh rows through the other, and the
released-version rows once the compatibility policy is defined.
