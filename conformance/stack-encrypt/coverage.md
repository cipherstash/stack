# Coverage map

Snapshot: PR #1404 at `b684a217e`, including the JSON matching work through #1452.
This is an inventory of evidence, not a claim that every suite was rerun here.
Paths are relative to the repository root. New profile cases run from `v1/`.

| Requirement | Existing evidence | Remaining work |
|---|---|---|
| Scalar value widths and lossless transport | Initial scalar cases and [value-kind requirements](fixture-contract.md#value-kind-requirements), executed by the existing Rust and generated Go runners | Complete per-kind boundary matrices, bytes and broader floats; Python/TS mappings |
| Owned opaque ciphertext and storage envelope | `packages/stack-encrypt/tests/scalar.rs`, `frozen_bytes.rs`; initial cross-opening cases | Blob profile; encoded targets; supported version matrix |
| Record declaration and lowering | [Declaration grammar](declaration-grammar.md); `v1/declarations.json` shared by native Rust and Go; native normalization observations; existing record lowering suites | EQL-resolver profile; SDK-to-declaration mappings; runtime source/read shapes |
| Context binding and composition | `packages/stack-encrypt/tests/target.rs`, `descriptor.rs`, `record_lowering.rs`; `languages/golang/encrypt/context_field_test.go`; initial wrong-context cases | Shared composition vectors; expected-context and required-input matrix |
| Query terms and diagnostics | [Query-operator requirements](fixture-contract.md#query-operator-requirements), existing Rust/Go runners and initial equality/query-error cases | Common rejection corpus for every operator, capability and input shape; wider kind/index combinations |
| Missing, SQL NULL and sealed null | `packages/stack-encrypt/src/dynamic/record.rs` null tests; `languages/golang/encrypt/null_test.go` | Explicit language mappings and common missing/null fixtures |
| Fresh cross-language storage | `.github/workflows/tests-golang.yml` exports fresh Go EQL rows for Rust; initial scalar artifact exchange | Every producer/consumer/backend pair and supported released versions |
| JSON queries, extraction and tampering | `packages/stack-encrypt/tests/json_tree_vectors.rs`; `packages/eql/tests/encryption/tests/json_tree.rs`; `languages/golang/encrypt/json_tree_test.go`, `json_postgres_test.go` | Formal operation profile; JSON vectors consumed by all runners |
| Element and predicate matching | Go `json_elements_test.go`, `json_match_test.go` and corresponding PostgreSQL tests; Rust/SQL predicate suites | Map exact supported grammar and documented semantic differences to case IDs |
| Generated SDK declarations | Go stashgen and generated-code fixture tests | Python and TypeScript public-API runners; compiler/type-checker cases |
| Validation before key I/O and batching | Rust `tests/common::CountingSource` and record/query tests; guest preflight tests | Requirement-by-requirement coverage; common provider observations |
| Binding lifecycle and cleanup | `packages/stack-guest-abi`; Go `cancel_test.go`, `step_test.go`, guest memory tests | Native Python/TS and WASM backend-specific matrices; no blanket host-erasure claim |
| Version/capability negotiation | Existing ABI status table and target/operator discovery | Normative supported-version rules; reject unknown required capabilities |

Python and future TypeScript runners have no evidence in this checkout. Their
absence is a delivery gap, not a test skip that counts toward certification.

## Runtime checkpoint

`v1/runtime.json` adds shared cases for typed writes and reads, null storage,
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

`v1/reads.json` adds cases for stored-shape validation, authenticated types
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
Repeated-key trees cannot be emitted by Go's map-based tree encoder; a future
raw-byte profile must cover that boundary explicitly.

## Consolidation policy

The value-kind/query-operator enrollment adds named requirements for the
existing fixtures through [the enrollment index](v1/fixture-profiles.json).
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
