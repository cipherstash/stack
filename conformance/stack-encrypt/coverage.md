# Coverage map

Snapshot: PR #1404 at `b684a217e`, including the JSON matching work through #1452.
This is an inventory of evidence, not a claim that every suite was rerun here.
Paths are relative to the repository root. New profile cases run from `v1/`.

| Requirement | Existing evidence | Remaining work |
|---|---|---|
| Scalar value widths and lossless transport | `packages/stack-encrypt/tests/value_kinds.rs`; `languages/golang/encrypt/value_kinds_test.go`; initial shared scalar cases | Expand shared cases to decimals, dates, timestamps, floats, bytes and all widths; Python/TS mappings |
| Owned opaque ciphertext and storage envelope | `packages/stack-encrypt/tests/scalar.rs`, `frozen_bytes.rs`; initial cross-opening cases | Blob profile; encoded targets; supported version matrix |
| Record declaration and lowering | [Declaration grammar](declaration-grammar.md); `v1/declarations.json` shared by native Rust and Go; native normalization observations; existing record lowering suites | EQL-resolver profile; SDK-to-declaration mappings; runtime source/read shapes |
| Context binding and composition | `packages/stack-encrypt/tests/target.rs`, `descriptor.rs`, `record_lowering.rs`; `languages/golang/encrypt/context_field_test.go`; initial wrong-context cases | Shared composition vectors; expected-context and required-input matrix |
| Query terms and diagnostics | `packages/stack-encrypt/tests/query_operators.rs`; `languages/golang/encrypt/query_test.go`; initial equality/query-error cases | Common rejection corpus for every operator, capability and input shape |
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

## Consolidation policy

Shared semantic expectations should be maintained once and executed by each
language runner. Conformance can replace duplicate case tables and fixture
maintenance. It does not eliminate the need to execute the Rust and Go paths.
No existing test has been deleted in these first two slices.

| Existing evidence | Relationship to conformance | Consolidation action |
|---|---|---|
| Rust `dynamic/record.rs` tests `a_malformed_plan`, `a_null_is_refused_as_its_key`, `a_missing_or_null_index_payload_is_the_default` | Many inputs and diagnostic outcomes are now shared declaration cases | Move the remaining cases and retain any unique display/low-level assertions before removing duplicate rows |
| Rust kind/index admission tests | The corpus has the complete 21-kind/five-index acceptance matrix | Share case data; retain direct tests that compare declaration admission with actual term execution |
| Rust `value_kinds.rs`, Go `value_kinds_test.go` | Already share `value_kinds.json`; cover more types and generated SDK code than the initial scalar profile | Enroll that existing fixture under named requirements instead of copying it; keep generated-code assertions |
| Rust `query_operators.rs`, Go `query_test.go` | Already share operator vectors, including verification and target limits | Reuse their fixture and cases when adding an operator profile; preserve host/generated query mapping tests |
| Go checker and host validation tests in `guest_test.go` | Exercise host rejection and diagnostic forwarding through public checker methods | Keep adapter-specific assertions; raw-frame conformance bypasses host validation deliberately |
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
