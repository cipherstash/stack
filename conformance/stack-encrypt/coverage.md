# Coverage map

Snapshot: PR #1404 at `b684a217e`, including the JSON matching work through #1452.
This is an inventory of evidence, not a claim that every suite was rerun here.
Paths are relative to the repository root. New profile cases run from `v1/`.

| Requirement | Existing evidence | Remaining work |
|---|---|---|
| Scalar value widths and lossless transport | `packages/stack-encrypt/tests/value_kinds.rs`; `languages/golang/encrypt/value_kinds_test.go`; initial shared scalar cases | Expand shared cases to decimals, dates, timestamps, floats, bytes and all widths; Python/TS mappings |
| Owned opaque ciphertext and storage envelope | `packages/stack-encrypt/tests/scalar.rs`, `frozen_bytes.rs`; initial cross-opening cases | Blob profile; encoded targets; supported version matrix |
| Record declaration and lowering | `packages/stack-encrypt/tests/record_lowering.rs`; `languages/golang/encrypt/fixture_test.go` | Normative grammar, normalization, accepted/rejected definition corpus |
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
