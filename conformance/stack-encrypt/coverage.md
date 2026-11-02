# Coverage map

Snapshot: PR #1404 at `b684a217e`, including the JSON matching work through #1452.
This is an inventory of evidence, not a claim that every suite was rerun here.
Paths are relative to the repository root. New profile cases run from `v1/`.

| Requirement | Existing evidence | Remaining work |
|---|---|---|
| Scalar value widths and lossless transport | Initial scalar cases, [value-kind requirements](fixture-contract.md#value-kind-requirements) and the [value boundary profile](values-contract.md) (`v1/values.json`: every kind's edges, float specials, bytes, decimal and timestamp precision, sealed/SQL nulls per kind, cross-kind write refusals, Go host conversions) | Fresh exchange of every kind; Python/TS mappings; dates before year 1 and the timestamp range ends |
| Owned opaque ciphertext and storage envelope | `packages/stack-encrypt/tests/scalar.rs`, `frozen_bytes.rs`; initial cross-opening cases. Whole-value blobs: `packages/stack-encrypt/tests/opaque_blob.rs` (round trips, the bytes leaf shared with the structural writer, a pinned storage blob and a pinned sealed ciphertext, refusals by class after authentication, source wipe) and `languages/golang/encrypt/gensupport/gensupport_internal_test.go::TestOpaqueReadsARustWrittenBlob`; the storage profile itself is pinned upstream by Vitamin C's golden corpus | Encoded targets; supported version matrix; a fresh sealed exchange of a blob with Go (Go seals, Rust opens, and back) through the conformance task |
| Record declaration and lowering | [Declaration grammar](declaration-grammar.md); `v1/declarations.json` shared by native Rust and Go; native normalization observations; existing record lowering suites | EQL-resolver profile; SDK-to-declaration mappings; runtime source/read shapes |
| Context binding and composition | `packages/stack-encrypt/tests/target.rs`, `descriptor.rs`, `record_lowering.rs`; `languages/golang/encrypt/context_field_test.go`; initial wrong-context cases | Shared composition vectors; expected-context and required-input matrix |
| Query terms and diagnostics | [Query-operator requirements](fixture-contract.md#query-operator-requirements), existing Rust/Go runners, initial equality/query-error cases and the [query-refusal profile](query-refusals-contract.md) (`v1/query-refusals.json`: every scalar operator against every field capability that does not answer it, the listed range shapes, other-kind values and nulls, by class, with the typed chain's refusal stage) | JSON operator and EQL target refusals; moving the typed chain's value refusals before the keyset |
| Missing, SQL NULL and sealed null | `packages/stack-encrypt/src/dynamic/record.rs` null tests; `languages/golang/encrypt/null_test.go` | Explicit language mappings and common missing/null fixtures |
| Fresh cross-language storage | `.github/workflows/tests-golang.yml` exports fresh Go EQL rows for Rust; initial scalar artifact exchange; fixed storage-blob vectors read by both Rust (`opaque_blob.rs`) and Go (`TestOpaqueReadsARustWrittenBlob`) | Every producer/consumer/backend pair and supported released versions; fresh sealed blob exchange |
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
Repeated-key trees cannot be emitted by Go's map-based tree encoder; the
[raw-frame profile](raw-frames-contract.md) covers that boundary with
transport bytes both runners decode.

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
Enrollment alone deleted no test; the [consolidations](#consolidations) below
record each duplicate table that was later removed, with the shared cases
and the fault evidence that replaced it.

| Existing evidence | Relationship to conformance | Consolidation action |
|---|---|---|
| Rust `dynamic/record.rs` plan-refusal tests | Their inputs and diagnostic outcomes are shared declaration cases | Removed; the message naming its field stays in `a_plan_refusal_names_its_field_in_the_message` (see [consolidations](#consolidations)) |
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
`v1/eql-json.json`: Rust and Go execute them, retaining native key-call checks,
Go diagnostic mapping and all extra cases from the original suites.

The database lane preserves independent plaintext oracles and generated
properties. Required test inventory/no-skip checks and engine/guest/SQL identity
reports make enrollment observable. This consolidates data and requirements;
it does not replace adapter tests or claim whole-database authentication.
Fresh JSON artifact exchange, released-version matrices and Python/TypeScript
runners remain open.

## Value, refusal and raw-frame checkpoint

Three shared corpora close the boundary gaps the representative profiles
left: `v1/values.json` (the [value contract](values-contract.md)),
`v1/query-refusals.json` (the [query-refusal contract](query-refusals-contract.md))
and `v1/raw-frames.json` (the [raw-frame contract](raw-frames-contract.md)).
Each runs in native Rust and Go WASI under `test:conformance`.

| Existing evidence | Shared case IDs | Retained assertions |
|---|---|---|
| `value_kinds.json` and its runners | `i8-*`, `u8-*`, `i16-*`, `u16-*`, `u32-*`, `i128-*`, `u128-*`, `f32-*`, `f64-*`, `bytes-*`, `decimal-*`, `date-*`, `timestamp-*`, `sealed-*`, `sql-*`, `*-given-*` | Typed Rust term comparisons and generated Go methods |
| Native `dynamic/query.rs` refusal tests, Go `TestVerifyAndTargetLimitRefuseWhatIsNotAMatchQuery` | Every `record-query-refusals-v1` case | Tree-notation inputs, the hand-built match options, generated query methods |
| Native typed refusal tests in `tests/op.rs` | The `typed` entries | Case-sensitivity mismatch, batch and `via` forms |
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
Existing runtime/read/context vectors retain their provider-call counters.

This adds required execution and explicit observation limits; it removes no
backend-specific tests. The known Go post-decryption shadow-stack gap and native
heap-observer exclusions stay visible in reports. Logical batching is distinct
from downstream chunking and unobserved live HTTP behavior. Python and TypeScript
lifecycle evidence is pending.

## Consolidations

Each row is one old assertion table whose literal expectations are now held
by a shared corpus and executed by both language runners. A row was removed
only after a fault was introduced by hand into the engine and the named
replacement runner failed on it under `STACK_CONFORMANCE_REQUIRED=1`; the
fault was then reverted. "Fails on" names the fault and the case the runner
reported. Where an old table mixed shared rows with shapes the corpus cannot
spell, only the shared rows were removed and the test's doc comment says what
stays. Every shared case in these rows runs natively through the Rust binary
named and through the Go guest (`TestDeclarationConformance` on both guests,
`TestRuntimeConformance`, `TestReadConformance`, `TestQueryRefusalConformance`).

Five cases were enrolled so the old rows had a one-to-one home rather than a
neighbour: `output-not-string`, `passthrough-with-index` and `target-number`
in `v1/declarations.json`; `ore-block-between-long-low` and
`ore-block-between-nul-high` in `v1/query-refusals.json`.

| Old test (file) | Shared case IDs | Replacement runner | Fails on |
|---|---|---|---|
| `every_refusal_names_its_field_and_reason::a_malformed_plan` (`src/dynamic/record.rs`), 24 rows, removed; its check that the message names the field stays in `a_plan_refusal_names_its_field_in_the_message`, since the corpus compares payloads, not messages | `root-null`, `root-list`, `empty-plan`, `field-not-object`, `unknown-key`, `frame-duplicate-key` (a field given twice; the frame refuses a repeated key before the plan is read, and a key repeated inside a spec stays in the kept `a type given twice` and `a context_field key given twice` rows), `missing-context`, `missing-outputs`, `outputs-with-target`, `outputs-string`, `output-unknown`, `outputs-empty`, `output-duplicate`, `passthrough-with-ciphertext`, `target-number`, `type-unknown`, `type-uint32-match`, `type-bool-ore`, `context-bare-label`, `context-bool`, `mixed-prefix`, `shared-identity`, `context-empty` | `declarations::shared_declaration_grammar` | `missing_context` reported as `unknown_key`: `missing-context`; a label refusal reported as another reason: `context-bare-label`, `context-one-segment`, `context-segment-*`, `context-nested-extension`, `context-field-static-label` |
| `every_refusal_names_its_field_and_reason::a_null_is_refused_as_its_key` (`record.rs`), 6 rows, removed; the message check stays as above | `context-null`, `outputs-null`, `target-null`, `type-null`, `context-field-null`, `field-null` | `declarations::shared_declaration_grammar` | `present` reading a null as an absent key: `outputs-null`, `target-null`, `target-options-null`, `type-null`, `null-mode-null` |
| `every_refusal_names_its_field_and_reason::a_missing_or_null_index_payload_is_the_default` (`record.rs`), removed | `match-default-bare`, `match-default-null`, `match-default-empty`, `unit-output-null-eq` | `declarations::shared_declaration_grammar` (normalization) | a non-default option substituted for a missing match payload: `match-default-bare`, `match-default-null` |
| `given_a_plan_value::refuses_a_malformed_plan_before_any_field_is_built` (`record.rs`), 17 rows, removed | `root-null`, `empty-plan`, `field-not-object`, `unknown-key`, `missing-context`, `missing-outputs`, `outputs-empty`, `output-not-string`, `output-unknown`, `output-duplicate`, `passthrough-with-ciphertext`, `passthrough-with-index`, `frame-duplicate-key`, `context-bool`, `context-empty` | `declarations::shared_declaration_grammar` | as the first row; the old rows asserted the error variant alone, the corpus asserts code, reason and field |
| `given_a_plan_value::refuses_a_field_context_that_is_not_a_label` (`record.rs`), 6 of 9 rows removed; the integer, bytes and extended one-segment shapes stay | `context-bare-label`, `context-one-segment`, `context-segment-slash`, `context-segment-digit`, `context-nested-extension` | `declarations::shared_declaration_grammar` | a label refusal reported as another reason: every `context_not_label` case |
| `every_refusal_names_its_field_and_reason::a_source_that_does_not_fit` (`record.rs`), 3 of 9 rows removed; the passthrough, repeated-key and non-object shapes stay | `required-missing`, `late-missing`, `unknown-field`, `sql-missing-with-unknown-field`, `required-wrong-width`, `late-wrong-type` | `runtime_conformance::shared_record_runtime_profile` | a missing field tolerated by every null mode: `required-missing`; the declared type not checked on a required field: `required-null`; `unknown_field` reported as `field_missing`: `unknown-field` |
| `given_a_source_that_does_not_fit_the_plan::encrypt_and_check_source_refuse_it_alike_with_no_key_request` (`record.rs`), 3 of 11 rows and the two matching `encrypt` checks removed | as the row above; the runner also asserts no data key is generated on a refusal | `runtime_conformance::shared_record_runtime_profile` | as the row above |
| `every_refusal_names_its_field_and_reason::a_stored_record_that_does_not_fit` (`record.rs`), 5 of 7 rows removed; the repeated-field row stays (the engine guard is reached natively alone, see the raw-frame contract), and so does the record that is one leaf: the read profile stores every record as a batch, so `row-not-map` reaches the batch-row arm and not the whole-record one | `missing-field`, `field-not-map`, `missing-ciphertext`, `plaintext-under-c`, `context-tenant-no-payload` | `read_conformance::shared_record_read_profile` (`check_record` and `decrypt`, with the retrieval counter) | `outputs_not_map` and `no_ciphertext_node` reported as other reasons: `field-not-map`, `missing-ciphertext`; a missing field tolerated by every null mode: `missing-field`, `late-missing-field`, `context-drop-tenant`; `passthrough` and `no_passthrough_node` reported as other reasons: `plaintext-under-c`, `context-tenant-no-payload` |
| `given_a_field_that_stores_a_null::a_null_in_a_field_with_no_null_mode_is_refused` (`record.rs`), removed | `required-null` | `runtime_conformance::shared_record_runtime_profile` | the declared type not checked on a required field: `required-null` |
| `given_a_field_that_stores_a_null::a_stored_null_is_refused_through_a_plan_that_has_no_null` (`record.rs`), removed | `authenticated-null-as-required` (the refusal), `sealed-null` and `sealed-boundaries` (a value opens through the sealing plan) | `read_conformance::shared_record_read_profile`, `runtime_conformance::shared_record_runtime_profile` | a sealed null accepted by a plan with no null mode: `authenticated-null-as-required` |
| `given_a_field_that_stores_a_null::a_row_with_every_field_left_out_is_an_empty_record` (`record.rs`), removed | `sql-all-absent`, `sql-null` | `runtime_conformance::shared_record_runtime_profile` | an explicit SQL null not left out of the record: `sql-null` |
| `given_a_field_that_stores_a_null::a_stored_record_may_leave_out_only_a_sql_field` (`record.rs`), removed | `sql-absent-as-required`, `sql-absent-as-sealed` | `read_conformance::shared_record_read_profile` | a missing field tolerated by every null mode: `sql-absent-as-required`, `sql-absent-as-sealed` |
| `a_query_the_field_does_not_answer_is_refused_naming_the_field` (`src/dynamic/query.rs`), 10 rows, removed | `eq-on-match-only`, `matches-on-equality-only`, `eq-on-order-only`, `lt-text-for-integer`, `lt-fraction-for-integer`, `between-scalar`, `between-one-bound`, `between-mixed-bounds`, `no-such-field` | `query_refusal_conformance::shared_query_refusal_profile` (`check_query` and `query_term` alike) | `operator_not_answered` reported as `unknown_operator`: `eq-on-match-only`; `not_a_range` reported as `field_type`: `between-scalar`; `no_such_field` reported as `unknown_field`: `no-such-field` |
| `the_typed_paths_query_refusals_are_made_before_any_term` (`query.rs`), 6-row table removed; renamed `folded_equivalents_derive_one_term` for the one-term assertions that stay | `lt-unassigned`, `between-unassigned-high`, `between-unassigned-low`, `matches-too-short`, `matches-unassigned`, `eq-unassigned` | `query_refusal_conformance::shared_query_refusal_profile` | the upper bound of a range not folded before a term: `between-unassigned-high` |
| `block_ore_refuses_text_it_has_no_term_for_before_any_term` (`query.rs`), refusal rows removed; the accepted texts' index assertion stays as `accepted_block_ore_text_derives_a_block_ore_term`, since the corpus records that a case is accepted, not which index answers it | `ore-block-too-long`, `ore-block-trailing-nul`, `ore-block-between-long-high`, `ore-block-between-long-low`, `ore-block-between-nul-low`, `ore-block-between-nul-high` | `query_refusal_conformance::shared_query_refusal_profile` | the length refusal reported as the NUL refusal: `ore-block-too-long` |
| `TestAQueryTheFieldDoesNotAnswerIsRefused` (`languages/golang/encrypt/query_test.go`), 5-row table, the inverted range and the short match text removed; renamed `TestVerifyAndTargetLimitRefuseWhatIsNotAMatchQuery` for the `Verify`/`TargetLimit` refusals that stay | `matches-on-integer`, `lte-on-match-only`, `unknown-operator`, `between-scalar`, `lt-text-for-integer`, `inverted-range`, `matches-too-short` | `TestQueryRefusalConformance` | the host dropping the diagnostic's `reason`: every refusal case; the engine faults above, through the same engine the guest embeds |
| `TestAPlanRefusalNamesItsReason` (`languages/golang/encrypt/guest_test.go`), removed | `output-duplicate` as a frame, on both guests (its host plan in `v1/go-declarations.json` is refused by `Validate` before the engine, so the frame is what observes the engine's reason; `TestCheckerRefusesAnIndexedUntypedField` still reaches the engine through `engineCheck`) | `TestDeclarationConformance` | the host dropping the diagnostic's `reason`: `output-duplicate` and every other refusal case |

Considered and kept, with the reason:

- `given_a_stored_record_that_does_not_fit_the_plan::decrypt_and_check_record_refuse_it_before_any_key_is_retrieved`:
  eight of its thirteen shapes are read cases, but the five that are not (a
  passthrough inside the ciphertext subtree, a passthrough field carrying a
  ciphertext, a field, an output and a key given twice) are the engine guards
  the transport reaches natively alone, and the test is the module's
  load-bearing forged-plaintext check with its retrieval counter.
- `refuses_fields_under_different_contexts_or_extensions` and
  `refuses_two_fields_keyed_under_one_identity`: each holds one shared row
  beside shapes the corpus has not got (one field extended and one not; two
  passthrough fields sharing a label).
- `tests/op.rs` typed refusals (`a_match_query_with_no_tokens_is_refused_before_any_term_or_keyset`,
  `a_match_query_is_cut_in_nfc_and_refuses_text_with_no_normal_form`,
  `an_inverted_range_is_a_query_like_any_other`): the corpus's `typed` entries
  record the typed chain's refusal stage, not its `via`, batch, case-sensitive
  and bound-order assertions.
- Go `TestPlanCheckAnswersWithoutACipher`, `TestQueryTermRefusesWhatTheFieldDoesNotAnswerBeforeState`,
  `TestGuestRefusesMalformedInputsBeforeState`, `TestCheckerRefusesAnIndexedUntypedField`:
  their rows are shared declaration and refusal cases, but each is about the
  uninitialised instance answering `ErrEncoding` before `ErrState`, or the
  host rule refusing before the engine, which the corpus runners do not observe.
- Everything in the retained list above: compile-fail, ownership and
  zeroization, batching, property, frozen-bytes, generated-code, host
  conversion, error wrapping, cancellation, guest lifecycle, PostgreSQL and
  live-provider tests.
