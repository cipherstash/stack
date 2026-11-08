# Stack Encrypt conformance

This directory holds a shared test contract for Stack Encrypt bindings. The
[implementation plan](../../docs/plans/2026-10-31-stack-encrypt-conformance.md)
sets out the wider work; [coverage.md](coverage.md) maps existing evidence and
gaps. These profiles are **experimental**, not certification of an entire SDK.

## Files

Each file in `v1/` is named `<profile>.<role>.json`. `<profile>` is the exact
`profile` value in the file's header, so searching for a profile ID finds every
file that belongs to it. `v1/` is the corpus format version, which is separate
from each profile's own version. `<role>` is one of:

- `cases`: the shared, language-neutral cases that every runner executes. When
  an expectation is a category rather than bytes, such as an error class or a
  retrieval count, it is written in the case itself.
- `expected.<producer>`: frozen outputs keyed by the case IDs in `cases`,
  produced by `<producer>`. `rust-native` is the native Rust engine. Only the
  producer regenerates this file, deliberately; runners compare against it.
- `inputs.<runner>`: extra inputs keyed by case ID that only `<runner>` needs,
  such as Go host values that have no language-neutral form.
- `enrollment`: the profile's requirement IDs mapped onto existing compiled
  tests that are its evidence, rather than cases of its own.

Every file has a `version` and `profile` header. An `expected` file also names
its `producer`, and an `inputs` file names its `runner`.
`scripts/__tests__/stack-conformance-ci.test.mjs` fails on a file that breaks
these rules.

| File | Role | Rust reader | Go reader |
|---|---|---|---|
| `record-scalars-v1.cases.json` | cases | `tests/conformance.rs` | `conformance_test.go` |
| `record-scalars-v1.expected.rust-native.json` | expected | `tests/conformance.rs` (writes it) | `conformance_test.go` |
| `record-declarations-v1.cases.json` | cases | `tests/declarations.rs` | `declaration_conformance_test.go` |
| `record-declarations-v1.inputs.go.json` | Go inputs | — | `declaration_conformance_test.go` |
| `record-reads-v1.cases.json` | cases | `tests/read_conformance.rs` | `read_conformance_test.go` |
| `record-runtime-v1.cases.json` | cases | `tests/runtime_conformance.rs` | `runtime_conformance_test.go` |
| `record-contexts-v1.cases.json` | cases | `tests/context_conformance.rs` | `context_conformance_test.go` |
| `record-contexts-v1.expected.rust-native.json` | expected | `tests/context_conformance.rs` (writes it) | `context_conformance_test.go` |
| `record-context-boundaries-v1.cases.json` | cases | `tests/context_conformance.rs` | `context_conformance_test.go` |
| `record-values-v1.cases.json` | cases | `tests/value_conformance.rs` | `value_conformance_test.go` |
| `record-query-refusals-v1.cases.json` | cases | `tests/query_refusal_conformance.rs` | `query_refusal_conformance_test.go` |
| `record-raw-frames-v1.cases.json` | cases | `tests/raw_frame_conformance.rs` | `raw_frame_conformance_test.go` |
| `eql-json-v1.cases.json` | cases | `tests/json_operators.rs`; EQL's `tests/encryption/tests/json_tree_data_plan.rs` | `json_conformance_test.go` |
| `eql-json-v1.enrollment.json` | enrollment | `scripts/stack-eql-conformance.mjs` runs the tests it names | `scripts/stack-eql-conformance.mjs` runs the tests it names |
| `lifecycle-v1.enrollment.json` | enrollment | `scripts/stack-lifecycle-conformance.mjs` runs the tests it names | `scripts/stack-lifecycle-conformance.mjs` runs the tests it names |
| `fixture-enrollment.json` | index | `tests/common/mod.rs` | `fixture_conformance_test.go` |

Rust readers are under `packages/stack-encrypt/`; Go readers are under
`languages/golang/encrypt/`; EQL's are under `packages/eql/`.
`fixture-enrollment.json` is the one file not named after a profile: it maps
requirement IDs of several profiles onto existing fixtures and tests (see
[the fixture contract](fixture-contract.md)), and
`scripts/stack-conformance-selection.mjs` reads it to choose the Go tests that
`mise run test:conformance` runs.

## Run

From the repository root, with the pinned mise tools installed:

```sh
mise run wasm:guest:build:deterministic
mise run wasm:guest:build
mise run test:conformance
```

No credentials or database are required. The task refuses a missing test guest.
It runs native Rust against frozen vectors, Go against the same vectors, then
native Rust against the ciphertexts Go has just produced. It never regenerates
expectations. CI also runs the Go cases on its other supported host platforms.
The same task runs the shared declaration acceptance/rejection corpus in both
languages, with native observations of normalization. It also runs the shared
runtime, read, context, value-boundary, query-refusal and raw-frame cases, and
enrolls the existing value-kind, context-field and query-operator
fixtures described below. Set no fixture-update variables when checking conformance.

The Rust runner is `packages/stack-encrypt/tests/conformance.rs`; the Go runner
is `languages/golang/encrypt/conformance_test.go`. Go calls the record interface
used by generated code. Testing public SDK declarations is a separate layer.
Python and TypeScript runners are pending; their absence is not a passing result.

## Lifecycle, cleanup and key I/O

The [lifecycle contract](lifecycle-contract.md) maps native/Go ownership,
cancellation, partial-output cleanup, diagnostics, validation-before-I/O and
batching evidence. Run `mise run test:conformance:lifecycle` on a supported Unix
host with the normal and deterministic guests built. Reports retain known
cleanup gaps and unobserved behavior alongside the passing requirements.

## EQL and JSON operations

The [EQL/JSON contract](eql-json-contract.md) enrolls resolver capabilities,
document writes, queries, extraction/subtree reads, element-match and predicate
matching. It reuses the native, Go and independent PostgreSQL suites and shares
write/predicate case data. Run `mise run test:conformance:eql` and the separate
required `test:conformance:eql:postgres` task; see the contract for guest builds,
disposable database setup, intentional SQL differences and version reports.

## Context composition and expectations

The [context contract](context-contract.md) covers ordered extensions, canonical
context encodings, typed/generated API calls, stored-context expectations,
tampering and preflight boundaries. The required command runs the new
`context_conformance` Rust binary and `TestContextConformance` /
`TestContextBoundaries` Go runners, together with native `plan_grammar` and
existing context-field fixture tests.

## Existing value-kind and query-operator fixtures

The [fixture contract](fixture-contract.md) defines `record-value-kinds-v1` and
`record-query-operators-v1`. Their [enrollment index](v1/fixture-enrollment.json)
maps stable requirement IDs to the existing Rust and Go tests. The fixtures
remain under `packages/stack-encrypt/tests/fixtures`; no vectors are copied.

These profiles cover the represented narrow/128-bit integers, dates,
timestamps, decimals, equality/order terms, query operand metadata, match
verification and fetch limits. They preserve typed Rust and generated Go API
checks. The task runs the existing tests directly, and a missing guest fails
when conformance is required. The ordinary CI suites already execute them.

This is representative fixture coverage, not an exhaustive type/operator
matrix. Wider fresh artifact exchange and shared scalar query refusals remain
separate work. The EQL/JSON profiles are described below.

## Value boundaries, query refusals and raw frames

Three profiles close the gaps the representative profiles left. The
[value contract](values-contract.md) defines `record-values-v1` in
`v1/record-values-v1.cases.json`: every kind at its edges, sealed and SQL nulls for the
fixed-width kinds, write refusals between kinds, frozen typed frames, and
the Go-only host conversions the host refuses before the engine. The
[query-refusal contract](query-refusals-contract.md) defines
`record-query-refusals-v1` in `v1/record-query-refusals-v1.cases.json`: one plan, every
scalar operator against every field capability that does not answer it,
the range shapes, other-kind values and nulls the contract lists, each refusal's
class and diagnostic, no key I/O, and the stage at which the typed Rust
chain refuses the same query. The [raw-frame contract](raw-frames-contract.md)
defines `record-raw-frames-v1` in `v1/record-raw-frames-v1.cases.json`: stored batches as
transport bytes, so repeated keys and malformed leaves reach both decoders,
and the table of error classes (transport, leaf, shape, authenticated,
invalid declaration, unsupported host conversion). The runners are
`value_conformance`, `query_refusal_conformance` and `raw_frame_conformance`
in the Rust crate and `TestValueConformance`, `TestQueryRefusalConformance`
and `TestRawFrameConformance` in the Go module; `test:conformance` runs all
six.

## `record-reads-v1` contract

The [read contract](read-contract.md) defines cases in `v1/record-reads-v1.cases.json` for
malformed stored records, authenticated read-type failures and context preflight.
The native runner observes retrieval stages. Go exercises the same cases through
an uninitialised guest and a configured cipher, plus the normal record adapter
for representable cases. The contract records the static-context combination
that the host refuses before calling the guest. The runners are `tests/read_conformance.rs` in the Rust
crate and `encrypt/read_conformance_test.go` in the Go module.

## `record-runtime-v1` contract

The [runtime contract](runtime-contract.md) defines cases in `v1/record-runtime-v1.cases.json`:
missing and explicit null values, SQL-null omission, sealed-null storage and
equality, typed batch round trips, write validation and lossless query conversions.
The runners are `packages/stack-encrypt/tests/runtime_conformance.rs` and
`languages/golang/encrypt/runtime_conformance_test.go`. Native Rust also checks
data-key call counts; Go host source validation preserves shared structured diagnostics.

## `record-declarations-v1` contract

The [declaration grammar](declaration-grammar.md) defines the engine's current
record-plan syntax, defaults, context rules, kind/index table and null policies.
`v1/record-declarations-v1.cases.json` contains cases, including malformed frames and all
21 kinds against five scalar indexes. The resolver is explicitly `none`; EQL
targets need their own profile.

The runners are `packages/stack-encrypt/tests/declarations.rs` and
`languages/golang/encrypt/declaration_conformance_test.go`. Both call the engine
without a cipher. Valid-frame declaration diagnostics agree exactly; malformed
frames document the different native-parser and WASI-boundary classifications.
Native Rust also checks normalization observations. Go's checker does not expose
the parsed plan, so it asserts acceptance and diagnostics against both release
and deterministic guests. Representable cases also exercise `Checker.Check`
through explicit host plan fixtures in `v1/record-declarations-v1.inputs.go.json`.

## `record-scalars-v1` contract

`v1/record-scalars-v1.cases.json` has a corpus format `version`, a semantic `profile`, a public
deterministic-provider `seed`, a record `context`, a `field`, an exact list of
`required_capabilities`, and uniquely identified `cases`. Unknown fields,
versions, profiles, capabilities and input types fail. Every case must run.

The profile fixes a one-field record with ciphertext (`c`) and equality (`eq`)
outputs. Its field context is the record context followed by the field name.
Each case declares the field's `kind` and a typed `input`. `input.text` is the
literal string value, canonical base-10 integer, `true`/`false`, or empty text
for null, as determined by `input.type`. Runners construct real typed host
values, preserving integer width. JSON numbers are deliberately not used for
values: future TypeScript runners must not pass 64-bit integers through Number.

The initial positives cover int32 and int64 bounds, uint64 max, an integer
above JavaScript's safe-integer limit, Unicode text and empty text. For each:

1. The encoded typed frame must equal the frozen frame, including its type.
2. Record encryption and opening must preserve both value and type.
3. An equality query must produce one exact `eq` operand, encoded as `bytes`,
   without an EQL domain. Its bytes must equal the frozen equality term and
   the term stored with the record.
4. The frozen native owned-scalar ciphertext must open through the record
   path. Native Rust additionally opens it through the owned scalar API.
5. Fresh Go ciphertext must open in Rust through both paths. Ciphertext bytes
   themselves are not compared: encryption is randomized.
6. Opening with `wrong` appended to the record context (before the field name)
   must refuse key retrieval as forbidden.
   This expectation uses `stack_kms::DeterministicSource`, whose descriptor
   binding models ZeroKMS's refusal. It is distinct from an AEAD failure and
   does not imply every provider returns the same error shape.

Negative cases have `expected_error` and exercise the equality query only.
They require the exact engine diagnostic `code`, `reason`, and field name;
Go must also expose `ErrEncoding`. Native Rust verifies rejection occurs
before data-key generation or retrieval. String/bool inputs for an integer
field and a null query are currently covered. Error prose is not contractual.

Boolean equality is not admitted by the current engine. Boolean scalar
encryption, nullable records, other numeric kinds, bytes, JSON, EQL targets,
other operators, declarations, cancellation and provider failures need later
profiles or cases. The full SQL behavior is not part of this initial profile.

## Artifacts and evolution

`v1/record-scalars-v1.expected.rust-native.json` is a frozen artifact set produced by the Rust owned scalar API.
It records `version`, `profile`, `producer`, and a case-ID map containing hex
`frame`, `ciphertext` and `equality` bytes. The map must contain exactly every
positive case; missing or extra cases fail. Every key and plaintext here is
public test material. The provider seed is not a production key mechanism.

The runners accept `STACK_CONFORMANCE_OUTPUT` to export fresh artifacts; Rust
accepts `STACK_CONFORMANCE_INPUT` to validate another producer. The task isolates
these variables and sets `STACK_CONFORMANCE_REQUIRED=1`, preventing a missing
Go test guest from turning conformance into a skipped test. Ordinary Go test
runs may skip this suite when the guest has not been built.

To intentionally create or update native artifacts:

```sh
STACK_CONFORMANCE_UPDATE=1 mise x --env test -- cargo nextest run --locked \
  -p stack-encrypt --all-features --test conformance
mise run test:conformance
```

Review the case and artifact diff together. Never regenerate artifacts merely
to make a regression pass. Existing IDs retain their meaning; incompatible
expectations require a new profile. Corpus version 1 is a test format, not a
production wire version. Ciphertext/storage versions remain owned by their
existing codecs.

Both runners currently share the Rust engine. This checks host value conversion,
native/WASI interoperability and regressions against frozen evidence; it cannot
detect every bug shared by both paths. Independent SQL oracles, broader negative
cases, release-version matrices and richer version reports remain in the plan.
