# Stack Encrypt conformance

This directory holds a shared test contract for Stack Encrypt bindings. The
[implementation plan](../../docs/plans/2026-10-31-stack-encrypt-conformance.md)
sets out the wider work; [coverage.md](coverage.md) maps existing evidence and
gaps. These profiles are **experimental**, not certification of an entire SDK.

## Run

From the repository root, with the pinned mise tools installed:

```sh
mise run wasm:guest:build:deterministic
mise run test:conformance
```

No credentials or database are required. The task refuses a missing test guest.
It runs native Rust against frozen vectors, Go against the same vectors, then
native Rust against the ciphertexts Go has just produced. It never regenerates
expectations. CI also runs the Go cases on its other supported host platforms.
The same task runs the shared declaration acceptance/rejection corpus in both
languages, with native observations of normalization.

The Rust runner is `packages/stack-encrypt/tests/conformance.rs`; the Go runner
is `languages/golang/encrypt/conformance_test.go`. Go calls the record interface
used by generated code. Testing public SDK declarations is a separate layer.
Python and TypeScript runners are pending; their absence is not a passing result.

## `record-declarations-v1` contract

The [declaration grammar](declaration-grammar.md) defines the engine's current
record-plan syntax, defaults, context rules, kind/index table and null policies.
`v1/declarations.json` contains 201 cases, including malformed frames and all
21 kinds against five scalar indexes. The resolver is explicitly `none`; EQL
targets need their own profile.

The runners are `packages/stack-encrypt/tests/declarations.rs` and
`languages/golang/encrypt/declaration_conformance_test.go`. Both call the engine
without a cipher. Valid-frame declaration diagnostics agree exactly; malformed
frames document the different native-parser and WASI-boundary classifications.
Native Rust also checks normalization observations. Go's checker does not expose
the parsed plan, so it asserts acceptance and diagnostics.

## `record-scalars-v1` contract

`v1/cases.json` has a corpus format `version`, a semantic `profile`, a public
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

`v1/native.json` is a frozen artifact set produced by the Rust owned scalar API.
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
