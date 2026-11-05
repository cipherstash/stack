# Stack Encrypt cross-language conformance

Date: 2026-10-31. Status: scalar, declaration, initial runtime, read and context-composition slices implemented; existing value-kind, query-operator and context-field fixtures enrolled. The complete contract is not frozen.

This work is stacked on [PR #1404](https://github.com/cipherstash/stack/pull/1404),
at `b684a217e2da629c762efa70fac958ec7e21646a`. It follows the accepted
[SDK principles](../sdk-design-principles.md) and the interoperability deliverable
in [the API redesign](https://github.com/cipherstash/stack/pull/1365).

## Objective

Equivalent declarations and operations have the same meaning in native Rust,
Go, Python, and TypeScript. SDKs retain idiomatic APIs and find errors at the
earliest stage their languages permit. Encryption and semantic validation stay
in the shared Rust engine.

Python bindings are underway; TypeScript bindings are planned. Neither runner
is present in this checkout. Do not report their conformance as passing or
assume they will use Go's WASI backend. Native and WASM backends implement the
same semantic contract and have additional lifecycle tests of their own.

Vitamin C's transport and storage codecs are dependencies of this contract.
Reference their versions and vectors rather than copying their specifications.
Codec agreement alone does not prove declaration or operation agreement.

## Approach and order

1. **Define the layers.** Specify value representation, declarations, operations,
   persistence/SQL, binding lifecycle, and language SDK mappings separately.
   Keep public SDK syntax distinct from the engine's data grammar and from the
   test corpus format.
2. **Inventory the implemented profile.** Map existing tests to requirements,
   identifying covered, partial, and missing evidence. Document current `next`
   behavior and explicit differences from plaintext SQL. Proposed context roles
   and future declarations must not silently become requirements of this profile.
3. **Create one portable corpus.** Give cases stable IDs, required capabilities,
   typed inputs, declarations, operations, and expected values or diagnostics.
   Use text for integers and other values JSON cannot carry losslessly. Run the
   same cases in Rust and Go first; enroll Python early and TypeScript when its
   binding exists. Unknown versions, operations, or required cases must fail.
4. **Test SDK mappings separately.** Exercise real host values and public SDK
   declarations, not just pre-encoded frames. Cover TypeScript number/bigint,
   undefined/null, byte arrays and timestamps; Python integer ranges, bool/int,
   bytes/text, decimals and timezones; Go integer widths, pointers and typed nil.
   Make unsupported or lossy conversions explicit refusals.
5. **Use independent evidence.** Combine fixed vectors, cross-language writes
   and reads, plaintext SQL oracles, malformed requests and tampering. Compare
   randomized ciphertext by opening it and querying it, not by byte equality.
   Instrument test key providers for batching and validation-before-I/O checks.
   Verify cleanup, cancellation and ownership separately for each backend;
   do not promise equivalent erasure of host-language values.
6. **Gate claims in CI.** Record corpus/profile, SDK, engine, backend and supported
   capabilities. Every required case must run; an absent guest or unknown case
   must not create a green conformance result. Keep a fast credential-free lane,
   with database, live-provider and cross-version lanes alongside it. Version
   expected behavior and require review for changes to frozen expectations.

## First slice

The initial `record-scalars-v1` test profile is intentionally small. It covers
typed scalar boundaries, a one-field record declaration, exact equality terms,
cross-opening native scalar leaves through the Go record path, wrong-context
opening, and rejected query inputs. It uses the existing deterministic test
provider, with public test keys only.

The Rust runner exercises both the owned scalar API from #1404 and dynamic
record/query execution. The Go runner exercises the internal record interface
used by generated SDK code. This proves engine/binding behavior; it does not
replace tests of generated declarations or certify the complete Go SDK.

The shared corpus and runner contract live in
[`conformance/stack-encrypt`](../../conformance/stack-encrypt/README.md).
The coverage map there identifies existing evidence and remaining gaps.

## First-slice checkpoint

Implemented on `feat/stack-encrypt-conformance`, based directly on #1404.
The corpus has eight positive cases and three query refusals. Local validation
passes for native Rust, Go WASI, and fresh Go-to-Rust artifact exchange through
`mise run test:conformance`. Rust clippy, the enabled Go linters, and the CI wiring
checks also pass. The work is in draft [PR #1460](https://github.com/cipherstash/stack/pull/1460),
targeting #1404's branch. Local validation is distinct from hosted CI status.

The first profile includes frozen typed frames and equality terms, frozen native
ciphertexts, fresh native scalar and record round trips, and forbidden retrieval
under a wrong context. The implementation adds no production API changes.
SQL requirements and Python/TypeScript runners remain open.

## Declaration checkpoint

The [declaration grammar](../../conformance/stack-encrypt/declaration-grammar.md)
records the implemented syntax and semantic rules, including accepted enum
aliases, defaults, context composition, all 21 kinds against five scalar indexes,
null policies and target-capability refusal. Its cases run in native Rust
and Go WASI without a cipher. Native Rust checks selected normalized plan
observations; Go's existing checker exposes acceptance and diagnostics only.

The profile fixes `NoTargets`. EQL resolver/catalog behavior and full JSON/SQL
operation semantics remain later profiles. Malformed frames explicitly distinguish
the native parser's diagnostic from the WASI boundary's earlier refusal.

Local validation passes for both profiles, fresh ciphertext
exchange, Rust clippy/formatting, Go lint, Biome and the CI wiring checks.

The [coverage map](../../conformance/stack-encrypt/coverage.md#consolidation-policy)
records consolidation candidates. Shared case tables can replace duplicated
expectations once coverage matches; language-specific and implementation tests
remain. No existing tests have been removed.

## Runtime checkpoint

The initial runtime slice is on `feat/stack-encrypt-runtime-conformance`, stacked
on draft [PR #1460](https://github.com/cipherstash/stack/pull/1460). Its shared
cases cover missing/null storage, typed batch round trips, source refusals, and
lossless equality query conversions. Native Rust observes data-key call counts.
Go host source validation preserves the shared structured diagnostic fields.
The [runtime contract](../../conformance/stack-encrypt/runtime-contract.md)
describes the corpus and limits. No production API or existing test is removed.

Local validation passes for all three profiles, fresh scalar
ciphertext exchange, Rust clippy/formatting, Go lint, Biome and the CI wiring
checks. The deterministic guest is reused from the unchanged parent engine.

The read checkpoint below adds malformed stored records, authenticated read-type
failures and context preflight. Existing wider value-kind, query-operator,
generated SDK and EQL fixtures remain in place.

## Read checkpoint

The read slice is on `feat/stack-encrypt-read-conformance`, stacked on draft
[PR #1461](https://github.com/cipherstash/stack/pull/1461). Its shared cases
cover malformed stored shapes, authenticated type failures, null read-policy
changes and context preflight, including late failures in batches.

Native Rust distinguishes shape rejection, pending preflight and authenticated
type refusal using data-key counters. Go checks each case against an uninitialised
guest and an active guest; representable cases additionally use `Cipher.Open`.
A test-only entry point supplies shapes the record adapter cannot represent.
The [read contract](../../conformance/stack-encrypt/read-contract.md) records
exact diagnostics and the remaining gaps. The tree hook shares the production
open/decode path, including field-order validation before conversion to maps.
No public API or existing test is removed.

Local validation passes for all four profiles, fresh scalar
artifact exchange, Rust clippy/formatting, Go lint, Biome and the CI wiring checks.
The deterministic guest is reused from the unchanged parent engine.

The fixture checkpoint below enrolls the existing wider value-kind and operator
fixtures. Next, extend context composition and EQL/JSON operation profiles.
Repeated-key and malformed-leaf cases need an explicit raw-byte transport path.
Python and TypeScript consumers remain pending.

## Value-kind and query-operator checkpoint

Building on the read-compatibility profile, the
[fixture contract](../../conformance/stack-encrypt/fixture-contract.md) and
[enrollment index](../../conformance/stack-encrypt/v1/fixture-enrollment.json)
assign stable requirement IDs to the existing `value_kinds.json` and
`query_operators.json` evidence. The conformance task directly runs their
existing Rust and Go tests. Typed Rust comparisons, generated Go methods,
match verification and fetch sizing remain intact.

The fixture files stay in place with no duplicated expectations. CI guards
the requirement-to-test mapping, compiled test availability and exact test
selection. The Go selection is generated from the enrollment index. Required Go runs fail if
the guest is missing; required checks cannot regenerate frozen fixtures.
This is consolidation of inventory and execution, not removal of assertions.

Local validation passes for the expanded conformance command, fresh scalar
artifact exchange, missing-guest regressions, Rust clippy/formatting, Go lint,
Biome and CI wiring checks. All four Rust fixture writers refuse regeneration in
required mode, and the frozen fixture files remain unchanged.

The coverage is representative, not a complete kind/operator boundary matrix.
Shared operator refusals, wider fresh artifact exchange, Python/TypeScript
consumers and version matrices remain open. The next implementation slice is
shared context-composition vectors, followed by EQL/JSON operation profiles.

## Follow-up slices

- Extend the declaration grammar to EQL resolver capabilities and the operation
  request profiles. Generate structural schemas from shared models where faithful;
  keep semantic validation executable rather than assuming JSON Schema covers it.
- Extend shared cases to runtime source/read/request shapes, missing/null values,
  all numeric kinds, and context binding. Consolidate existing duplicate tables
  only after their unique assertions have equivalent coverage.
- Bring the existing JSON/SQL suites under named requirements. Add common JSON
  vectors across runners and pin the supported predicate grammar and its limits.
- Add Python's runner in its owning repository/worktree, with a declared capability
  set and the same artifact exchange. Establish its actual backend and APIs with
  that implementation; do not design them by inference here.
- Add TypeScript's runner and SDK mapping tests when its binding exists. Include
  native and WASM variants if both are supported.
- Extend artifact exchange to every producer/consumer pair for common profiles,
  then supported release versions. Pin SQL bundle and engine versions in reports.
- Add backend lifecycle, cancellation, no-secret-diagnostics, key-I/O and batching
  requirements. Reuse current tests and instrument providers where evidence is absent.

## Completion criteria

A profile is conformant only when every mandatory requirement has executable
evidence for the claimed language/backend/version. Optional capabilities have
named tests and explicit support status. No unsupported feature is silently
ignored. Released profiles define supported version combinations and evolution
rules; the corpus format version is not a new production wire version.

Initial success means Rust and Go run the same cases, freshly written Go values
open in native Rust, fixed native values open in Go, and malformed query inputs
produce the specified diagnostics. Python and TypeScript remain visibly pending
until their runners execute. The complete specification, SQL profile, and all
language SDK mappings remain follow-up work.

## Context composition checkpoint

Implemented shared composition and boundary cases in
`conformance/stack-encrypt/context-contract.md`: 18 typed extension cases,
eleven read/preflight cases and four query cases, generated Go calls and native
typed chains. Existing
context-field fixture tests and the native plan-grammar suite are required by
`test:conformance`. Repeated Rust `.extend()` now appends, aligning Rust with Go;
the changelog documents compatibility for records written under the old behavior.
The current shared binding/search context remains distinct from the future
binding/search-scope split.

Next: the EQL/JSON operation profile. Python and TypeScript runner delivery
and the wider fresh artifact exchange remain separate planned work.
