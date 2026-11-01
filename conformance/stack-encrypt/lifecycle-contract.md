# Lifecycle, cleanup and key-I/O conformance

`lifecycle-v1` enrolls observable native Rust and Go WASI behavior. The
[index](v1/lifecycle-profiles.json) names existing compiled tests and focused
new lifetime probes. These are backend-specific observations, not another
semantic value corpus and not a promise to erase every plaintext copy in a
process. Python and TypeScript are explicitly not enrolled.

## Required evidence

| Requirement | Native evidence | Go evidence and limits |
|---|---|---|
| `lifecycle-ownership-v1` | Actual record operations release fulfilment captures exactly once on success, provider failure and unpolled drop; zipped fulfilments do not share key material. | Client keys are consumed/redacted; explicit close and unreachable-client cleanup release guest memory; calls on a closed client fail. GC cleanup is eventual, so callers should close explicitly. |
| `lifecycle-cancellation-v1` | Dropping a future paused in generation drops the provider future and operation captures; subsequent work on the cipher succeeds. Guest ABI abort spends the handle and drops the operation. | Cancellation before a call sends no request; cancellation between steps or during token fetch leaves unrelated operations usable. A guest step that overruns cancellation closes the client. Discarded late output is wiped. |
| `lifecycle-partial-output-v1` | A batch with a valid first row and a later authenticated type mismatch releases its decoded prefix without marked heap residue. Existing context cases reject late authentication failures without returning partial output. | Generated and raw batch APIs return no partial rows on failure; interrupted HTTP bodies fail; cancelled output is wiped. SDK conversion diagnostics contain no decrypted values. This does not assert erasure of partially populated caller-owned Go objects. |
| `lifecycle-buffer-cleanup-v1` | The existing allocator observer checks selected write/read/JSON parse paths and has a negative control. Guest ABI tests check buffer-registry cleanup, error-buffer release and protected text drop. | Request bodies survive until their owner closes them, then wipe; refused requests wipe; heap growth wipes abandoned backing arrays; guest runtime close releases memory. Post-encryption memory scans are supplementary observations. |
| `lifecycle-diagnostics-v1` | Guest errors discard untrusted foreign cause messages; failed/successful exports do not hand over stale diagnostics. | Structured errors remain available after failures; SDK errors and redacted display/logging expose types or fields rather than plaintext values. |
| `lifecycle-validation-before-io-v1` | Existing runtime/read/context cases count provider calls. Wrong shape, independently detectable context mismatch and oversized descriptors fail before key I/O; lazy assembly stops after local failure. | Host refusals happen before entering the guest, and shared runtime/read cases exercise the uninitialised guest's preflight boundary. Go does not yet expose native provider counters. |
| `lifecycle-logical-batching-v1` | Instrumented `DataKeySource` calls establish one logical generation batch, retrieval grouping by keyset, descriptor ordering and no work for empty batches. | Go uses the same engine, but this profile does not claim independently instrumented Go key-request counts. |
| `lifecycle-provider-chunks-v1` | The actual KMS chunking helper preserves order, handles a final short chunk, fails the whole call on a chunk error, bounds in-flight chunks and releases their futures on cancellation. | This is a native algorithm observation, not a measurement of live HTTP request counts. |

The drop witnesses belong to fulfilment closures and provider futures in real
record operations. They establish ownership release. They do **not** establish
that arbitrary captured values implement zeroization. The separate heap and
buffer observations provide the narrower byte-cleanup evidence.

A validation failure detectable only after authentication necessarily retrieves
keys. The profile distinguishes that from shape and context checks that can run
without keys. An error does not imply that no provider request ever occurred.

## Logical calls and physical requests

A `Pending` combines requests before awaiting them. For supported assemblies,
generation dispatches one logical `generate_keys` call; retrieval dispatches one
logical `retrieve_keys` call per keyset. Existing instrumented providers observe
those calls and their ordered payloads.

`StackKms::send_chunked` subsequently splits a logical call according to
`max_keys_per_req` and bounds concurrent chunks by `max_concurrent_reqs`.
The chunk tests observe this helper with controlled callbacks: ten inputs with
chunk size three and concurrency two start only two three-item chunks while
both are pending; dropping the aggregate releases both. This is distinct from
“one HTTP request per batch.” Live service limits, retries and transport timing
are not inferred from the logical counters.

## Limits carried in every report

These entries in the index are limitations, not successful requirements:

- **`go-post-decrypt-shadow-stack` — known gap.**
  `TestPlaintextDoesNotRemainInGuestMemoryAfterDecrypt` in
  `languages/golang/encrypt/roundtrip_test.go` is explicitly skipped because
  decrypted plaintext can remain in the WASM shadow stack in underlying cipher
  temporaries. It is not enrolled as passing evidence. The post-encryption scan
  cannot establish the post-decryption guarantee.
- **`native-heap-observer-exclusions` — limited observation.**
  `packages/stack-encrypt/tests/heap_hygiene.rs` watches marked frees on the
  executing thread. Its existing observer excludes a named upstream aws-lc
  sealing frame by backtrace and reports excluded frees. It scrubs stack residue
  before observing heap frees; it does not prove stack erasure. Its JSON query
  paths use borrowed/static path text because owned path copies have separate
  cleanup limitations. The lifecycle runner preserves the observer's output.
- **`caller-owned-host-values` — outside the guarantee.** Caller-owned strings,
  bytes, objects, returned plaintext, aliases and copies remain the caller's
  responsibility. Ownership transfer or protected borrowing must be stated by
  each public API. Cancellation cannot retract work already accepted by a remote
  service, and dropping a provider future does not prove remote cancellation.
- **`live-provider-http-chunking` — not observed.** Hermetic tests count logical
  provider calls and chunk callbacks. They do not attest to actual ZeroKMS
  request counts, retry behavior or remote cleanup.
- **`python-typescript-lifecycle` — not enrolled.** Their backends, cancellation
  models, host mappings and extension-owned buffers need their own evidence.

The current required lane supports Linux and macOS. Its native heap observer
requires Unix; unsupported hosts fail explicitly rather than silently skipping
that evidence. This is not Windows lifecycle certification. Memory locking under
OS resource limits, whole-process heap scans, other threads, compiler/register
residue and arbitrary caller-supplied sinks are outside the enrolled guarantees.
Existing broader platform, Miri, fuzz, live and locking tests remain in place.

## Running and extending the profile

From the repository root:

```sh
mise run wasm:guest:build
mise run wasm:guest:build:deterministic
mise run test:conformance:lifecycle
```

No CipherStash credentials or database are required. Some Go cancellation tests
start local HTTP stubs. The runner shares inventory/execution checks with EQL
conformance: every enrolled native test must be compiled, selected and not
ignored, and every Go test must pass with no skipped subtests. Fresh Go tests
bypass the test cache. Required fixture-update variables are rejected.

The required `wasi-check` CI job runs the task and uploads its report, failing
if the report is absent. Reports identify the engine, platform/architecture,
lockfile, guest hashes, enrollment, executed evidence and known limitations.
Set `STACK_CONFORMANCE_REPORT_DIR` locally to retain the same JSON report.

Add evidence to the existing requirement where possible. Keep language-specific
lifetime probes and implementation regressions: a shared semantic round-trip
cannot replace them. Do not claim a stronger cleanup guarantee by removing a
limitation or accepting a skipped test; supply executable evidence on the
backend being claimed. Secure-buffer adoption and key-copy removal remain
implementation work, distinct from this inventory.
