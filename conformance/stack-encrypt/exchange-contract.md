# Fresh artifact exchange

`artifact-exchange-v1` is the profile under which one runner writes
artifacts and another opens them, in the same run, with nothing frozen in
between. The scalar profile proved fresh Go-to-Rust opening for one field.
This profile widens that to every value kind at its edges, structural
records with index terms, whole-value opaque blobs and EQL rows, in both
directions between the runners that exist: native Rust and Go over WASI.
Python and TypeScript have no runner; the report lists them as not
enrolled, and their absence is a gap, not a pass.

The corpus is [`v1/artifact-exchange-v1.cases.json`](v1/artifact-exchange-v1.cases.json). The runners are
`packages/stack-encrypt/tests/exchange_conformance.rs`
(`fresh_artifact_exchange`) and
`languages/golang/encrypt/exchange_conformance_test.go`
(`TestArtifactExchange`) for values, records and blobs; and for EQL rows,
`rows_rust_seals_open_in_the_go_sdk` and `rows_the_go_sdk_sealed_open_in_rust`
in `packages/eql/tests/encryption/tests/v4_types.rs` with
`TestV4RowsMatchTheCommittedFixture` and `TestV4RowsTheRustSuiteSealedOpenInGo`
in `languages/golang/encrypt/eql_v4_test.go`. The task that drives them is
`scripts/stack-exchange-conformance.mjs`:

```sh
mise run wasm:guest:build:deterministic
mise run wasm:guest:build:eql:deterministic
mise run test:conformance:exchange
```

## What is exchanged

| Kind | Producer writes | Consumer checks |
|---|---|---|
| `values` | One record per positive case of `v1/record-values-v1.cases.json` (the value-boundary corpus), under the plan that case declares, with context `["conformance", "exchange"]`: the sealed leaf and every declared index term; nothing for a SQL null | The record opens to the case's typed input. Every stored term equals the term the consumer's own query of the same value derives (`eq` for equality, `lt` for an order index), and the `equal_query` spelling derives the same equality term. An index the corpus lists as unanswered is present and not queried |
| `record` | The rows of the corpus's one record: a passthrough `int64` id (held on the host by Go, lowered as a `passthrough` output by Rust), text, `uint32`, decimal, date and timestamp fields with equality and order terms, a SQL-null text field and a sealed-null `float32` field, under context `["conformance", "exchange", "people"]` | The passthrough carried equals the corpus input; every sealed field opens to its input, a sealed null opens as null and a SQL null is absent from storage and opens as null; every stored term equals the consumer's derived query term |
| `blobs` | A whole struct (`name`, `age`, `tags`, optional `nickname`) as one opaque ciphertext under `["conformance", "exchange", "blob"]`, field `value`: Rust through `OpaqueBlob<T>`, Go through the storage blob the generated opaque path writes (`vcffi.MarshalStorage` sealed as the one `bytes` field) | The ciphertext opens and decodes to the corpus value through the other SDK's opaque reader (`OpaqueBlob<T>` or `gensupport.Opaque`). A nil Go slice and an empty Rust `Vec` are one value; Rust's `Some` marker and Go's bare pointer are one value |
| `eql-rows` | The EQL v4 `profiles` rows: every column of the committed fixture's plaintexts sealed afresh, Rust through eql-bindings' typed targets, Go through its generated code | Each column opens to the plaintext through the other side's typed target, and each equality column's stored `hm` equals the term the consumer's own equality query derives for that plaintext (the generated `*Eq` query in Go, the typed `*EqQuery` target in Rust) |

Each kind runs Go to Rust and Rust to Go. Ciphertext bytes are never
compared: encryption is randomized, and agreement is shown by opening and
by deriving the same query terms.

## Artifact and manifest format

A producer writes one JSON file:

```text
{ "version": 1, "profile": "artifact-exchange-v1",
  "producer": { "language", "sdk", "sdk_version", "backend",
                "engine": { "name", "version", "guest_sha256" },
                "key_source": { "kind": "deterministic", "seed" },
                "profiles": [..], "capabilities": [..], "toolchain" },
  "values": { <case id>: { "c": <hex | null>, "terms": { <index>: <hex> } } },
  "record": { <row id>: { "passthrough": { <field>: {type, text} },
                          "fields": { <field>: { "c", "terms" } } } },
  "blobs":  { <case id>: <hex ciphertext> } }
```

`producer` records the SDK (`stack-encrypt` and its crate version; the Go
module path and its build version), the engine (the crate version natively;
the SHA-256 of the deterministic guest the Go runner loaded), the backend
(`native` or `wasi`), the key source (the deterministic test provider and
the corpus seed; no live credentials exist here), the profiles the
artifacts claim and the capabilities they exercise. Both consumers refuse a
file of another version or profile, another language's own output, another
seed, or a capability list that differs from the corpus, and require every
artifact set to hold exactly the corpus's cases. Unknown fields are refused
in both languages.

EQL rows travel in the shape of the committed `v4_rows.json` fixture (seed,
table, rows of plaintext and stored envelopes) with a `producer` object the
committed fixtures do not carry: `language`, `sdk` and `sdk_version`
(`eql-bindings` and its version; the Go module path and its build version),
`backend`, `engine` (the stack-encrypt version natively; the SHA-256 of the
deterministic EQL guest under WASI) and `schema` (`eql_v4`). Each EQL
consumer refuses rows without it or written by its own language, and the
task requires it before any consumer runs.

## Required execution

`mise run test:conformance:exchange` (the `scripts/stack-exchange-conformance.mjs`
script, also run at the end of `test:conformance`) refuses every
fixture-update variable, `EQL_UPDATE_FIXTURES` included (the Go EQL producer
rewrites its committed rows under it), requires both deterministic guests to be present
and nonempty, requires the `go` and Rust toolchains, and only then creates a
fresh temporary directory. It runs each producer with its output variable
set (`STACK_EXCHANGE_OUTPUT`, `EQL_V4_RUST_ROWS_OUT`, `EQL_V4_ROWS_OUT`),
checks every output is nonempty and of the right shape and producer, and
runs each consumer with its input variable set (`STACK_EXCHANGE_INPUT`,
`EQL_V4_RUST_ROWS`, `EQL_V4_ROWS`). Producer caches are bypassed: nextest
reruns its binaries, Go runs with `-count=1`, and the fresh directory is
new every run: a passing run removes it once the report is written, and a
failing one, a failure while reading the lockfiles or writing the report
included, keeps it and prints its path. A missing runner, a missing or empty guest, an empty fresh
output, a skipped or failed test, or a consumer refusal fails the task.
`STACK_CONFORMANCE_REQUIRED=1` is set throughout, so a Go test that would
skip on a missing guest fails instead.

Without the variables, each runner still produces and opens its own
artifacts in memory, so the ordinary Rust and Go suites exercise the same
code; only the task proves the cross-language half. The Go EQL consumer
skips without its input variable, and the task treats a skip as a failure.

CI runs the task in `tests-golang.yml` (`wasi-check`), after both
deterministic guests are built, and uploads the report as
`exchange-conformance`. The earlier scalar exchange step and the EQL rows
step remain.

## Report

The task prints and, under `STACK_CONFORMANCE_REPORT_DIR`, writes
`exchange.json`: the corpus, value-corpus and EQL fixture hashes; the
commit; the Go and Rust toolchains; the engine versions each path resolves
(`stack-encrypt`, `vitaminc-aead` and `vitaminc-aead-frame` from the root,
guest and EQL lockfiles, and `eql-bindings`); the storage versions the EQL
rows were derived under (the `eql_v4` schema, the `@cipherstash/eql`
package and `eql-bindings` crate versions); the lockfile and guest hashes;
each producer's manifest; one row per exchanged kind and direction with
the artifact count and what the consumer compared; the languages not
enrolled; and a `released_versions` section.

## SQL lane

The exchanged EQL rows are opened and query-compared in the fast lane. The
PostgreSQL oracle for EQL rows is the `eql-postgres` job of
`tests-golang.yml` (`go:test:postgres`), where the Go SDK stores fresh rows
in `eql_v4` columns and the EQL encryption suite's ignored tests insert
the Go-sealed fixture rows and query them; its report records the installed
bundle and PostgreSQL version. Storing Rust-sealed rows through the Go SDK
into PostgreSQL in the same run is not wired yet.

## Released-version combinations

Only this checkout has exchanged with itself. The API plan
(`docs/plans/2026-10-24-stack-encrypt-api-plan.md`, "The stored format
stays compatible with Go rc.3") already fixes one combination: data that Go
`v0.1.0-rc.3` wrote (the tag `languages/golang/v0.1.0-rc.3`, with the
`eql-v4-install.sql` bundle attached to that release) must stay readable and
searchable by the current Rust and Go. The report names it as required and
not yet run. The other released-version combinations follow the EQL v4 and
Stack Encrypt compatibility policy, which is not written yet:

```text
released_versions: { status: "rc.3 required, not yet run",
  required: [ { producer: {sdk: "go", version: "languages/golang/v0.1.0-rc.3"},
                consumer: {sdk: "rust and go", version: "this checkout"},
                storage: {eql_bundle: "eql-v4-install.sql of languages/golang/v0.1.0-rc.3",
                          schema: "eql_v4"},
                result: "opens" } ],
  row_shape: { producer: {sdk, version}, consumer: {sdk, version},
               storage: {eql_bundle, schema: "eql_v4"},
               kinds: ["values", "record", "blobs", "eql-rows"],
               result: "opens | refused (<documented reason>)" },
  rows: [] }
```

`rows` holds results that a run produced. The rc.3 row joins it when a lane
runs the released Go module against this checkout; no result is written
before then.

## Scope and remaining work

Match terms, JSON documents, EQL types outside the `profiles` fixture,
context-field records and caller-supplied scopes are not exchanged here;
the earlier profiles cover them within one language or against frozen
vectors. Python and TypeScript runners, their backends, and a SQL lane that
stores one language's fresh rows through the other are open. No frozen
fixture or artifact changes: everything this profile writes lives in a
temporary directory for the length of one run.
