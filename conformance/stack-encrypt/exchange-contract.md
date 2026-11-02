# Fresh artifact exchange

`artifact-exchange-v1` is the profile under which one runner writes
artifacts and another opens them, in the same run, with nothing frozen in
between. The scalar profile proved fresh Go-to-Rust opening for one field.
This profile widens that to every value kind at its edges, structural
records with index terms, whole-value opaque blobs and EQL rows, in both
directions between the runners that exist: native Rust and Go over WASI.
Python and TypeScript have no runner; the report lists them as not
enrolled, and their absence is a gap, not a pass.

The corpus is [`v1/exchange.json`](v1/exchange.json). The runners are
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
| `values` | One record per positive case of `v1/values.json` (the value-boundary corpus), under the plan that case declares, with context `conformance/exchange/value`: the sealed leaf and every declared index term; nothing for a SQL null | The record opens to the case's typed input. Every stored term equals the term the consumer's own query of the same value derives (`eq` for equality, `lt` for an order index), and the `equal_query` spelling derives the same equality term. An index the corpus lists as unanswered is present and not queried |
| `record` | The rows of the corpus's one record: a passthrough `int64` id (held on the host by Go, lowered as a `passthrough` output by Rust), text, `uint32`, decimal, date and timestamp fields with equality and order terms, a SQL-null text field and a sealed-null `float32` field, under context `conformance/exchange/people` | The passthrough carried equals the corpus input; every sealed field opens to its input, a sealed null opens as null and a SQL null is absent from storage and opens as null; every stored term equals the consumer's derived query term |
| `blobs` | A whole struct (`name`, `age`, `tags`, optional `nickname`) as one opaque ciphertext under `conformance/exchange/blob/value`: Rust through `OpaqueBlob<T>`, Go through the storage blob the generated opaque path writes (`vcffi.MarshalStorage` sealed as the one `bytes` field) | The ciphertext opens and decodes to the corpus value through the other SDK's opaque reader (`OpaqueBlob<T>` or `gensupport.Opaque`). A nil Go slice and an empty Rust `Vec` are one value; Rust's `Some` marker and Go's bare pointer are one value |
| `eql-rows` | The EQL v4 `profiles` rows: every column of the committed fixture's plaintexts sealed afresh, Rust through eql-bindings' typed targets, Go through its generated code | Each column opens to the plaintext through the other side's typed target. The Go consumer also derives the generated equality query for each `*Eq` column and compares its `hm` with the stored term; the Rust consumer opens the columns |

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
table, rows of plaintext and stored envelopes); the Rust producer adds a
`_comment` naming the eql-bindings and stack-encrypt versions it sealed with.

## Required execution

`mise run test:conformance:exchange` (the `scripts/stack-exchange-conformance.mjs`
script, also run at the end of `test:conformance`) refuses every
fixture-update variable, requires both deterministic guests to be present
and nonempty, requires the `go` and Rust toolchains, and only then creates a
fresh temporary directory. It runs each producer with its output variable
set (`STACK_EXCHANGE_OUTPUT`, `EQL_V4_RUST_ROWS_OUT`, `EQL_V4_ROWS_OUT`),
checks every output is nonempty and of the right shape and producer, and
runs each consumer with its input variable set (`STACK_EXCHANGE_INPUT`,
`EQL_V4_RUST_ROWS`, `EQL_V4_ROWS`). Producer caches are bypassed: nextest
reruns its binaries, Go runs with `-count=1`, and the fresh directory is
new every run. A missing runner, a missing or empty guest, an empty fresh
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

Only this checkout has exchanged with itself. Supported released-version
combinations follow the EQL v4 and Stack Encrypt compatibility policy,
which is not written yet. The report carries the placeholder the matrix
will take, with no rows:

```text
released_versions: { status: "not defined",
  row_shape: { producer: {sdk, version}, consumer: {sdk, version},
               storage: {eql_bundle, schema: "eql_v4"},
               kinds: ["values", "record", "blobs", "eql-rows"],
               result: "opens | refused (<documented reason>)" },
  rows: [] }
```

Rows are added when the policy names the combinations it supports and the
released artifacts to run them against. No row is fabricated before then.

## Scope and remaining work

Match terms, JSON documents, EQL types outside the `profiles` fixture,
context-field records and typed-extension contexts are not exchanged here;
the earlier profiles cover them within one language or against frozen
vectors. Python and TypeScript runners, their backends, and a SQL lane that
stores one language's fresh rows through the other are open. No frozen
fixture or artifact changes: everything this profile writes lives in a
temporary directory for the length of one run.
