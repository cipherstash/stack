# EQL and JSON operation profiles

These experimental profiles enroll the existing EQL v4 JSON tree operations.
They do not describe EQL v3 SteVec, or certify an entire SDK. The
[enrollment index](v1/eql-json-profiles.json) names mandatory compiled tests;
[shared cases](v1/eql-json.json) supply document text and predicate refusals to
native Rust and Go. Python and TypeScript have no enrolled runner yet.

## Requirements and evidence

| Requirement | Contract | Existing evidence retained |
|---|---|---|
| `eql-resolver-catalog-v1` | The resolver names catalog domains, their producibility and operators. Unknown names, unavailable EQL builds and unsupported capabilities are refused. JSON options require a JSON target. | Native `targets` and `json_tree_data_plan`; Go catalog and plain-guest refusal tests |
| `json-write-v1` | JSON documents, including scalar roots, empty containers, JSON null and integer boundaries, round-trip as values. SQL null stores no document. Invalid text is refused without exposing it; native tests observe no key request. Typed and dynamic plans agree on search terms and can open each other's output. | Native typed/data-plan suites, Go raw and generated typed document APIs; existing seeded derivation fixture |
| `json-query-v1` | Containment, reverse containment, equality at a path, ordered bounds, selectors and child operations derive their documented operand shapes. Unsupported requests fail. | Native engine/EQL operand comparisons, Go generated queries, independent PostgreSQL `jsonb` containment oracles |
| `json-request-bound-reads-v1` | Extraction and subtree/wildcard reads open against the prepared path, column, position and bounds. Wrong requests and detectable tampering fail. | Native adversarial read suite, EQL request/open tests, Go selector reads, PostgreSQL extraction/subtree and hostile-row suites |
| `json-element-match-v1` | Every condition must hold on one element. Ordering paths and resolver capability are required; a probe beyond the declared bound raises rather than silently truncating. | Native operator/capability tests, Go generated member APIs, SQL domain and independent plaintext predicate tests |
| `json-predicate-match-v1` | Supported text compiles to existing operators; refusals preserve reason, construct and byte offset, with no caller text in diagnostics. Missing and null paths obey the documented truth rules. | Shared negative corpus, native compiler/property tests, Go generated `Match`, SQL `jsonb_path_match` and handwritten-operator oracles |

The index is an evidence inventory, not a second copy of every existing test.
Native execution retains whole binaries, including their unindexed properties
and regressions. Go selects the exact enrolled tests and rejects missing passes,
failures and skips, including skipped subtests. Native inventory checks reject
missing names, filtered tests and a wrong `#[ignore]` state before execution.
Only the PostgreSQL lane executes the database tests marked `#[ignore]`.

## Predicate grammar

The current grammar in `packages/stack-encrypt/src/dynamic/json_query.rs` and
`json_predicate.rs` is the executable specification. This profile pins:

```text
predicate := comparison | exists(path) | exists(path ? (filter))
           | (predicate) | !(predicate)
           | predicate && predicate | predicate || predicate
comparison := path op value | value op path
op := == | != | <> | < | <= | > | >=
path := $ followed by .key, ."quoted key", or [*] steps
value := JSON scalar literal | $variable | $"quoted variable"
filter := comparison on @ or @.member, optionally joined with &&
```

Negation binds before `&&`, which binds before `||`. Variables are a JSON
object; absence of `vars` means an empty object. Scalar literals are strings,
numbers, booleans and null; objects/arrays cannot be comparison values.
Orderings and multi-condition element filters require numbers or strings and
configured ordered paths. A filter requires a wildcard in its outer path;
its member cannot contain a wildcard. Predicate nesting is limited to 32.
A wildcard bound must be positive; its probe prevents an undersized bound from
silently producing a partial answer.

Arithmetic, regex, `starts with`, `is unknown`, mode words, methods, `.*`, `.**`,
slices, `last`, path-to-path/value-to-value comparisons, array positions,
filters outside `exists`, and `||`, `!`, `!=` or nested `exists` inside filters
are unsupported. `!=` at a wildcard is refused. The corpus pins representative
syntax, unsupported-construct, variable, type, depth and path diagnostics.
Existing parser tests retain the wider grammar matrix and adapter-specific
invalid-input checks; the shared corpus is not an exhaustive grammar fuzzer.
Offsets are UTF-8 byte offsets, not character indices.

## Nulls, oracles and intentional differences

SQL null (no encrypted document), JSON null (a document/node), and an absent
path are distinct. The SQL predicate suites compare both selected rows and
three-valued answers. An absent path does not satisfy a comparison. Ordering a
JSON null can produce SQL unknown where plaintext jsonpath returns false;
the compiled predicate adds the null test under negation where it affects
selected rows. This exception is checked explicitly, not normalized away.

The independent oracles use PostgreSQL `jsonb @>`, `<@`, `jsonb_path_query` and
`jsonb_path_match`, alongside handcrafted plaintext conditions. They do not
calculate expected results from encrypted operands. Their supported-domain
assumptions and exceptions remain explicit:

- Paths are literal. There is no lax implicit array unwrapping or scalar-to-array
  wrapping. Use `[*]` and keep array shapes consistent.
- Keep one scalar kind at an ordered path. Terms do not preserve the plaintext
  type distinctions used by jsonpath's cross-kind comparisons.
- Order terms fold text case/accents and compare numbers as float64. Equality in
  a multi-condition element filter uses those terms; standalone `==` is exact.
- Reverse containment excludes the plaintext root-scalar-in-root-array special
  case; the generated oracle logs how many such comparisons it excludes.
- Storage and projection list order is randomized. Compare projections as sets
  and stored selector collections as multisets. The existing deterministic
  `packages/stack-encrypt/tests/fixtures/json_tree_vectors.json` pins a seeded
  permutation, tags and tokens, not a production ordering promise. Fresh
  ciphertext bytes are not equality fixtures.
- Read authentication detects substituted paths, wrong columns, mixed-document
  subtrees, forged tags and incomplete returned chains. It does not establish
  database completeness or row identity: withholding a whole answer can look
  like no node, and another row's node at the same path can open. Those limits
  have named native evidence in the index.

## Required execution and identity

From the repository root:

```sh
mise run wasm:guest:build
mise run wasm:guest:build:deterministic
mise run wasm:guest:build:eql
mise run wasm:guest:build:eql:deterministic
mise run test:conformance:eql

# A disposable database: this command installs/replaces EQL v4 there.
EQL_TEST_DATABASE_URL='host=localhost port=5432 user=postgres password=postgres dbname=postgres' \
  mise run test:conformance:eql:postgres
```

No CipherStash credentials are required. Both lanes are required steps in
`tests-golang.yml`; conformance changes trigger them. The database lane rebuilds
SQL from this tree, installs exactly the bundle whose SHA-256 it records, and
passes the same connection to both languages. It fails without a database or
required guests. A fast-lane pass alone is not SQL conformance.

Reports include the native engine and EQL binding package versions, root/EQL
lockfile hashes, corpus/enrollment hashes, deterministic guest hashes, executed
requirement test names, and (for PostgreSQL) the installed EQL version, schema
version, PostgreSQL version and actual SQL bundle hash. Development bundles can
report `DEV`; their hash distinguishes them. CI uploads reports and fails if
none were produced. Locally set `STACK_CONFORMANCE_REPORT_DIR` to retain them;
the same report is always printed after success. These describe this checkout
and its guest artifacts, not a claim of compatibility across released versions.

Required checks reject all fixture-update environment variables. Extending a
language binding means running the applicable shared cases and providing its
own adapter evidence for each claimed requirement. Fresh cross-language JSON
artifact exchange, a release compatibility matrix, and Python/TypeScript
runners remain separate work.
