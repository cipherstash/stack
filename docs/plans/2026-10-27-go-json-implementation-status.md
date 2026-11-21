# Go JSON implementation status after the October 27 merges

Source baseline: merged `next` at
[`ffeed7adb3f7d8739cda53261046147852bffc82`](https://github.com/cipherstash/stack/commit/ffeed7adb3f7d8739cda53261046147852bffc82).
This reconciles the [Go JSON plan](2026-10-24-go-json-tree.md) with the
implementation. It is source and test inspection, not a fresh test run or a
claim that every release gate has passed.

## Work that has landed

The customer path is implemented through the existing Rust engine and guest:
full-document writes and reads; JSON query operators; prepared selector and
subtree reads; generated Go field methods; typed document serialization and
number-preserving decoding; and a documented executable PostgreSQL example.
The plan should move from building its first vertical slice to validating
and closing concrete release gaps.

The target's registered name is **`JsonSearch`**. Go uses
`eql.JSONSearch`, `eql.JSONSearchQuery`, `eql.JSONSearchLeafQuery` and
`eql.JSONEntry`; SQL uses `public.eql_v4_json_search`, `eql_v4.query_json`,
`eql_v4.query_json_leaf` and `public.eql_v4_json_entry`. `eql.JSON` is still
the storage-only type. The former v4 SteVec names were removed. The proposed
`EncryptedJson` / `eql.EncryptedJSON` names are not the implemented surface.
Do not make another cosmetic naming migration a customer prerequisite.
[Generated EQL types](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/languages/golang/encrypt/eql/eql_gen.go),
[Go changelog](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/languages/golang/CHANGELOG.md).

## Declarations and options

An implemented declaration is:

```go
type Customer struct {
    _       struct{} `stash:"context=customers"`
    ID      int64    `stash:"id,passthrough"`
    Profile Profile  `stash:"profile,encrypt_into=JsonSearch(ordered=$.age)"`
}
```

The generator emits one shared declaration with `EncryptInto(...,
"JsonSearch")` and `Options(..., gensupport.TargetOptions{...})`. Record
transport writes `target: {name, options}` when options are present and a
string target otherwise. Options currently contain `sealed_root` and
`ordered`; omitted values use native defaults. The native engine validates
the target and paths at generation/runtime boundaries.
[Example model](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/languages/golang/encrypt/example/json/model.go),
[generated declaration](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/languages/golang/encrypt/internal/testusers/customer_stash.go),
[record transport](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/languages/golang/internal/record/record.go).

The tag supports `ordered=$.age;$.visits[*].at,sealed_root=false`. Its path
spelling is deliberately limited to plain member keys and array steps;
quoted keys and keys containing delimiters have no tag spelling. The Go
parser checks that restricted spelling, while the engine validates path
semantics. The structured internal options type can carry a string list,
but that alone does not establish a supported arbitrary-path generator
policy API. A general options schema/catalog, versioned definition wrapper
and cached immutable resolved-definition abstraction remain broader work.
[Tag parser](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/languages/golang/stashgen/tag.go),
[policy API](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/languages/golang/encrypt/policy/policy.go).

## Actual query and read surface

| Surface | Implemented result / behavior |
| --- | --- |
| `Fields.Profile.Contains`, `ContainedBy` | `eql.JSONSearchQuery`; caller supplies an explicit needle |
| `EqAt(ctx, cipher, path, value)` | `eql.JSONSearchQuery`; positional selector paths refused |
| `At.Age.Lt/Lte/Gt/Gte` | `eql.JSONSearchLeafQuery`; declared ordered accessor |
| `At.Age.Between` | `encrypt.JSONRange[eql.JSONSearchLeafQuery]`, `Low` and `High` |
| `Selector(ctx, cipher, path)` | `encrypt.JSONSelection[eql.JSONEntry]` with `Selector()` and `Open(ctx, []*eql.JSONEntry)` |
| `Subtree(ctx, cipher, path, opts)` | `encrypt.JSONRead[eql.JSONEntry]` with `Tokens()`, `Open(ctx, [][]eql.JSONEntry)` and `OpenOne(ctx, []eql.JSONEntry)` |
| `Children`, `ChildCount` | `encrypt.JSONToken`; derives the concrete node token for the SQL function |
| `encrypt.DecodeJSON[T]` | Converts opened raw JSON to an application type, using `json.Number` for interface destinations |

Prepared reads retain the cipher and original field/path/options request.
Their `Open` method therefore does **not** take the cipher argument used in
the earlier proposed example. Opening sends the trusted request and grouped
untrusted rows through `se_json_open`; Rust rederives verification state.
`JSONSelection.Open` reports `JSONValue{Found, JSON}`. `JSONRead.Open` returns
one list per database row; `OpenOne` refuses a wildcard read before opening,
rather than accepting it whenever a particular result happens to be singular.
The Go wrappers retain no `context.Context`.
[Read types and opening](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/languages/golang/encrypt/json.go),
[generated query methods](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/languages/golang/encrypt/internal/testusers/customer_stash.go).

`JSONSelector` and `JSONToken` implement `driver.Valuer` for text.
`JSONTokens` itself binds a PostgreSQL text-array literal, so the earlier
instruction to add a driver-specific array adapter is unnecessary for this
API. Zero selectors/tokens/lists fail when bound. Token and prepared-read
formatters redact capabilities and paths. Opened `JSONValue` holds plaintext
and does not redact it.

The low-level query response has been extended, rather than replaced by a
new public sum type: `QueryTerm.Encoding` is `bytes`, `eql`, `text` or
`text_array`; `Terms` carries byte operands and `Text` carries selectors or
tokens. Operation discovery adds an input shape. Generated helpers validate
the encoding, cardinality and fidelity they expect. This implements the
needed distinction; the plan should not require a wholesale response rewrite
solely to match its illustrative tagged-union spelling.
[Query response](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/languages/golang/encrypt/query.go),
[generated helper checks](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/languages/golang/encrypt/gensupport/json.go).

Two limitations must remain visible:

- `Children` and `ChildCount` prepare SQL operands. They do not provide the
  earlier plan's parent-bound plaintext child opener. Immediate child rows
  are not a complete subtree and must not be passed to a subtree opener as
  though they were. Decide whether that extra helper is required for the
  customer; do not mark it implemented merely because child tokens exist.
- After randomized stored entry ordering, a wildcard selector's `->` result
  is an **unspecified matching element**, not the first array element.
  Generated documentation directs wildcard comparisons through SQL
  `json_tree_path_query` with explicit existential semantics and sorting
  through the least/greatest matching order term. Subtree opening reconstructs
  document order. Update old first-match examples accordingly.

## Typed JSON and input guarantees

A JSON field may be `json.RawMessage` (or its alias), or an accepted struct,
map or slice type, optionally behind a pointer with `null=sql`. Native scalar
field types are not accepted as documents; raw JSON can still hold scalar
roots. Plain bytes and a newly defined type over `json.RawMessage` are
refused, avoiding implicit base64 serialization.

The generator checks whether a typed document can be written and read with
`encoding/json`. It rejects interfaces within document types; dropped or
colliding fields; unsupported channel/function types; unmatched custom
marshal/unmarshal methods; and `json:",string"`. Explicit JSON adapters use
`encoding/json` once, without a preliminary `map[string]any` conversion.
`DecodeJSON[T]` uses `UseNumber`, rejects trailing values, and sanitizes errors.
An interface destination through this explicit decoder is supported even
though an interface-containing generated document declaration is refused.
[Generator documentation and rules](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/languages/golang/cmd/stashgen/README.md),
[typed field admission](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/languages/golang/stashgen/read.go).

Preserve these documented qualifications in the plan:

- `encoding/json` replaces invalid UTF-8 in Go strings before Rust sees it.
  Rust's strict raw-JSON ingress cannot recover or reject the original bytes.
- Nil maps/slices become JSON null; empty ones become `{}`/`[]`. A nil optional
  field pointer becomes SQL NULL. A present raw `null` remains encrypted JSON
  null. An empty raw document is invalid.
- Nested `time.Time` is RFC3339 text in its own offset, not a temporal search
  domain. Equal instants can have different string terms, and text ordering
  is not chronological ordering. Application representations must reflect
  the intended query semantics.
- Containment helpers refuse plain Go string needles and needles serialized
  as JSON null. For typed fields holding structs, `Contains` refuses a needle
  of the field's own type (or pointer), preventing unintended zero-valued
  constraints. Maps or dedicated optional-field needle types are supported;
  `EqAt` accepts scalar values, including nil as JSON null.

## Storage and release work

Opaque generated structs now use `vcffi.MarshalStorage` and
`UnmarshalStorage`, with an old-JSON read fallback. The generated format
marker is `GeneratedVersion2`; generated shape fields use `vc:"name,default"`.
This integration is no longer prospective. The Go module still pins Vitamin
C pseudo-versions. The actual release guard refuses a final Go version
while those pins remain; prereleases may carry them. Regenerate application
code and replace them with released module tags before a final release. Existing
compatibility fallbacks need not be redesigned in this plan refresh.
[Opaque codec](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/languages/golang/encrypt/gensupport/codec.go),
[module pins](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/languages/golang/go.mod),
[release caveats](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/languages/golang/CHANGELOG.md),
[enforced release guard](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/scripts/go-release-version.mjs).

## Evidence of coverage, and what was not rerun

The tree contains guest round-trip and refusal tests (`json_tree_test.go`),
generated raw/typed field tests (`json_fields_test.go`, `json_typed_test.go`),
number-preserving decoder tests, generator admission/refusal tests, and real
PostgreSQL suites (`json_postgres_test.go`, `json_typed_postgres_test.go`).
The PostgreSQL suites skip when `DATABASE_URL` is absent. The Go workflow
builds guests and installs EQL before its PostgreSQL test task. The typed
example includes generated code and a complete database flow.
[Guest tests](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/languages/golang/encrypt/json_tree_test.go),
[typed PostgreSQL tests](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/languages/golang/encrypt/json_typed_postgres_test.go),
[CI wiring](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/.github/workflows/tests-golang.yml),
[executable example](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/languages/golang/encrypt/example/json/main.go).

This review did not run those tests, inspect every CI execution result, or
prove all proposed cross-language/storage release vectors are covered. Keep
release verification, formal interoperability specification, supported-driver
coverage and the remaining context/child-opening questions as explicit tasks.
