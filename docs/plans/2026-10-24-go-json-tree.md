# The json_tree capability in the Go SDK

Status: plan, not a spec. Tracking issue: #1347. Written against the json_tree stack
(#1288 → #1325 → #1329 → #1336, with #1345 on top) and `next` (#1229).
Where this disagrees with the code, the code wins.

## Background

`json_tree` is the EQL v4 domain family for an encrypted JSON document. The
Rust engine (`packages/stack-encrypt/src/json/`) seals a
`serde_json::Value` as one entry per node, plus a containment projection
`q`. The SQL (`packages/eql/src/v3/json_tree/`, v4 only) answers:

- containment `@>` (GIN over `eql_v4.json_tree_query(col)`) and `<@`;
- scalar equality at a path, sent as a containment needle;
- `->` / `->>` extraction by an encrypted path selector;
- `< <= > >=`, ranges and `ORDER BY eql_v4.ord_term(col -> sel)`, at paths
  declared `ordered` (CLLW OPE);
- walks over a subtree by token (`json_tree_subtree`, `_children`), with
  a fallback through the sealed root.

The design is `docs/plans/2026-10-17-json-tree-index.md`, and the leakage
write-up is `packages/eql/docs/reference/json-tree-leakage.md`.

Today none of this reaches Go, and that is deliberate. The design doc puts
Go out of scope (lines 336-338, 377). The pieces that exist are
placeholders that refuse:

- `encrypt.JSON()` and `encrypt.JSONTerm` (`term.go:73-78, 157`);
- stashgen's `index=json`, which parses and is then refused
  (`engine.go:265-268`);
- the `eql.SteVecDocument` and `eql.JSON` rows, marked not producible
  (`eql_gen.go:61-62`).

## Constraints

The design principles (`docs/sdk-design-principles.md`, ADR-0007 and
ADR-0008) settle most of the shape before any Go is written.

1. **The engine does the work (G1, ADR-0007).** Go reaches the engine only
   through a data plan run in the WASI guest. The engine refuses the JSON
   index in a data plan today: `IndexSpec::Json` crosses the wire and is
   refused with `Reason::JsonIndexPending` (`dynamic/kind.rs:106`). The
   json_tree family is also missing from the EQL catalog, from `v4::all()`
   and from the target table, so `eql-codegen` emits no Go type for it.
   **Most of the work is in Rust, and it comes first.**
2. **One EQL column per field (Go-11).** A json_tree field is an
   `encrypt_into=` field. It binds and scans as a generated
   `eql.JSONTree`, which holds the EQL JSON exactly as PostgreSQL stores
   it. Go never builds or reads that JSON.
3. **Checks run at the earliest stage (G3, Go-1).** Options and ordered
   paths belong in the struct tag, so they are checked at `go generate` by
   asking the engine (`se_plan_check`). Go keeps no copy of the path
   grammar.
4. **Named concrete types (Go-2).** Every generated query method returns a
   named `eql.*Query` type, never `[]byte` or `any`.
5. **Nulls.** A null json_tree document cannot be sealed at a value's
   length, because documents have no single length. So a json_tree field
   needs `null=sql`, exactly as text does. stashgen's `nullMode` already
   gives this answer once the type reports that it is not fixed-width.

## The proposed Go surface

### Declaration

```go
type Patient struct {
    _       struct{}        `stash:"context=patients"`
    ID      int64           `stash:"id,passthrough"`
    Profile json.RawMessage `stash:"profile,encrypt_into=JSONTree(ordered=$.age|$.visits[*].date)"`
    Notes   *Notes          `stash:"notes,encrypt_into=JSONTree,null=sql"`
}
```

- `encrypt_into=JSONTree` takes the engine's `JsonOptions`:
  - `ordered=` is a `|`-separated list of paths;
  - `sealed_root=false` opts out of the sealed root, which defaults to on,
    as in the engine.

  stashgen hands these to the engine unparsed, as the wire form of the
  `json` index (`{"json":{"sealed_root":…,"ordered":[…]}}`). The engine
  parses and checks them, so a bad path or a position in an ordered path
  (`JsonOrderingAtPosition`) fails `go generate`.
- **The field's Go type** (decision 1) is `json.RawMessage`, `[]byte`, or
  any type `encoding/json` marshals (a struct, `map[string]any`, `any`).
- **The value crosses the ABI as JSON text** (decision 2): a new record
  kind `json` whose source value is UTF-8 JSON. The engine parses it with
  `serde_json`, so number canonicalisation (`2 == 2.0`) and key handling
  happen in Rust, identically for every language (G1).

  On decrypt the engine returns JSON text, and the generated code
  unmarshals it into the field's type. `encoding/json` is already how
  opaque structs cross (`gensupport/codec.go:345`), so this adds no new
  reflection to the SDK.

### Writes and reads

These are unchanged in shape. `patients.Encrypt(ctx, cipher, []Patient)`
returns `[]EncryptedPatient`, with `Profile eql.JSONTree`;
`patients.Decrypt` reverses it. The field's own
`Fields.Profile.Encrypt(ctx, c, v)` returns `eql.JSONTree`.

### Queries

These are generated per field from what the engine reports
(`se_operators`), like every other query method:

| Generated method | Operand | Returns | SQL |
|---|---|---|---|
| `Contains(ctx, c, needle)` | a JSON document (decision 3) | `eql.JSONTreeQuery` | `profile @> $1::eql_v4.query_json_tree` |
| `ContainedBy(ctx, c, doc)` | a JSON document | `eql.JSONTreeQuery` | `profile <@ $1::eql_v4.query_json_tree` |
| `EqAt(ctx, c, path, v)` | `string` path, scalar `v` | `eql.JSONTreeQuery` | `profile @> $1::eql_v4.query_json_tree` |
| `At.Age.Lt/Lte/Gt/Gte(ctx, c, v)` | the scalar | `eql.JSONTreeLeafQuery` | `(profile -> $2::text) < $1::eql_v4.query_json_tree_leaf` |
| `At.Age.Between(ctx, c, lo, hi)` | two scalars | `encrypt.Range[eql.JSONTreeLeafQuery]` | two predicates |
| `At.Age.Selector(ctx, c)` | none | `eql.JSONTreeSelector` (text) | `profile -> $1::text`, `ORDER BY eql_v4.ord_term(profile -> $1::text)` |
| `Selector(ctx, c, path)` | `string` path | `eql.JSONTreeSelector` | `->` / `->>` on any path |

Ordered paths get a generated accessor under `At` (decision 4), named from
the path (`$.age` becomes `Age`, or the name in an `as=`), so a typo in an
ordered path fails to compile. Equality at a path and extraction take a
runtime path, because they work at any path. The engine refuses a bad path
with `ErrTerm` and its reason, and never echoes the path text.

Refusals come from the engine, with its reasons:

- `JsonValueNotScalar`, for equality with a container;
- `JsonLeafNotOrdered`, for an ordering value that is not a number or
  string;
- `JsonPathNotOrdered`;
- `JsonTooDeep`, for nesting deeper than 127.

### Extraction and walks (phase 5, decision 5)

- **Decrypting an extracted node.** A `profile -> sel` result scans into
  `eql.JSONTreeEntry`. `Fields.Profile.OpenEntry(ctx, c, []eql.JSONTreeEntry)`
  returns the scalars as JSON text, and a container is refused, as the
  engine refuses it (`OpenedType`).
- **Subtree walks.** `Fields.Profile.SubtreeKey(ctx, c, path)` returns
  `eql.JSONTreeSubtreeKey`, which binds as the token and gates for
  `json_tree_subtree(_at)`. `key.Open(ctx, c, rows)` then rebuilds the
  value, including the fallback through the sealed root.

  This needs a new guest entry point, because the key's path is not on the
  wire and the open has to see it. It is the least settled part, so it
  ships last.

## Work, in PR-sized steps

Each step is one PR closing one issue. Steps 1-3 are Rust and unblock
everything after them.

1. **Catalog and Go types (eql-bindings, eql-codegen), #1348.**
   - Add the json_tree family to the catalog, to `v4::all()` and to the
     target table. `JSONTree`, `JSONTreeQuery`, `JSONTreeLeafQuery` and
     `JSONTreeEntry` then generate into `eql_gen.go`, with a not-producible
     reason that points at step 2. `JSONTreeSelector` is a text type, so
     check whether the generator can emit it or it needs hand-writing in
     `encrypt/eql`.
   - Report the family as not fixed-width, so stashgen requires
     `null=sql`.
   - Gates: `types:check`, `go_eql_parity`, the codegen tests.
2. **The data-plan form of the JSON index (stack-encrypt `dynamic`), #1349.**
   - Admit `IndexSpec::Json` with its options.
   - Accept the `json` source kind as JSON text, seal it to a
     `JsonDocument` through the same `Layout` the typed path uses, and open
     it back to JSON text.
   - Teach the guest's `EqlTargets` the family. `Producible` flips to true.
   - Tests:
     - a dynamic-versus-typed parity test, so the same document gives the
       same ciphertext under the same key and the same terms;
     - the mutants gate on the diff.
3. **Query by operator for json_tree (stack-encrypt, guest), #1350.**
   - Add `contains` and `contained_by`.
   - Add the path operators, taking a `{path, value}` input:
     `eq_at`, `lt/lte/gt/gte/between` at a path, and `selector`.
   - `se_operators` reports them per field, from the field's options.
   - `se_query_term` returns the query twin's JSON and domain, as for other
     EQL types.
   - Tests: Rust parity between the dynamic and typed paths.
4. **Go: stashgen, gensupport, the checker and the record model, #1351.**
   - Add the `JSONTree(...)` options on `encrypt_into`, a `json` `Kind`,
     the operator names in `parseOperatorName`, and `json` in
     `parseOperatorIndex`.
   - Generate `Contains`, `ContainedBy`, `EqAt`, `Selector` and the `At.*`
     accessors.
   - Retire the `encrypt.JSON()` / `JSONTerm` / `index=json` placeholders,
     which were the SteVec shape, or repoint them, so that a single
     `json` index name means json_tree. This needs a decision: see Open
     questions.
   - Tests:
     - stashgen golden output;
     - refusal tests (bad path, `null=sealed`, a position in an ordered
       path);
     - a fixture test that the Go-sealed document and terms equal the
       Rust-sealed ones under the deterministic guest;
     - a live `eql_postgres_test.go` case: round trip, `@>`, `<@`,
       equality at a path, ordering and `ORDER BY` at an ordered path, and
       `->`.
   - Docs: the Go README, the stashgen README, `doc.go` usage, the
     CHANGELOG.
5. **Extraction and walks in Go, #1352.** `OpenEntry`, `SubtreeKey` and `Open`,
   behind a new guest export. Live tests for walks, the sealed-root
   fallback and a node that is not a scalar.

The semantic oracle stays in Rust: #1345 holds encrypted containment to
`jsonb`. The Go tests check wiring and byte parity, not containment
semantics again.

## Decisions needed

1. **Which Go types a json_tree field may have.** Recommended:
   `json.RawMessage`, `[]byte`, and anything `encoding/json` marshals.
   - Alternative: `json.RawMessage` only. It is the strictest option and
     involves no reflection, but users would unmarshal by hand.
2. **How the value crosses the ABI.** Recommended: JSON text, so the
   engine parses it and the bytes match every language.
   - Alternative: a vcvalue map/sequence tree. vcffi can carry one, but
     Go's `encoding/json` decodes numbers to `float64`, which loses
     integers above 2^53 before the engine sees them.
3. **The type of a containment needle.** Recommended: `any` marshalled
   with `encoding/json`, documented. A needle built from the field's
   struct type carries zero values (`"age":0`), which silently narrows the
   match.
   - Alternative: the field's type `T`, which is concrete (Go-2) but has
     that trap whenever `T` is a struct without `omitempty`.
4. **How ordered paths are named.** Recommended: a generated accessor per
   ordered path under `At`, so a typo fails to compile.
   - Alternative: a runtime path string for everything, with fewer
     generated methods and errors found at run time.
5. **Scope of the first release.** Recommended: steps 1-4, which cover
   write, read, containment, equality at a path, ordering and
   `->` selectors. Walks and opening entries (step 5) follow.

## Open questions

- **`index=json` and `encrypt.JSON()`.** They were reserved for the EQL v3
  SteVec index, which is also `"json"` in `checker.go:179`. Is json_tree
  the only JSON index Go will ever offer? If so, delete the placeholders.
  If not, give json_tree its own name.
- **"Query building in Go"** is listed as not yet decided in the
  principles (line 213). The `At.*` accessors and the runtime-path methods
  are a first answer, and it should be recorded there.
- **The design doc's open items reach Go:**
  - The client does not yet check that a returned entry is the one at the
    path asked for (DOC:495).
  - The walk budget's default (DOC:391).
  - The stored entry order (DOC:494).

  None blocks steps 1-4. Step 5 should wait for the selector check.
- **Ordering.** The json_tree stack is 101 commits behind `next`, which
  carries the Go `null=` work, `eql_postgres_test.go` and the
  `eql-postgres` CI job. Step 4 needs both, so the stack lands on `next`
  first, or step 4 rebases onto it.
