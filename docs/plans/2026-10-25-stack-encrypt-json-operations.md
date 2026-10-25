# JSON tree: first-release operation contract and public examples

Date: 2026-10-25. Companion to the
[API plan](2026-10-24-stack-encrypt-api-plan.md) and
[public workflow examples](2026-10-24-stack-encrypt-public-examples.md).

## Status and scope

The customer requires a comprehensive first version. This document defines
the required operation inventory for Rust and the dynamic interface used by
Go. Extraction, opening extracted values, and subtree walks are included;
they are not a post-release phase. Internal implementation can still be
split into PRs. The feature is complete only when every required row below
has Rust, dynamic/Go, and applicable PostgreSQL coverage.

This is a target API contract, not a claim that these public signatures
already exist. Rust and JSON examples below propose the redesigned surface.
Final names/package paths are deliberately left to the last naming pass.
The [packaging glossary](2026-10-25-stack-encrypt-packaging.md#json-names-by-role)
now proposes that pass; this document retains its working names until review.
They are candidates for executable documentation during implementation;
they have not been compiled against today's API. Existing SQL spellings and
current behavior are separately identified. Do not publish these as current
SDK instructions until the acceptance suite runs them.

Sources reviewed:

- [Claude's Go JSON plan, PR #1353](https://github.com/cipherstash/stack/pull/1353),
  head `65ece530934d367e30ea99d1f149f76117191739`, still a draft when read.
  Tracking #1347; steps #1348–#1352. Its step-5 deferral is superseded here.
- [JSON tree design](2026-10-17-json-tree-index.md), including the Phase 4
  notes on extracted-path checking and stored order.
- [Engine query implementation](../../packages/stack-encrypt/src/json/query.rs),
  [path grammar](../../packages/stack-encrypt/src/json/path.rs),
  [derivation/opening](../../packages/stack-encrypt/src/json/derive.rs).
- [EQL target and result types](../../packages/eql/crates/eql-bindings/src/v4/json_tree.rs),
  [SQL functions](../../packages/eql/src/v3/json_tree/functions.sql),
  [operators](../../packages/eql/src/v3/json_tree/operators.sql),
  [refused operations](../../packages/eql/src/v3/json_tree/blockers.sql),
  and [leakage contract](../../packages/eql/docs/reference/json-tree-leakage.md).

The local source baseline is the reviewed `next` commit `b1049824b` and
this documentation branch. Untracked experimental EQL files are not used
as evidence of implemented JSON-tree behavior.

## Roles and shared policy

| Working name | Role |
| --- | --- |
| `JsonPlaintext` | Owned JSON input/output with `Zeroize`; an adapter around the engine's JSON value model, not ciphertext or a policy |
| `JsonOptions` | Validated target options: `sealed_root` and `ordered` paths |
| `EncryptedProfile` | Application-defined fixed-policy output wrapper |
| `JsonTreeDocument` | Existing EQL encrypted document envelope, stored in one column |
| `JsonTreeQuery` | Containment/path-equality query operand; cannot decrypt |
| `JsonTreeLeafQuery` | Ordering query operand; cannot decrypt |
| `JsonTreeSelector` | Encoded path selector, not a plaintext path or ciphertext |
| `JsonTreeEntry` | Extracted encrypted node with the metadata needed to open it |
| `JsonSubtreeKey` | Client-held walk request state: token, gates, requested path and policy binding |
| `JsonTreeSubtree` | Encrypted walk rows paired with their original request state |
| `JsonSelection` | Proposed owned plaintext result distinguishing missing, one value and multiple matches; implements `Zeroize` |

`JsonPlaintext` is a proposed library adapter, not a claim that
`serde_json::Value` implements `Zeroize`. It accepts JSON text without
requiring callers to implement their own cleanup trait. Returned plaintext
is owned by the caller. Future zeroization/timing work must not change the
stored representation.

One immutable definition supplies options, column identity, search scope
and ciphertext binding to every operation. Rust's derive builds it from a
typed options factory; dynamic loading deserializes the same options and
validates the same constraints. Query code never supplies a second options
object that can disagree with the write policy.

For a row-bound, tenant-scoped field:

- Ciphertext binding: declared column + tenant scope + row ID.
- Search selectors, value terms, ordering terms and walk-token derivation:
  declared column + tenant scope, with the operation's domain separation.
- Queries do not require row ID. Decrypting a selected document, entry or
  subtree requires it; SELECT examples must return that ID.
- Preserve JSON node selector/ordinal authentication in addition to these
  outer bindings. The engine currently combines context roles; implementing
  their separation is required, not just changing a derive attribute.

## Definitive first-release inventory

`q` below means the typed query result, not manually assembled EQL JSON.
SQL functions shown with `eql_v4` use the existing EQL v4 names. Parameter
types are explicit to avoid PostgreSQL selecting native jsonb operators.

| ID | Required operation | Rust surface / result | Dynamic operation / result | Database use |
| --- | --- | --- | --- | --- |
| J01 | Encrypt document: object, array, scalar or JSON null | `value.encrypt_into` → encrypted target | `encrypt` → typed EQL document | Store `eql_v4_json_tree` |
| J02 | Decrypt complete document | `JsonPlaintext::decrypt_from` → JSON | `decrypt` → JSON text | Read full column |
| J03 | Batch write/read | `Vec<_>` conversion composition | `encrypt_many`, `decrypt_many` | Preserve row/result ordering; shared executor |
| J04 | Contains | `query(op::Contains, value)` → `JsonTreeQuery` | `contains` → same EQL operand | `profile @> $1::eql_v4.query_json_tree` |
| J05 | Contained by | `query(op::ContainedBy, value)` → `JsonTreeQuery` | `contained_by` | `profile <@ $1::eql_v4.query_json_tree` |
| J06 | Scalar equality at path | `query(op::AtPath(op::Eq), (path, scalar))` → `JsonTreeQuery` | `eq_at` | Same containment predicate as J04 |
| J07 | Four ordering predicates | `AtPath(Lt/Lte/Gt/Gte)` → `JsonTreeLeafQuery` | `lt_at`, `lte_at`, `gt_at`, `gte_at` | `(profile -> $1::text) < $2::eql_v4.query_json_tree_leaf`, etc. |
| J08 | Inclusive range | `AtPath(Between)` → two leaf operands | `between_at` → lower/upper operands | `>= lower AND <= upper` |
| J09 | Sort ascending/descending | `Selector` query → selector; no bound value | `selector` | `ORDER BY eql_v4.ord_term(profile -> $1::text) ASC/DESC` |
| J10 | Path exists | `Selector` query | `selector` | `json_tree_path_exists(profile::jsonb, $1::text)` |
| J11 | Extract first match | `Selector` query → optional encrypted entry from DB | `selector`; result accepted by `decrypt_entry` | `profile -> $1::text` or `json_tree_path_query_first` |
| J12 | Extract first match as text | Same selector; parse text into `JsonTreeEntry` | Same selector; parse encrypted entry text | `profile ->> $1::text`; never plaintext |
| J13 | Extract all matches | Same selector → encrypted entry rows | Same selector; `decrypt_entries` | `json_tree_path_query(profile::jsonb, $1::text)` |
| J14 | Open extracted scalar(s) | `decrypt_from` on source bound to selection request | `decrypt_entry`, `decrypt_entries` with selection handle | No server decrypt; container markers refused |
| J15 | Prepare subtree/positional request | `query(op::Subtree, path)` → `JsonSubtreeKey` | `subtree_key` → handle + SQL parameters | Token/gates, derived under field scope/options |
| J16 | Fetch/open subtree | Request-bound `JsonTreeSubtree`, then `decrypt_from` | `decrypt_subtree` with walk handle | `json_tree_subtree` / `json_tree_subtree_at` |
| J17 | Enumerate immediate children | J15 key, encrypted child rows | J15 key; opening scalar children uses J14 with walk validation | `json_tree_children(profile, token, gates)` |
| J18 | Count immediate children | J15 key; result is integer | J15 key; database returns integer | `json_tree_child_count(profile, token, gates)` |
| J19 | Walk budget and sealed-root fallback | Same J16 plaintext result regardless of path taken | Same handle and result shape | Default budget 64; zero walks without fallback |
| J20 | Compare stored documents/ordered entries within one scope | Existing typed EQL operands; no new plaintext term | Existing typed EQL operands | Document `@>`/`<@`; entry `< <= > >=`; same policy/scope required |

J09–J13 and J17–J18 are SQL actions using a derived selector/key, not new
cryptographic primitives or SDK database execution methods. The dynamic
engine derives operands and opens results; the caller runs SQL. The
definition's capability discovery must describe both operand preparation
and the supported database use, including ordering-path restrictions.

J20 does not authorize whole-document `=` or equality via an ordering
term. Initial ORE support never answers `Eq`. JSON scalar equality remains
available through its independent exact value-selector mechanism. Any
future ORE equality capability must be explicit and limited to encodings
that preserve equality; text/lossy encodings remain ineligible.

## Path, null and result semantics

- Grammar: `$`, `.member`, `["member"]`, nonnegative `[n]`, and `[*]`.
  No filters, recursive descent or slices in this release.
- Selector-based operations address a path class across array elements.
  Existing selectors erase positions (`[2]` has the same selector as
  `[*]`). **Proposed first-class API rule:** reject positional paths for
  `EqAt`, selector extraction/existence and selector ordering rather than
  silently broadening them. Use the positional subtree route for exact
  `[n]` retrieval. This is a deliberate stricter wrapper than today's engine.
- Wildcard equality means at least one matching element has that scalar
  value. Containment preserves grouping within array elements; it is not
  an ungrouped bag of independent terms. Multiple independent EqAt SQL
  predicates do not imply the values belong to the same array element.
  Use one containment needle to require that correlation.
- Equality accepts null, boolean, string and supported JSON number values;
  objects/arrays are refused. Containers use containment, not an operator
  labelled equality. At `$`, equality asks for that scalar root, not an
  array containing it (which is containment semantics).
- Ordering is opt-in per path and accepts supported numbers/strings only.
  No implicit ordering at undeclared paths. A wildcard ordering policy can
  supply terms to many entries: `->` compares/sorts the first matching
  entry, while `json_tree_path_query` can enumerate all and an explicit
  SQL `EXISTS` chooses any-match semantics. Never present first-match as
  any-match, or term equality as exact plaintext equality.
- A missing path gives no extraction row (or SQL NULL for first-match).
  A present JSON null gives an encrypted entry that opens to JSON null.
  SQL NULL for an absent document is a separate field-null policy, not an
  encrypted JSON null. An empty object/array is neither missing nor null.
- JSON inputs cross the dynamic ABI as UTF-8 JSON text. No intermediate
  conversion of JSON numbers to Go `float64`; use raw JSON/number-preserving
  decoding. Define accepted numeric range and canonicalization from the
  engine, test `2`/`2.0`, negative zero and large integers. Reject values
  outside the supported representation rather than silently rounding them.
- SQL returns encrypted data, even with `->>`. A scalar node opens directly;
  an ordinary container node is a marker, not a serialized subtree. Use a
  subtree walk to reconstruct containers. The sealed root holds the whole
  document and has an explicit whole-document/fallback decode path.
- Selection/open requests retain expected selector, field definition and
  scope. Check the returned selector before opening: current code opens
  under server-supplied selectors, which is insufficient to establish the
  requested path. Row provenance requires explicit row binding. Walks must
  validate the path/selector relationships needed for their requested result.
  Successful decryption does not prove query completeness or authenticate
  every search/index metadata field.
- Requests for `$` (or root-array wildcards requiring a root token) under
  `sealed_root=true` use whole-document fetch/decrypt and local selection;
  never fabricate a nonexistent root token. For a missing/empty/scalar
  subtree where a descendants-only walk cannot distinguish the cases, use
  the selected start-node metadata or full-document fallback explicitly;
  do not treat an empty row set as an empty object by assumption.

## Rust write/read example

Proposed public code. `target(column = ...)` is illustrative declaration
syntax for an explicit EQL column identity; the exact attribute spelling
belongs to the forthcoming specification/naming pass. The options factory
is typed Rust, not JSON hidden inside an attribute.

```rust
use eql_bindings::v4::json_tree::JsonTreeDocument;
use serde::{Deserialize, Serialize};
use stack_encrypt::{DecryptFrom, DecryptSource, EncryptInto, EncryptTarget, StackCipher};
use stack_encrypt::json::{JsonOptions, JsonPlaintext};
use stack_encrypt::sem::TermError;
use std::error::Error;
use zeroize::Zeroize;

fn profile_options() -> Result<JsonOptions, TermError> {
    JsonOptions::new().ordering(["$.age", "$.visits[*].date"])
}

#[derive(Serialize, Deserialize, EncryptTarget, DecryptSource)]
#[serde(transparent)]
#[stash(
    plaintext = JsonPlaintext,
    transparent,
    target(column = ("users", "profile"), options = profile_options)
)]
struct EncryptedProfile(JsonTreeDocument);

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let client = StackCipher::new().await?;
    let keyset = client.default_keyset();
    let _definition = EncryptedProfile::definition()?;

    let profile = JsonPlaintext::parse(
        r#"{"age":42,"name":"Alice","visits":[{"date":"2026-10-01"}]}"#,
    )?;
    let encrypted: EncryptedProfile = profile.encrypt_into(&keyset).await?;

    // These bytes can instead be bound to the EQL PostgreSQL column.
    let stored = serde_json::to_vec(&encrypted)?;
    let loaded: EncryptedProfile = serde_json::from_slice(&stored)?;
    let mut opened = JsonPlaintext::decrypt_from(loaded, &keyset).await?;
    // The caller now owns the returned plaintext and its cleanup.
    opened.zeroize();

    let profiles = vec![
        JsonPlaintext::parse(r#"{"age":42}"#)?,
        JsonPlaintext::parse(r#"{"age":27}"#)?,
    ];
    let encrypted: Vec<EncryptedProfile> = profiles.encrypt_into(&keyset).await?;
    let mut opened = Vec::<JsonPlaintext>::decrypt_from(encrypted, &keyset).await?;
    assert_eq!(opened.len(), 2);
    opened.zeroize();
    Ok(())
}
```

This example explicitly declares column-wide scope and no row binding by
its fixed standalone definition; the normative schema must express that
choice rather than silently replacing missing required tenant scope.
For an output-derived `EncryptedUser` with `id: PrimaryKey<u64>` and
`tenant_id: ScopeKey<u64>`, select those fields through the context/scope
attributes described in the API plan. Obtain its JSON field handle from
`EncryptedUser::definition()?.profile()` and require `TenantId` on query
requests. Store/return both ID fields for decrypt. If caller input is used,
use the agreed `_with_context` variants with a typed input separating
binding and scope. No row ID is ever an index/query input implicitly.

## Rust query and extraction recipes

These snippets share `keyset` and a resolved definition `profile` from the
write example. Add `use stack_encrypt::{op, json::JsonPath};`. The `using`
selector chooses that definition before the operation. `Selector` and
`Subtree` are proposed operation markers integrating today's separate
`json_selector`/`json_subtree_key` helpers into the shared definition API.
All query operands below use the same plaintext JSON adapter as writes.

```rust
let profile = EncryptedProfile::definition()?;
let contains = keyset.using(&profile)
    .query(op::Contains, JsonPlaintext::parse(r#"{"name":"Alice"}"#)?)
    .await?;
let contained_by = keyset.using(&profile)
    .query(op::ContainedBy, JsonPlaintext::parse(r#"{"age":42,"name":"Alice"}"#)?)
    .await?;
let eq = keyset.using(&profile)
    .query(op::AtPath(op::Eq), ("$.name", JsonPlaintext::parse(r#""Alice""#)?))
    .await?;

let lt = keyset.using(&profile)
    .query(op::AtPath(op::Lt), ("$.age", JsonPlaintext::parse("65")?)).await?;
let lte = keyset.using(&profile)
    .query(op::AtPath(op::Lte), ("$.age", JsonPlaintext::parse("65")?)).await?;
let gt = keyset.using(&profile)
    .query(op::AtPath(op::Gt), ("$.age", JsonPlaintext::parse("18")?)).await?;
let gte = keyset.using(&profile)
    .query(op::AtPath(op::Gte), ("$.age", JsonPlaintext::parse("18")?)).await?;
let range = keyset.using(&profile)
    .query(op::AtPath(op::Between), (
        "$.age", (JsonPlaintext::parse("18")?, JsonPlaintext::parse("65")?),
    )).await?;

let age = keyset.using(&profile)
    .query(op::Selector, JsonPath::parse("$.age")?).await?;
let visit_dates = keyset.using(&profile)
    .query(op::Selector, JsonPath::parse("$.visits[*].date")?).await?;
```

The results carry named typed EQL payloads. For example, `lt.selector()`
and `lt` bind the selector and leaf operand in the ordering SQL below;
`range.lower()`/`upper()` name the two bounds (proposed accessors).
For static policies, generated ordered-path handles can add compile-time
checks; runtime paths still validate against the same definition before
term derivation. Missing definition/scope makes a Rust request unawaitable.

```sql
-- Containment/equality operands: bind the named query payload, not plaintext.
SELECT id, tenant_id, profile FROM users
WHERE profile @> $1::eql_v4.query_json_tree;

SELECT id, tenant_id, profile FROM users
WHERE profile <@ $1::eql_v4.query_json_tree;

-- Lower and upper bounds; use <, <=, >, >= individually for J07.
SELECT id, tenant_id, profile FROM users
WHERE (profile -> $1::text) >= $2::eql_v4.query_json_tree_leaf
  AND (profile -> $1::text) <= $3::eql_v4.query_json_tree_leaf
ORDER BY eql_v4.ord_term(profile -> $1::text) ASC NULLS LAST;

-- Existence, first encrypted entry, first entry as encrypted JSON text.
SELECT id, tenant_id FROM users
WHERE eql_v4.json_tree_path_exists(profile::jsonb, $1::text);
SELECT id, tenant_id, profile -> $1::text AS entry FROM users;
SELECT id, tenant_id, profile ->> $1::text AS entry_text FROM users;

-- All matching entries: group results by document before opening them.
SELECT u.id, u.tenant_id, e.entry
FROM users AS u
CROSS JOIN LATERAL eql_v4.json_tree_path_query(u.profile::jsonb, $1::text) AS e(entry);

-- Stored-to-stored comparisons require matching policy and search scope.
SELECT a.id, b.id FROM users AS a JOIN users AS b
  ON a.tenant_id = b.tenant_id AND a.profile @> b.profile;
SELECT a.id, b.id FROM users AS a JOIN users AS b
  ON a.tenant_id = b.tenant_id
 AND (a.profile -> $1::text) < (b.profile -> $1::text);
```

Add the application's tenant filter where appropriate; cryptographic scope
does not replace SQL authorization. A selector identifies a path class;
the SQL above never receives `$.age` or another plaintext JSON path.

Proposed request-bound opening preserves the expected path and avoids the
current server-supplied-selector ambiguity. Here `entry` and `entries` are
typed database results for the corresponding selection request, and each
batch belongs to the identified document/context:

```rust
let value = JsonPlaintext::decrypt_from(age.bind(entry)?, &keyset).await?;
let values = Vec::<JsonPlaintext>::decrypt_from(
    visit_dates.bind_many(entries)?, &keyset,
).await?;
```

`bind` is a proposed checked source adapter, not a second decrypt method.
For row-bound policies, call `decrypt_from_with_context` with that result
row's expected ID and required scope. Missing first-match rows stay absent;
do not manufacture an encrypted null. Containers use the walk route below.

## Walks, children, positional retrieval and fallback

```rust
let walk = keyset.using(&profile)
    .query(op::Subtree, JsonPath::parse("$.visits[0]")?).await?;

// After the SQL below returns all rows for one document:
let source = walk.bind_subtree(rows)?;
let visits = JsonSelection::decrypt_from(source, &keyset).await?;
```

`walk` retains the requested path, resolved scope and definition; only the
token/gates go to SQL. Exact positions are supported here, including the
necessary selector gate to distinguish an array element from an object
member at the same ordinal. The final specification must normalize result
cardinality through `JsonSelection`: a concrete path yields `Missing` or
`One(JsonPlaintext)`; wildcard paths yield `Many(Vec<JsonPlaintext>)` in
document order. Missing and an explicit JSON null remain distinguishable.
`bind_subtree`/opening must preserve that distinction. `JsonSelection` is a
working type name and is imported from the proposed JSON module.

```sql
-- $1: token; $2: gates; $3: budget (64 default, 0 disables fallback).
SELECT u.id, u.tenant_id, w.entry
FROM users AS u
CROSS JOIN LATERAL eql_v4.json_tree_subtree_at(
    u.profile, $1::text, $2::text[], $3::integer
) AS w(entry);

-- With no gates, the dedicated form is also supported.
SELECT u.id, u.tenant_id, w.entry
FROM users AS u
CROSS JOIN LATERAL eql_v4.json_tree_subtree(
    u.profile, $1::text, $2::integer
) AS w(entry);

-- Immediate children and counts use the same token/gates.
SELECT u.id, u.tenant_id, c.entry
FROM users AS u
CROSS JOIN LATERAL eql_v4.json_tree_children(
    u.profile, $1::text, $2::text[]
) AS c(entry);
SELECT id, tenant_id,
       eql_v4.json_tree_child_count(profile, $1::text, $2::text[])
FROM users;
```

Use one request-bound source per document; do not merge entries from several
rows into a subtree. Immediate scalar children can use checked entry
opening; container children need their complete descendants or an explicit
full-document fallback. The SDK must expose this distinction rather than
pretend that a container marker decrypts to its children.

Budget 64/0 are current SQL semantics to retain in the first public scope.
When `sealed_root=true`, an over-budget walk returns the sealed root instead
of partial data; the client opens it and selects the original requested
path. With `sealed_root=false`, walk the full result or report an explicit
resource limit, never silently truncate it. The same requested value(s)
must result from budget 0 and fallback. Tokens reveal subtree structure
within their search scope and are not decryption keys; document their
existing leakage and lifetime with these examples.

## Dynamic definition and operation examples

These are logical JSON messages for the specification, not a promise to
replace the frame ABI with JSON. The host/guest transport encodes their
typed equivalents. `using` identifies a validated field definition; the
engine, not Go, creates EQL envelopes and query terms. Naming the definition
in a request must resolve to the same options and scope contract as writes.

The fixed-column example's dynamic counterpart is:

```json
{
  "version": 1,
  "name": "users.profile",
  "plaintext": "json",
  "target": {
    "name": "JsonTreeDocument",
    "column": { "table": "users", "column": "profile" },
    "options": { "sealed_root": true, "ordered": ["$.age", "$.visits[*].date"] }
  },
  "search_scope": { "kind": "column" },
  "context": { "kind": "none" }
}
```

`version: 1` is an illustrative schema version, to allocate in the formal
specification. Named types are optional. For tenant/row policies use the
accepted `ScopeKey`/`PrimaryKey` declarations and source selectors; the
resolved query input requires the tenant scope but never the row ID.

Request corpus (each array element is an independent example, not one
batch of mixed operations). JSON text is deliberately explicit so no host
float conversion precedes the engine parser:

```json
[
  { "operation": "encrypt", "using": "users.profile", "value": { "json_text": "{\"age\":42}" } },
  { "operation": "encrypt_many", "using": "users.profile", "values": [{ "json_text": "{\"age\":42}" }, { "json_text": "{\"age\":27}" }] },
  { "operation": "query", "using": "users.profile", "operator": "contains", "input": { "json_text": "{\"age\":42}" } },
  { "operation": "query", "using": "users.profile", "operator": "contained_by", "input": { "json_text": "{\"age\":42,\"name\":\"Alice\"}" } },
  { "operation": "query", "using": "users.profile", "operator": "eq_at", "input": { "path": "$.name", "json_text": "\"Alice\"" } },
  { "operation": "query", "using": "users.profile", "operator": "lt_at", "input": { "path": "$.age", "json_text": "65" } },
  { "operation": "query", "using": "users.profile", "operator": "lte_at", "input": { "path": "$.age", "json_text": "65" } },
  { "operation": "query", "using": "users.profile", "operator": "gt_at", "input": { "path": "$.age", "json_text": "18" } },
  { "operation": "query", "using": "users.profile", "operator": "gte_at", "input": { "path": "$.age", "json_text": "18" } },
  { "operation": "query", "using": "users.profile", "operator": "between_at", "input": { "path": "$.age", "lower": { "json_text": "18" }, "upper": { "json_text": "65" } } },
  { "operation": "query", "using": "users.profile", "operator": "selector", "input": { "path": "$.age" } },
  { "operation": "query", "using": "users.profile", "operator": "selector", "input": { "path": "$.visits[*].date" } },
  { "operation": "query", "using": "users.profile", "operator": "subtree_key", "input": { "path": "$.visits[0]" } }
]
```

Responses carry a result kind and typed payload: document, containment
operand, leaf operand, range, selection, or walk request. SQL preparation
returns the named domain and encoded payload (or typed token/selector
parameters); it does not concatenate SQL. Selectors serve J09–J13, and walk
keys serve J16–J19, so those SQL uses do not need redundant engine opcodes.

For decode operations, this table specifies the dynamic signatures. Values
such as `document` and `entries` mean complete validated EQL payloads, not
literal placeholder strings to parse as ciphertext:

| Operation | Required inputs | Result |
| --- | --- | --- |
| `decrypt` | `using`, `document`, required context/scope | JSON text |
| `decrypt_many` | `using`, documents with per-record context/scope | JSON texts in input order |
| `decrypt_entry` | `using`, `selection_handle`, entry, required context/scope | Scalar JSON text |
| `decrypt_entries` | `using`, selection/walk handle, entries grouped by record and context | Ordered scalar JSON texts |
| `decrypt_subtree` | `using`, `walk_handle`, complete rows for one document, required context/scope | Explicit missing / one JSON value / multiple matches |

The response to `selector`/`subtree_key` includes an opaque request handle
in addition to SQL parameters. The handle retains the path and resolved
definition/scope in the engine, so callers cannot accidentally substitute
arbitrary path/options during decode. Specify handle lifetime and release
in the guest ABI; handles are not persistent database values. If the host
must recreate one after restart, derive it again from the original request,
not from server-returned metadata. Stale or mismatched handles are errors.
An equivalent Rust source adapter retains the same state directly.

Example host orchestration, using proposed dynamic method names rather
than inventing ciphertext strings in a JSON example:

```rust
let loaded = dynamic.load_definition(definition_json)?;
let encrypted = loaded.encrypt(json_text, inputs).await?;
let stored = database.store(encrypted).await?;
let opened = loaded.decrypt(stored, decrypt_inputs).await?;

let selection = loaded.selector("$.age", scope).await?;
let entry = database.select_first(selection.sql_parameters()).await?;
if let Some(entry) = entry {
    let age = loaded.decrypt_entry(&selection, entry, row_inputs).await?;
}

let walk = loaded.subtree_key("$.visits[0]", scope).await?;
let rows = database.subtree(walk.sql_parameters(), 64).await?;
let result = loaded.decrypt_subtree(&walk, rows, row_inputs).await?;
```

This is an orchestration recipe: `database` represents application SQL,
not a new Stack Encrypt database driver; the input variables are supplied
by that application. Generated Go methods should hide these message details,
use named results, and call the same validated dynamic operations. JSON
marshalling helpers must not force a containment needle into a whole record
struct whose zero-valued fields accidentally narrow the query.

## Explicitly unsupported operations

The comprehensive first release covers the inventory, not all PostgreSQL
JSON operators. Reject whole-document `=`/`<>` as plaintext equality,
entry equality through ordering terms, plaintext path SQL operands,
JSONPath filters/recursive descent/slices, and in-place encrypted document
patch/delete/concatenation. Updates read/decrypt, modify, then encrypt the
complete document. Projection extraction does not confer the ability to
write a standalone node back into an existing tree.

Reject malformed JSON/path/options; unsupported numeric values; container
EqAt operands; boolean/null ordering operands; undeclared ordering paths;
selector-position ambiguity; missing scope/context; unknown/expired request
handles; and wrong definition/scope/path during opening. Preserve useful
reason codes and structural locations without echoing plaintext values.
Structural validation that needs no key must precede key I/O. The current
engine refusal names include `JsonValueNotScalar`, `JsonLeafNotOrdered`,
`JsonPathNotOrdered`, `JsonOrderingAtPosition`, `JsonTooDeep`,
`JsonTooWide`, `JsonSealedRoot`, and `OpenedType`; final dynamic codes must
map deliberately rather than exposing unstable Rust enum spellings.

## Implementation gaps and release gates

1. **Shared definitions and scope separation.** Implement fixed/dynamic
   target resolution, typed options, scope-role validation, row-binding
   inputs and matching write/query context derivation. Generate capability
   metadata from one registry, including JSON-specific operand/result kinds.
2. **Catalog/guest coverage.** Complete the JSON tree catalog, target table,
   guest registration, dynamic index execution and JSON-text record kind.
   Current Rust helpers/EQL types are not evidence that Go supports them.
3. **Direct EQL adapters.** Replace the existing serialization round trip
   with typed conversions for documents, entries and operands.
4. **Selectors and opening.** Add the request-bound source adapters and
   dynamic handles, validate expected selectors, preserve required row
   context, and test mismatched results and missing headers/ordinals.
5. **Walk completeness.** Cover children/counts, concrete positions,
   wildcards, empty containers, missing paths, scalar starts, root requests,
   sealed-root on/off and budgets 0/64. Resolve reconstruction ambiguities
   explicitly, including returning/fetching the start node when needed.
   Do not ship opening/walks later under the earlier PR #1353 scope.
6. **Conformance/documentation.** Turn J01–J20 into identified test cases
   and the examples into checked docs. Run Rust writes → Go reads/queries
   and Go writes → Rust reads/queries against PostgreSQL. Include negative
   cases, exact number handling, null distinctions, multi-element correlated
   containment, and batch ordering. Test SQL GIN/btree usage on representative
   containment/range queries. Randomized ciphertexts need semantic parity;
   deterministic fixtures are only for explicitly seeded test builds.

The current wire order/leakage and extraction trust boundaries must be
documented accurately. This operation inventory does not claim a new
authenticated-query-completeness protocol or a storage-order leakage fix.
Stable blob framing is a separate deliverable tracked in
[Vitamin C #519](https://github.com/cipherstash/vitaminc/issues/519); it must
not be confused with the EQL JSON-tree storage format.
