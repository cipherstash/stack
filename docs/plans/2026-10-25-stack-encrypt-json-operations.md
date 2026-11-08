# JSON tree: operation inventory and release contract

Updated 7 November 2026 against merged `next` at commit `e4990e49b`. The
previous update was on 27 October 2026, at `ffeed7adb`. This document accompanies the
[API plan](2026-10-24-stack-encrypt-api-plan.md).

## Summary

The Go JSON feature is implemented, through #1372, #1373, #1378, and #1402.
This document lists every JSON operation the release needs, with what is
supported now and what work remains. Each operation has an ID from J01 to
J20, used in the table of operations below. Two operations still have
gaps: J14 and J17. The SQL types and functions come from Encrypt Query
Language (EQL).

Since 27 October 2026, two operations have been added as J21 and J22.
J21 tests several conditions on one array element. J22 sends a jsonpath
predicate as one query parameter. Both are in the engine, EQL, and Go. The
`eql-json-v1` conformance profile, from #1492, enrols the JSON operations
in Rust, Go, and PostgreSQL tests.

From 7 November 2026, the stored format of Go `v0.1.0-rc.3` must not
break. The stored format is what is written to the database, such as JSON
tree entries and their search terms. See the [API
plan](2026-10-24-stack-encrypt-api-plan.md#the-stored-format-stays-compatible-with-go-rc3).

The Rust example in this document uses the proposed public derive and
facade. That example is not executable code for the current engine. The
[refreshed Go plan](https://github.com/cipherstash/stack/blob/docs/go-json-tree-plan/docs/plans/2026-10-24-go-json-tree.md)
and its findings on the engine and Go give the exact source evidence.

## Terms used in this document

| Term | Meaning |
| --- | --- |
| EQL | The SQL in `packages/eql` that stores and queries encrypted values |
| Entry | The encrypted record for one node of a document. A document is stored as one entry for each object, array, and scalar in it |
| Selector | A keyed pseudorandom value derived from a node's path, with every array position replaced by the wildcard. Every element of an array shares one selector |
| Token | A value derived from a node's concrete path. The database uses it to find that node and the entries beneath it |
| Needle | The JSON value that a containment query looks for |
| EqAt | Equality of a scalar at a path: `EqAt` in Go, `eq_at` in the dynamic engine |
| Containment projection | The set of selector and value pairs, one for each node, stored beside the entries. PostgreSQL's `jsonb @>` compares two of these sets to test containment |
| Subtree read | A read that returns a node and every entry beneath it, through `eql_v4.json_tree_subtree`, and opens them as one value |
| Cascaded tags | Each container's authentication tag covers the tags of its children, so a change anywhere below a node stops that node opening. Added by #1379 |
| Sealed root | The default. The root entry's ciphertext is the whole document, and the root token finds no other entry |
| A JSON document whose root is not sealed | The root is stored as an ordinary container entry (`sealed_root` false). Called "open root" in the code |
| Walk budget | The most entries a subtree read returns, counted across all its tokens, before the database falls back to the root |
| Root fallback | Past the walk budget, the database returns the sealed root alone. The client opens the whole document and picks out the requested values |
| Wildcard bound | How many elements each `[*]` in a read path expands to. One extra probe at the bound detects a longer array |
| Reads that Rust verifies against the original request | Prepared reads: Rust derives the request again when the rows are opened, and checks every row against it |
| Post-cascade format | The JSON storage and search format after #1379 added cascaded tags. Go rc.3 writes it, so it must stay compatible |
| Conformance profile | A named, versioned set of test cases for one area, such as `eql-json-v1`. Each language runs the same cases. The files are in `conformance/stack-encrypt/v1/` |
| Facade | The proposed public Rust API of `stack-encrypt` |
| Context | Data that a ciphertext is tied to, such as a column name or a row ID. Decryption needs the same context. See [Context and AAD](2026-10-24-stack-encrypt-api-plan.md#context-and-aad) |
| AAD | Additional authenticated data: data that encryption checks for one ciphertext, but does not encrypt. Stack Encrypt builds it from the context. See [Context and AAD](2026-10-24-stack-encrypt-api-plan.md#context-and-aad) |

## Current names

| Role | Current public name in Go, the dynamic engine, and SQL |
| --- | --- |
| Configured target | `JsonSearch` |
| Encrypted document | `eql.JSONSearch`, `public.eql_v4_json_search` |
| Operand for containment and EqAt | `eql.JSONSearchQuery`, `eql_v4.query_json` |
| Operand for ordering | `eql.JSONSearchLeafQuery`, `eql_v4.query_json_leaf` |
| Encrypted entry | `eql.JSONEntry`, `public.eql_v4_json_entry` |
| Prepared selector and prepared subtree read | `encrypt.JSONSelection`, `encrypt.JSONRead` |
| SQL capability values | `JSONSelector`, `JSONToken`, `JSONTokens` |
| Result of opening one value | `JSONValue{Found, JSON}` |
| Operand for several conditions on one array element | `eql.JSONSearchElementsQuery`, `eql_v4.query_json_elements` |
| Operand for a compiled jsonpath predicate | `eql.JSONSearchPredicateQuery`, `eql_v4.query_json_predicate` |

The handwritten Rust EQL adapters keep their `JsonTree*` names. The
internal engine type `JsonDocument` is not the Go ciphertext type.
`eql.JSON` is the type for storage only. Do not use the old domains
`query_json_tree` and `eql_v4_json_tree` in current recipes.

## Context and scope policy

The SDK resolves the target options configured for a field into native
`JsonOptions`. The SDK uses the same options for writes, queries, and
reads. The released configuration takes a document's context from its column, and its keys from the selected keyset.

The API plan's [query context and stored
context](2026-10-24-stack-encrypt-api-plan.md#query-context-and-stored-context)
replace the earlier idea of a separate row binding and search scope. A
binding, such as a row ID, is in the stored context and not in the query
context. Today an EQL type takes its context from its column only. So
until that work lands:

- a declaration that asks for a scope or a binding on an EQL field is
  refused;
- a row ID is never added to the shared context.

A query does not isolate rows only because the ciphertexts it returns
authenticate.

## Required operations and current support

| ID | Operation | Current support | Limits and remaining work |
| --- | --- | --- | --- |
| J01 | Encrypt an object, array, scalar, or null | Implemented. Raw JSON supports every kind of root. Typed adapters support declared structs, maps, and slices | None listed |
| J02 | Decrypt a complete document | Implemented, to raw JSON text or a declared Go type | None listed |
| J03 | Write and read in batches | Implemented, with a shared executor and chunking by the provider | None listed |
| J04 | Contains | Implemented: `Contains`, `contains`, and `@>` with `query_json` | Generated code checks the needle and refuses some shapes |
| J05 | Contained by | Implemented: `ContainedBy`, `contained_by`, and `<@` | None listed |
| J06 | Scalar equality at a path | Implemented: `EqAt`, `eq_at` | Compares value selectors, not ordering terms. J21 keeps several tests on one array element |
| J07 | The four ordering predicates | Implemented in runtime paths and in `At.<Path>` accessors | Ordered number and string paths only |
| J08 | Inclusive range | Implemented: `Between`, `between_at`, with named lower and upper operands | None listed |
| J09 | Sort | A selector and explicit SQL | Sorting at a wildcard path needs a defined reduction. Do not assume the first array element |
| J10 | Path exists | A selector and `json_tree_path_exists` | None listed |
| J11 | Extract one match | A selector and `->`, or the first result of a path query | At a wildcard path, which element is returned is unspecified |
| J12 | Extract as encrypted text | `->>` | The result is still encrypted entry JSON, not plaintext |
| J13 | Enumerate all matches | An SQL path query | The supported way to get grouped plaintext is a subtree read with a wildcard bound |
| J14 | Open extracted scalars | `JSONSelection.Open` opens one optional entry for each document group | Groups with more than one entry for a selector are refused. Do not label them supported |
| J15 | Prepare a read at a position or wildcard | Implemented: `Subtree`, `subtree`. Returns a token list, and keeps the trusted request | None listed |
| J16 | Fetch and open a subtree | `json_tree_subtree(document, tokens, budget)`, then `JSONRead.Open` or `OpenOne` | None listed |
| J17 | Immediate children | `children(path)` prepares a concrete token. SQL returns the child entries | Opening child scalars bound to their parent is not implemented |
| J18 | Count children | A `ChildCount` token. SQL returns a count that can be NULL | The count is not an authenticated proof of completeness |
| J19 | Walk budget and root fallback | Implemented. After root fallback, the client applies the selection originally requested | None listed |
| J20 | Comparisons between stored values | Existing document containment and entry ordering | Only within a compatible column, keyset, and storage format |
| J21 | Several conditions on one array element | Implemented in the engine and EQL (#1445), and in Go as `Elements.<Array>.Match` (#1451) | Needs ordered paths. Uses no index |
| J22 | A jsonpath predicate as one parameter | Implemented in the engine and EQL as `match` and `@@` (#1446), and in Go as `Match` (#1452) | Supports a subset of jsonpath. Uses no index |

Status on 7 November 2026: no merged pull request changes J14 or J17. The
`eql-json-v1` profile enrols tests for J01 to J08, J10, J11, J15, J16, and
J19, with J21 and J22. Its requirement IDs are not the J numbers. I made this mapping from that conformance profile's contract. I did not check it test by test.

In J21, equality compares folded ordering terms, not exact values. In J22, the EQL reference documents five cases where the answer differs from `jsonb_path_match`.

### Open requirements for J13 and J17

The release still needs every operation in the table. Closed tracking
issues do not mean an opener bound to the parent exists.

For J17, build an opener for child scalars that is bound to their parent.
Do not pass child rows to an unrelated selector or subtree request. Until
the opener exists, fetch and open the parent's subtree to inspect its
children. Document that this transfers different data and leaks
differently.

For J13, enumerating all matches in SQL is not the same as the supported
interface. The supported interface returns plaintext from a bounded
subtree read.

## Semantics that changed or are now implemented

- **Random order.** #1379 randomises the stored order of entries, the
  ordinals of object members, and the order of the containment
  projection. `->` at a wildcard selects an unspecified element. For
  ordering or sorting, use all matches with an explicit `EXISTS`, `MIN`,
  or `MAX` rule.
- **Cascaded tags.** Each container's tag covers its children's
  ciphertext tags. A container entry with children, opened on its own,
  fails with `JsonNotALeaf`. The same error is returned for an altered
  entry. An empty container entry authenticates, but fails with
  `OpenedType`. Every ordinary container needs a subtree read. A sealed
  root that the caller asks for can still open as a complete document.
- **No positional paths in queries.** The dynamic engine now rejects
  positional paths for selectors, ordering, and EqAt. Concrete positions
  such as `[n]` are for subtree reads. A wildcard selector addresses every
  path that differs only in its array positions. Two separate EqAt
  predicates can match different elements of one array. One containment
  needle keeps them matched to the same element. So does J21.
- **Native `jsonb` functions give wrong answers.** The encrypted column is
  a PostgreSQL domain over `jsonb`. So PostgreSQL's own `jsonb` functions
  accept it, and run over the stored envelope, not the document. For
  example, `jsonb_path_match(col, ...)` returns false for every row, with
  no error. #1444 documents this and does not block the functions.
- **Strict checks on JSON input.** The Rust parser now rejects duplicate
  keys and out-of-range integer literals before key I/O, that is, before
  any request to the key provider. For typed Go values, Go encodes first,
  with `encoding/json`. That package replaces invalid UTF-8. The parser
  checks raw JSON directly. Neither path promises to keep the JSON text
  byte for byte.
- **NULL, missing, null, and empty are different results.** SQL NULL, a
  missing selection, JSON null, and an empty container are different. `JSONValue.Found` records
  whether the selection was present. `OpenOne` rejects wildcards. Subtree
  reads that return several values return the requested values in
  document order.
- **Reads that Rust verifies against the original request.** A prepared
  read keeps the cipher, the field definition, the path, and the wildcard
  bound. `Open(ctx, rows)` asks Rust to derive the request again and
  verify it. No serialised key handle local to the guest is needed. Rows
  cannot supply their own expected path. Keep one group for each database
  document.
- **What cascaded tags do not prove.** Cascaded tags make verification
  stronger beneath the node at the top of a returned read. Cascaded tags
  do not authenticate the whole result set, the absence of a value, freshness,
  or that the row is the intended database row. The database can still
  withhold whole results or probes.
- **Defaults for reads.** The wildcard bound defaults to 64, with probes
  at the bound and a cap of 8,192 tokens. The walk budget is separate, and
  also defaults to 64. A walk budget of 0 turns off root fallback. A JSON
  document whose root is not sealed cannot fall back to the sealed root.
  The walk budget does not limit the size of every response.
- **Header version.** The header version is still 1, although the cascade
  changed what the AAD binds. Freeze the post-cascade format explicitly. Go rc.3 writes this format. Since 7 November 2026, a later change must
  keep it readable and searchable, or add a new header version beside it.
  The unchanged header does not show compatibility with older prototype
  ciphertexts. The query projection order is now random, so parity tests
  need to compare projections in a canonical form, by meaning.

## Current SQL recipes

The examples assume a column declared as
`profile public.eql_v4_json_search`. Each parameter is a query, selector,
or token value that the SDK generates, never a plaintext path. Add the
application's usual authorisation and tenant predicates.

```sql
-- Contains / contained by / EqAt operands.
SELECT id, profile FROM users WHERE profile @> $1::eql_v4.query_json;
SELECT id, profile FROM users WHERE profile <@ $1::eql_v4.query_json;

-- A single-valued ordered path: selector, lower bound, upper bound.
SELECT id, profile FROM users
WHERE (profile -> $1::text) >= $2::eql_v4.query_json_leaf
  AND (profile -> $1::text) <= $3::eql_v4.query_json_leaf
ORDER BY eql_v4.ord_term(profile -> $1::text) ASC NULLS LAST;

-- Wildcard ordering: explicitly existential, not an unspecified -> match.
SELECT u.id FROM users AS u
WHERE EXISTS (
  SELECT 1
  FROM eql_v4.json_tree_path_query(u.profile::jsonb, $1::text) AS x(entry)
  WHERE x.entry > $2::eql_v4.query_json_leaf
);

SELECT id FROM users
WHERE eql_v4.json_tree_path_exists(profile::jsonb, $1::text);
SELECT id, profile -> $1::text AS entry FROM users;
SELECT id, profile ->> $1::text AS encrypted_entry_text FROM users;

-- Token list, then walk budget. Group entries by id before opening.
SELECT u.id, w.entry FROM users AS u
CROSS JOIN LATERAL eql_v4.json_tree_subtree(
  u.profile, $1::text[], $2::integer
) AS w(entry);

-- Children/count take one concrete node token, with no gates parameter.
SELECT u.id, c.entry FROM users AS u
CROSS JOIN LATERAL eql_v4.json_tree_children(u.profile, $1::text) AS c(entry);
SELECT id, eql_v4.json_tree_child_count(profile, $1::text) FROM users;
```

The child count is 0 for a scalar or an empty container. The count is
NULL for a missing node or for the sealed root. Do not convert NULL to 0.

The earlier recipes with tokens and gates, and with
`json_tree_subtree_at`, are removed.
[The JSON example](../../languages/golang/encrypt/example/json/main.go)
contains complete current Go programs and examples of binding parameters.

## Current dynamic grammar and results

The example below shows the implemented syntax of a data plan. It leaves
out a versioned outer envelope:

```json
{
  "profile": {
    "type": "json",
    "context": ["users", "profile"],
    "target": {
      "name": "JsonSearch",
      "options": {"sealed_root": true, "ordered": ["$.age"]}
    }
  }
}
```

Operations select the field through the application binary interface
(ABI) between the host and the guest. The named inputs of operations
include:

- `{"json"}`
- `{"path","json"}`
- `{"path","low","high"}`
- `{"path"}`
- `{"path","wildcard_bound"}`

Since #1445 and #1446, two more operations take these inputs:

- `element_match` takes `{"path", "wildcard_bound", "predicates"}`. The
  `wildcard_bound` is optional.
- `match` takes `{"predicate", "vars"}`, as `jsonb_path_match` does.

JSON values are UTF-8 JSON text. Query results state the `encoding`
(`eql`, `text`, `text_array`, or scalar `bytes`), the SQL domain, and the
operands. Capabilities state the shapes of input.

To open, call `json_open` or `se_json_open` with the original `selector`
or `subtree` request and the grouped encrypted rows.

A general versioned package of definitions and schemas is still required
work. That package is not the current runtime grammar.

## Proposed Rust write and read example

The code below is proposed public code, not executable code for the
current engine.
`target(column = ...)` illustrates syntax that declares an explicit EQL
column identity. The coming specification and naming pass decides the
exact attribute spelling. The options factory is typed Rust, not JSON
hidden inside an attribute.

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
    let _plan = EncryptedProfile::encryption_plan();

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

### Scopes and bindings in the example

The example's declaration has no caller-supplied parts, so its query
context is the column. Its stored context is the column too. The schema
must state that choice. It must not add a tenant scope that the caller
did not declare.

To add a tenant scope and a row binding, declare them on the record. The
[API
plan](2026-10-24-stack-encrypt-api-plan.md#query-context-and-stored-context)
uses `scope(tenant: u64)` and `bind(row: Uuid)` as placeholder spellings.
Then:

1. A write passes both: `Scope::new(tenant).bind(row_id)`.
2. A query takes the scope only, from the document's marker:
   `EncryptedUser::PROFILE.contains(needle).scope(tenant).encrypt(&keyset)`.
   The query builder has no `bind`, so a row ID is never a query input.
3. A read passes both, or reads a stored part from the row and passes it
   to check it.

## Remaining work and release gates

1. Write down the implemented wire grammar, errors, and presence states in the formal specification and the promised conformance tests. Write down the context rules of the released configuration there too. General Rust definitions,
   caching, and more context roles can come later.
2. Close the stated scope gaps in J14 and J17. Subtree reads are the
   supported way to get plaintext for all matches. An opener for children
   bound to their parent is separate engine work. Do not add generic
   decryption of raw entries as a shortcut.
3. Replace the internal EQL bridge with typed conversion. The bridge
   serialises to `Value` and deserialises again. Keep the stored format.
   The change is an optimisation, not a missing execution path for Go
   JSON.
4. Run the existing Rust, guest, Go, and PostgreSQL suites on the release
   candidate, and map the tests to J01 to J20. Include:
   - typed and raw inputs;
   - numeric and null cases;
   - both root policies (sealed and not sealed);
   - wildcard bounds;
   - root fallback;
   - tampering that the cascaded tags detect;
   - the known limits on detecting omitted results.

   Inspect the real SQL parameter casts and index use.
5. Freeze the post-cascade storage and search vectors and the matching EQL
   bundle. Compare projections by their canonical meaning, and test
   cross-opening (one implementation opening another's ciphertexts).
   Ordinary random bytes do not need to match. Replace the temporary Go
   pins of Vitamin C before a final release. Opaque storage is already
   adopted. Opaque storage is a separate format from JSON tree storage.

### Status of this work on 7 November 2026

| Item | Status |
| --- | --- |
| 1. Specification and conformance | Partly done. #1492 adds the `eql-json-v1` conformance profile. That profile is experimental: it does not certify a whole SDK |
| 2. J14 and J17 | Still open |
| 3. Typed EQL conversion | Still open |
| 4. Run the suites on the release candidate | Partly done. #1492 runs them in CI, including a job against PostgreSQL |
| 5. Freeze the stored vectors and the EQL bundle | Still open. Go rc.3 already writes this format, so the frozen format must keep it readable |

## What this refresh did not check

This refresh is a review of source and documentation, not a new runtime
test run or a complete cryptographic audit.

Later activities in the API plan include:

- compiling the final Rust example;
- extracting packages;
- stronger zeroisation and constant-time work.

These activities must keep the released Go and data contract.
