# JSON tree: operation inventory and release contract

Updated: 2026-10-27 against merged `next`
`ffeed7adb3f7d8739cda53261046147852bffc82`. Companion to the
[API plan](2026-10-24-stack-encrypt-api-plan.md).

The Go JSON feature is implemented through #1372/#1373/#1378/#1402. This
inventory distinguishes current support from remaining requirements. The
public Rust derive/facade example below remains proposed, not executable
code for the current engine. The
[refreshed Go plan](https://github.com/cipherstash/stack/blob/docs/go-json-tree-plan/docs/plans/2026-10-24-go-json-tree.md)
and its engine/Go findings document the exact source evidence.

## Current names and policy

| Role | Current public Go / dynamic / SQL name |
| --- | --- |
| Configured target | `JsonSearch` |
| Encrypted document | `eql.JSONSearch`, `public.eql_v4_json_search` |
| Containment / EqAt operand | `eql.JSONSearchQuery`, `eql_v4.query_json` |
| Ordering operand | `eql.JSONSearchLeafQuery`, `eql_v4.query_json_leaf` |
| Encrypted entry | `eql.JSONEntry`, `public.eql_v4_json_entry` |
| Prepared selector / subtree | `encrypt.JSONSelection`, `encrypt.JSONRead` |
| SQL capability values | `JSONSelector`, `JSONToken`, `JSONTokens` |
| Singular plaintext result | `JSONValue{Found, JSON}` |

Handwritten Rust EQL adapters retain their `JsonTree*` names; the internal
engine `JsonDocument` is not the Go ciphertext type. `eql.JSON` is the
storage-only type. Do not use the old `query_json_tree` / `eql_v4_json_tree`
domains in current recipes.

A field's configured target options are resolved into native `JsonOptions`
and reused for writes, queries and reads. The shipped profile uses column
identity and keyset selection. Separate row binding and search scope remain
accepted future API work, not supported EQL context inputs. Reject those
unsupported declarations; do not append row IDs to the existing shared
context. Queries do not gain row isolation merely because their returned
ciphertexts authenticate.

## Required inventory and current support

| ID | Operation | Current behavior / remaining work |
| --- | --- | --- |
| J01 | Encrypt object/array/scalar/null | Implemented; raw JSON supports every root, typed adapters support declared structs/maps/slices |
| J02 | Decrypt complete document | Implemented; raw JSON text or declared Go type |
| J03 | Batch write/read | Implemented; shared executor and provider chunking |
| J04 | Contains | Implemented `Contains`, `contains`, `@>` with `query_json`; generated needle guards apply |
| J05 | Contained by | Implemented `ContainedBy`, `contained_by`, `<@` |
| J06 | Scalar equality at path | Implemented `EqAt`, `eq_at`; value selectors, not ordering equality |
| J07 | Four ordering predicates | Implemented runtime paths and `At.<Path>` accessors; ordered number/string paths only |
| J08 | Inclusive range | Implemented `Between`, `between_at`, named lower/upper operands |
| J09 | Sort | Selector plus explicit SQL; wildcard sort needs defined reduction, not an assumed first array element |
| J10 | Path exists | Selector plus `json_tree_path_exists` |
| J11 | Extract one match | Selector plus `->` / path-query-first; wildcard choice is unspecified |
| J12 | Extract as encrypted text | `->>`; still encrypted entry JSON, not plaintext |
| J13 | Enumerate all matches | SQL path query exists; bounded wildcard subtree is the supported grouped plaintext route |
| J14 | Open extracted scalars | `JSONSelection.Open` handles one optional entry per document group. Multi-entry selector groups are refused; do not label them supported |
| J15 | Prepare positional/wildcard read | Implemented `Subtree`, `subtree`; token list plus retained trusted request |
| J16 | Fetch/open subtree | `json_tree_subtree(document, tokens, budget)`, `JSONRead.Open` / `OpenOne` |
| J17 | Immediate children | `Children` prepares a concrete token; SQL returns child entries. Parent-bound child-scalar opening remains unimplemented |
| J18 | Count children | `ChildCount` token and SQL nullable count; not authenticated completeness |
| J19 | Budget/fallback | Implemented, with original requested selection applied after root fallback |
| J20 | Stored-value comparisons | Existing document containment and entry ordering, within compatible column/keyset/profile |

The comprehensive release requirement remains. Do not equate closed tracking
issues with implementation of a parent-bound child opener, or feed child
rows into an unrelated selector/subtree request. Complete that opener for
the J17 plaintext-child requirement; until then, fetch and open the parent's
subtree to inspect its children, documenting the different transfer/leakage
cost. SQL all-match enumeration is distinct from the supported bounded
subtree plaintext interface.

## Semantics that changed or are now implemented

- #1379 randomizes stored entries, object ordinals and containment projection
  order. `->` at a wildcard selects an unspecified element. Use all matches
  with an explicit `EXISTS`, `MIN` or `MAX` rule for ordering/sorting.
- Cascade authentication commits containers to their child ciphertext tags.
  Nonempty standalone container entries fail `JsonNotALeaf`, also used for
  alteration; empty container entries authenticate but fail `OpenedType`.
  All ordinary containers need a subtree read. A requested sealed root can
  still open as a complete document.
- The dynamic engine now rejects positional selector/ordering/EqAt paths.
  Concrete `[n]` positions belong to subtree reads; wildcard selectors address
  a path class. Independent EqAt predicates need not match one array element;
  one containment needle preserves their correlation.
- The strict Rust parser now rejects duplicate keys and out-of-range integer
  literals before key I/O. Typed Go encoding occurs first and follows
  `encoding/json`, including invalid-UTF8 replacement. Raw JSON is checked
  directly. Neither path promises byte-for-byte JSON text preservation.
- SQL NULL, missing selection, JSON null and empty containers are distinct.
  `JSONValue.Found` carries selection presence. `OpenOne` rejects wildcards;
  plural subtree reads return requested values in document order.
- Prepared reads retain the cipher, field definition, path and wildcard
  bound. `Open(ctx, rows)` asks Rust to rederive and verify the request.
  No serialized guest-local key handle is required. Rows cannot supply their
  own expected path. Keep one group per database document.
- Cascade strengthens verification beneath a returned root. It does not
  authenticate the whole result set, absence, freshness or the intended
  database row. Whole results/probes can still be withheld.
- Wildcard bound defaults to 64 with boundary probes and an 8,192-token cap.
  Walk budget independently defaults to 64; zero disables root fallback.
  An open-root document cannot use sealed-root fallback. The budget is not
  a universal response-size cap.
- Header version remains 1 despite the changed cascade/AAD semantics. Freeze
  the post-cascade profile explicitly; the unchanged header is not evidence
  of compatibility with older prototype ciphertexts. Randomized query
  projection order requires canonical semantic comparisons in parity tests.

## Current SQL recipes

The examples assume `profile public.eql_v4_json_search`. Parameters are the
SDK's generated query/selector/token values, never plaintext paths. Add the
application's authorization and tenant predicates as usual.

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

Child count is zero for scalars/empty containers and NULL for a missing node
or the sealed root. Do not convert NULL to zero. The former token/gates and
`json_tree_subtree_at` recipes are removed. Current full Go programs and
parameter binding examples live in
[the JSON example](../../languages/golang/encrypt/example/json/main.go).

## Current dynamic grammar and results

This is implemented data-plan syntax, without an illustrative versioned
outer envelope:

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

Operations select the field through the ABI. Their named inputs include
`{"json"}`, `{"path","json"}`, `{"path","low","high"}`, `{"path"}`
and `{"path","wildcard_bound"}`. JSON values are UTF-8 JSON text. Query
results identify `encoding` (`eql`, `text`, `text_array`, or scalar `bytes`),
SQL domain and operands. Capabilities identify input shapes. Opening uses
`json_open` / `se_json_open` with the original `selector` or `subtree`
request and grouped encrypted rows. The general versioned definition/schema
package remains required work; it is not the current runtime grammar.

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

## Remaining work and release gates

1. Capture the implemented wire grammar, errors, presence states and context
   profile in the promised formal specification and conformance corpus.
   General Rust definitions/caching and additional context roles can follow.
2. Close the explicit J14/J17 scope gaps. The supported all-match plaintext
   route is subtree reads; a parent-bound child opener is separate engine
   work. Do not add generic raw-entry decryption as a shortcut.
3. Replace the internal EQL serialize-to-Value/deserialize bridge with typed
   conversion while preserving the frozen profile. This is an optimization,
   not a missing Go JSON execution path.
4. Run the existing Rust/guest/Go/PostgreSQL suites on the release candidate,
   mapping tests to J01–J20. Include typed/raw inputs, numeric/null cases,
   both root policies, wildcard bounds, fallback, cascade tampering and known
   omission limitations. Inspect real SQL parameter casts and index use.
5. Freeze post-cascade storage/search vectors and the matching EQL bundle.
   Compare canonical projection semantics and cross-opening; ordinary
   randomized bytes need not match. Replace temporary Go Vitamin C pins
   before a final release. Opaque storage adoption is already done and is
   a separate format from JSON-tree storage.

This refresh is source and documentation review, not a fresh runtime test
run or a complete cryptographic audit. Final Rust example compilation,
package extraction and stronger zeroization/constant-time work remain later
API-plan activities; they must preserve the released Go/data contract.
