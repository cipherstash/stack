# Merged JSON engine: obligations for the Go contract

Supporting evidence for the [Go JSON implementation plan](2026-10-24-go-json-tree.md).

Research baseline: `origin/next` at
[`ebdb5de0a12bbec06842851eece283fb7faea30b`](https://github.com/cipherstash/stack/commit/ebdb5de0a12bbec06842851eece283fb7faea30b),
after JSON-tree #1363, leakage documentation/tests #1362 and float-roundtrip
fix #1366. This is source analysis, not a rerun of those changes' tests.
The Go API recommendations below are proposals; the named Rust/SQL behavior
is implemented at that baseline. No ngram decisions are made here.

## What the merged implementation actually provides

| Capability | Engine / SQL contract | Go consequence |
| --- | --- | --- |
| Store and open a document | `JsonDocument`; EQL `JsonTreeDocument` adds the version and column envelope | One document field is one JSON value, including scalar roots, arrays and JSON null; do not restrict it to a Go object/map |
| Containment | `JsonQuery`, exact element-nested projection; SQL `@>` and `<@` | Keep operand direction explicit; array-of-object containment must not combine predicates from different elements |
| Equality at a path | `AtPath<Eq>` constructs a scalar containment needle | Use this equality capability, never infer equality from the ordering term |
| Ordering at a path | `JsonLeafQuery`; `<`, `<=`, `>`, `>=`, inclusive `Between`; only number/string leaves at configured paths | Configuration belongs to the shared target definition used for writes and queries |
| Selector extraction | `JsonSelector`; SQL `->`, `->>`, path query, first and exists | Selector queries collapse positions to wildcards; first means first matching selector, not a named array position |
| Subtree read | `JsonSubtreeKey`; SQL `json_tree_subtree(document, tokens, budget)` | Preserve the trusted read request through to opening its rows |
| Children / count | SQL `json_tree_children(document, token)` and `json_tree_child_count(document, token)` | These take one node token, not an arbitrary wildcard token list; returned child entries are not complete subtrees |

Sources: [engine query types and operators](https://github.com/cipherstash/stack/blob/ebdb5de0a12bbec06842851eece283fb7faea30b/packages/stack-encrypt/src/json/query.rs),
[SQL functions](https://github.com/cipherstash/stack/blob/ebdb5de0a12bbec06842851eece283fb7faea30b/packages/eql/src/v3/json_tree/functions.sql),
[SQL operators](https://github.com/cipherstash/stack/blob/ebdb5de0a12bbec06842851eece283fb7faea30b/packages/eql/src/v3/json_tree/operators.sql).

`sealed_root` defaults to true; `ordered` defaults to empty. Ordered paths
may include wildcards, but may not name a position such as `$.scores[2]`.
A query at an unordered path fails before loading keys. Ordering through a
wildcard selector compares the first matching entry; it is not an existential
or universal comparison over all elements. Ordering numbers uses `f64`, so
different large integers can tie; text ordering folds case and accents.
These are storage/search semantics, not Go conversion choices.
[Options](https://github.com/cipherstash/stack/blob/ebdb5de0a12bbec06842851eece283fb7faea30b/packages/stack-encrypt/src/json/mod.rs),
[ordering derivation](https://github.com/cipherstash/stack/blob/ebdb5de0a12bbec06842851eece283fb7faea30b/packages/stack-encrypt/src/json/derive.rs),
[documented ordering profile](https://github.com/cipherstash/stack/blob/ebdb5de0a12bbec06842851eece283fb7faea30b/packages/eql/docs/reference/json-tree-leakage.md).

## Replace the old read recipe

The revised design derives tokens directly from paths, stores a self tag
`x` on every entry, and expands wildcards on the client. A subtree request
sends an ordered token list (`{"t":["…"]}`), not a single token plus the
old gates. A concrete path sends one token; no ancestor token must be sent.
Tokens are column-wide structural capabilities, not decryption keys, and
must not appear in routine logs.
[Read-key implementation](https://github.com/cipherstash/stack/blob/ebdb5de0a12bbec06842851eece283fb7faea30b/packages/stack-encrypt/src/json/query.rs).

Two independent controls must be named separately:

- **Wildcard bound:** default 64 elements at each wildcard. Each expansion
  includes a probe for the element at the bound. The probe names that
  element itself, even if the rest of the requested path does not exist
  inside it. A matching probe makes opening fail with
  `JsonWildcardTruncated`. A total expansion above **8,192 tokens** fails
  with `JsonWildcardTooWide`; two wildcard levels send `N² + N + 1` tokens.
- **Walk budget:** SQL default 64 returned entries across the request.
  Exceeding it with a sealed root returns the root entry alone. The client
  opens the whole document and evaluates the same paths and probes locally.
  Zero disables fallback; an unsealed root cannot fall back and returns the
  whole requested walk. This budget is not a hard response-size cap.

[Expansion and opening](https://github.com/cipherstash/stack/blob/ebdb5de0a12bbec06842851eece283fb7faea30b/packages/stack-encrypt/src/json/derive.rs),
[SQL budget behavior](https://github.com/cipherstash/stack/blob/ebdb5de0a12bbec06842851eece283fb7faea30b/packages/eql/src/v3/json_tree/functions.sql).

An honest server returns the named node at depth zero plus descendants.
Consequently `{}`, `[]`, a scalar, and an absent path remain distinct.
`DecryptInto<Option<Value>>` gives `Some(null)` for JSON null and `None` for
absence; `Vec<Value>` gives all wildcard results in document order; singular
`Value` fails on zero or multiple results. In Go use an explicit presence
indicator for a singular read and an explicit result list for a wildcard
read. A nullable Go pointer alone must not collapse JSON null into absence.
[Result implementations](https://github.com/cipherstash/stack/blob/ebdb5de0a12bbec06842851eece283fb7faea30b/packages/stack-encrypt/src/json/derive.rs).

## Opening requires trusted request state

An extracted `JsonNode` / `JsonTreeEntry` does **not** implement standalone
decryption. The selector opens a scalar extraction; the original subtree
key opens walk rows. The subtree key retains concrete paths, bound, probe
positions and the keyset/column machinery needed to recompute selectors;
its JSON serialization contains only the SQL tokens, so it is insufficient
to reconstruct the verification object.
[Engine wrappers](https://github.com/cipherstash/stack/blob/ebdb5de0a12bbec06842851eece283fb7faea30b/packages/stack-encrypt/src/json/mod.rs),
[EQL wrappers](https://github.com/cipherstash/stack/blob/ebdb5de0a12bbec06842851eece283fb7faea30b/packages/eql/crates/eql-bindings/src/v4/json_tree.rs).

The dynamic layer must retain an opaque guest handle or rederive the read
key from a trusted application request (definition, keyset, column context,
path, bound). Database rows must never supply the purported expected path
or context. A stateless rederivation avoids pinning requests to one WASM
instance, but the guest must still reconstruct the same native key and run
the existing opening checks. Do not duplicate these checks in Go.

The checks reject wrong selectors, inconsistent token/self-tag relationships,
wrong positions or labels, duplicate entries, mixed headers, malformed walks
and incomplete returned subtrees. They do not authenticate the result set:
another document's entries with its own header can open, a field under one
array element can substitute for the same field under another in the cases
documented by the engine, and the database can omit entire requested nodes
or probes. Therefore “verified read” must not promise authenticated absence,
completeness, or row identity. Root fallback must return only the requested
result after client selection, never accidentally hand the whole plaintext
document to a field-read caller.
[Authentication limits](https://github.com/cipherstash/stack/blob/ebdb5de0a12bbec06842851eece283fb7faea30b/packages/eql/docs/reference/json-tree-leakage.md).

Selector extraction opens scalars, or a sealed root explicitly requested at
`$`; container entries fail because their descendants hold their contents.
The children function returns immediate entries at depth one, not the
subtree result shape. The existing subtree opener cannot simply be applied
to those child rows. A binding should expose them as encrypted entries for
SQL use, or add a specifically request-bound opening operation if plaintext
child enumeration is required. A full subtree read and local child
enumeration is an alternative with different transfer/leakage costs.
[Extraction implementation](https://github.com/cipherstash/stack/blob/ebdb5de0a12bbec06842851eece283fb7faea30b/packages/stack-encrypt/src/json/derive.rs),
[children SQL](https://github.com/cipherstash/stack/blob/ebdb5de0a12bbec06842851eece283fb7faea30b/packages/eql/src/v3/json_tree/functions.sql).

Child count returns zero for scalars and empty containers, NULL for a missing
node, and NULL for the sealed root. The latter's top-level fields do not
chain from the root token. Do not turn either NULL case into zero.

## Remaining Go/dynamic work is real

At this source baseline, the dynamic wire grammar can parse
`{"json":{"sealed_root":true,"ordered":["$.salary"]}}`, but runtime
admission still refuses every JSON index with `json_index_pending`.
`ValueKind` admission assumes scalar indexes. The EQL JSON family is
handwritten and explicitly absent from the catalog/target table. Dynamic
query operands currently distinguish only one term from a range, and
their operator model lacks the JSON-specific path/read inputs. Merely
generating Go types does not make this capability usable.
[Dynamic index grammar](https://github.com/cipherstash/stack/blob/ebdb5de0a12bbec06842851eece283fb7faea30b/packages/stack-encrypt/src/dynamic/term.rs),
[admission](https://github.com/cipherstash/stack/blob/ebdb5de0a12bbec06842851eece283fb7faea30b/packages/stack-encrypt/src/dynamic/kind.rs),
[dynamic queries](https://github.com/cipherstash/stack/blob/ebdb5de0a12bbec06842851eece283fb7faea30b/packages/stack-encrypt/src/dynamic/query.rs),
[EQL family](https://github.com/cipherstash/stack/blob/ebdb5de0a12bbec06842851eece283fb7faea30b/packages/eql/crates/eql-bindings/src/v4/json_tree.rs).

Keep three contracts separate: plaintext JSON transport across the guest,
the existing EQL document/query/read wire forms, and the Vitamin C storage
profile for opaque blobs. A new storage codec for opaque user structs does
not replace `json_tree`'s node encoding or its EQL JSON envelope. The current
EQL/engine conversion still serializes through `serde_json::Value`; direct
typed conversion is a worthwhile format-preserving implementation change.
[Conversions and layouts](https://github.com/cipherstash/stack/blob/ebdb5de0a12bbec06842851eece283fb7faea30b/packages/eql/crates/eql-bindings/src/v4/json_tree.rs).

## Context roles must not be conflated

The existing `seal_pending` takes one `CallerContext`, obtains its ZeroKMS
descriptor, then uses the same context piece for both the index PRF context
and the AEAD context. The EQL layout accepts only a nonempty `Identifier`
for the column. Dynamic EQL target fields explicitly reject caller
extensions (`TargetError::Extended`) and context-field plans
(`TargetError::ContextField`). Separate row AAD and search scope are therefore
not an existing JSON capability.
[Sealing](https://github.com/cipherstash/stack/blob/ebdb5de0a12bbec06842851eece283fb7faea30b/packages/stack-encrypt/src/json/derive.rs#L755),
[EQL layout](https://github.com/cipherstash/stack/blob/ebdb5de0a12bbec06842851eece283fb7faea30b/packages/eql/crates/eql-bindings/src/v4/json_tree.rs),
[dynamic restrictions](https://github.com/cipherstash/stack/blob/ebdb5de0a12bbec06842851eece283fb7faea30b/packages/stack-encrypt/src/dynamic/record.rs#L73).

Before freezing a profile that offers row binding, lower distinct column
identity, ciphertext context and search scope into the engine. Never append
a row ID to the present shared context as a shortcut: that also changes
selectors, value terms and read tokens per row. An initial column-only
profile can explicitly refuse those extensions, but must not advertise
unsupported row AAD or reinterpret the same profile later. Tenant keyset
selection is another separate input; it does not provide a replacement for
the context-role distinction.

For the current client and any later pooled WASI execution, prefer a
host-owned immutable read descriptor
with definition/profile identity, resolved keyset identity, search-scope
inputs, path and wildcard bound. Each open call sends that trusted descriptor
plus untrusted rows, and the guest rederives `JsonSubtreeKey` before opening.
Ciphertext-only row context is supplied separately per document. This avoids
requiring a guest-local handle to survive pool scheduling. The descriptor
must never be reconstructed from database metadata; operation parameters
and column expectations remain application-owned. Reusing a definition ID
for different options/context encodings must be forbidden or versioned.

One stale source comment in `JsonOptions::sealed_root` says there is no root
token. After #1363 the root has a token; with a sealed root it finds only
the root entry and cannot enumerate top-level members. The module-level
description, implementation and SQL establish the current behavior.

## Numbers and release fixtures

#1366 enables `serde_json/float_roundtrip` on Stack Encrypt and tests the
reported one-ULP failure through document, scalar extraction and subtree
opening. This fixes #1364; do not retain it as an unresolved blocker.
It does not make PostgreSQL arbitrary-precision numeric values supported or
make the `f64` ordering encoding lossless for all integers.
[Merged fix](https://github.com/cipherstash/stack/commit/ff287a32887d6a6c07c51d64e61b00deb46eed16).

The Go contract must preserve signed/unsigned integers through 64 bits and
finite binary64 values without first decoding every JSON number as Go
`float64`. Declare the supported number model and reject unsupported values
instead of silently rounding them. Test Rust-written/Go-opened and
Go-written/Rust-opened documents, not just same-language round trips.

Release fixtures should cover both root settings; null/absent/empty
containers; nested arrays and quoted keys; containment grouping; equality
versus lossy ordering; concrete and wildcard reads; bound minus one, bound
and bound plus one; token-cap refusal; fallback equivalence; grouped rows
from multiple database records; malicious wrong entries and dropped probes;
and PostgreSQL parameter casts. In particular `->` with an untyped literal
can select native `jsonb` behavior: examples should use typed parameters or
explicit `::text` casts.
[Existing engine tests](https://github.com/cipherstash/stack/blob/ebdb5de0a12bbec06842851eece283fb7faea30b/packages/stack-encrypt/tests/json_index.rs),
[PostgreSQL oracle](https://github.com/cipherstash/stack/blob/ebdb5de0a12bbec06842851eece283fb7faea30b/packages/eql/tests/encryption/tests/json_tree.rs),
[operator resolution warning](https://github.com/cipherstash/stack/blob/ebdb5de0a12bbec06842851eece283fb7faea30b/packages/eql/src/v3/json_tree/operators.sql).
