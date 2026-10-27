# Merged JSON engine: obligations for the Go contract

Supporting evidence for the [Go JSON implementation plan](2026-10-24-go-json-tree.md).

Updated: 2026-10-27. Source baseline: merged `next` at
[`ffeed7adb3f7d8739cda53261046147852bffc82`](https://github.com/cipherstash/stack/commit/ffeed7adb3f7d8739cda53261046147852bffc82).
This replaces the earlier `ebdb5de0a` assessment. The relevant new merges
are #1379 (cascade and random order), #1372 (configured document targets)
and #1373 (dynamic queries/reads); #1378 and #1402 add the typed Go surface
and its documentation. This is source reconciliation, not a rerun of their
builds, tests or security analysis. No ngram recommendation is made here.

## Capabilities that are implemented now

The previous catalog and dynamic-admission blockers are resolved for the
configured JSON target. The current target identifier is **`JsonSearch`**,
and the generated Go stored type is **`eql.JSONSearch`**. The proposed
`EncryptedJson` spelling is not the implemented interface.

| Role | Current catalog / Go name | SQL domain |
| --- | --- | --- |
| Stored document | `JsonSearch` / `JSONSearch` | `public.eql_v4_json_search` |
| Containment or path-equality operand | `JsonSearchQuery` / `JSONSearchQuery` | `eql_v4.query_json` |
| Ordering operand | `JsonSearchLeafQuery` / `JSONSearchLeafQuery` | `eql_v4.query_json_leaf` |
| Extracted entry | `JsonEntry` / `JSONEntry` | `public.eql_v4_json_entry` |

The engine's handwritten Rust `JsonTreeDocument`, `JsonTreeQuery`,
`JsonTreeLeafQuery` and `JsonTreeEntry` remain implementation names. SQL
functions retain `json_tree_*` names. Update examples and fixtures to these
current domain spellings rather than the former `_json_tree` domains.
[Catalog](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/packages/eql/crates/eql-domains/src/lib.rs#L621),
[Rust domain mapping](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/packages/eql/crates/eql-bindings/src/v4/json_tree.rs#L286).

A dynamic field declares `"type":"json"` and either `"target":"JsonSearch"`
or `"target":{"name":"JsonSearch","options":{"sealed_root":true,
"ordered":["$.salary"]}}`. Options resolve once per parsed plan into
`FieldPlan::target_options` / `TargetOptions::Json`. Writes, queries and
reads consult those resolved options. The default remains sealed root and
no ordered paths. Unknown/incompatible options, `options:null`, JSON without
a target, and sealed field-null mode are refused. Legacy bare JSON index
admission is not the supported document route; the configured target is.
[Target options and resolver](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/packages/stack-encrypt/src/dynamic/target.rs),
[plan resolution and grammar](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/packages/stack-encrypt/src/dynamic/record.rs).

This implements the concrete configured-target seam. It does not by itself
implement the whole proposed versioned definition protocol, JSON Schema,
provider capability schema or general cached `TargetDefinition` lifecycle.
The guest still parses submitted plans in its operations; do not describe a
persistent loaded-definition cache as completed.
[Guest operations](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/languages/golang/encrypt/guest/src/ops.rs).

## JSON transport and validation are no longer pending

Documents enter as UTF-8 JSON in a text or bytes transport leaf and return
as JSON text in a bytes leaf. The new Rust parser rejects duplicate object
keys, malformed JSON/Unicode, and integer literals outside
`i64::MIN..=u64::MAX`. Decimal/exponent values use the engine's finite binary64
model, not arbitrary-precision PostgreSQL numeric. Errors carry codes and
positions without echoing document text. Source checks invoke the same
parser before key requests. The existing `float_roundtrip` fix remains.
[Dynamic JSON adapter](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/packages/stack-encrypt/src/dynamic/json.rs),
[parser and writer](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/packages/stack-encrypt/src/json/text.rs).

JSON text `null` is a present document. A transport null/missing optional
field with `null=sql` represents SQL NULL. A selection with no match is a
third state. Required JSON fields do not need a field-null mode. Whole
objects, arrays, scalars, null and empty containers are supported documents.

Keep the transport, searchable JSON storage and opaque-blob storage profiles
separate. The EQL/engine adapter still uses `serde_json::to_value` /
`from_value` in `transcode`, `envelope` and `document`; direct typed conversion
remains format-preserving follow-up work. Vitamin C opaque storage does not
replace the tree's node encoding or EQL envelope.
[Current conversions](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/packages/eql/crates/eql-bindings/src/v4/json_tree.rs#L293).

## Dynamic operations and request-bound opening have landed

`OpSpec` now covers containment, path equality, path ordering/range,
selector, subtree, children and child count. Operation discovery includes
an input-shape discriminator. Query responses include `encoding` (`bytes`,
`eql`, `text`, `text_array`), and operands include text and text lists as
well as one/range byte operands. The ordering SQL domain is represented
separately from the containment domain. These are implemented extensions to
the current wire model, not the entire proposed future tagged-result schema.
[Dynamic query model](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/packages/stack-encrypt/src/dynamic/query.rs),
[JSON operation grammar](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/packages/stack-encrypt/src/dynamic/json_query.rs).

| Operation | Input | Derived operand |
| --- | --- | --- |
| `contains`, `contained_by` | `{json}` | Containment EQL JSON |
| `eq_at` | `{path,json}` | Containment EQL JSON for a scalar |
| `lt_at`, `lte_at`, `gt_at`, `gte_at` | `{path,json}` | Ordered-leaf EQL JSON |
| `between_at` | `{path,low,high}` | Two ordered-leaf operands |
| `selector` | `{path}` | `text` |
| `subtree` | `{path,wildcard_bound?}` | `text[]` tokens |
| `children`, `child_count` | `{path}` | One node token as `text` |

Every JSON-valued operand is JSON text. Selector-class operations reject
explicit array positions rather than broadening `[n]` to `[*]`. Use a
subtree for positional reads. Children/count reject wildcard paths. Ordering
requires a configured path and a number/string operand. Equality remains
independent of lossy ordering; numeric ordering can tie large integers and
text ordering folds case and accents.

`dynamic::json_open` and guest `se_json_open` now rederive the native read
from the original operation/path/bound and the field's options. They open
through the deriving keyset only. A different keyset is refused before data
key retrieval. Returned rows remain grouped by database document; each group
opens independently in the shared batch. The result is a list of JSON texts
per group, preserving missing versus JSON null.
[Opening implementation](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/packages/stack-encrypt/src/dynamic/json_query.rs#L419),
[guest ABI](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/languages/golang/encrypt/guest/src/abi.rs#L574).

Two boundaries must remain explicit in the release plan:

- The opener accepts **selector or subtree**, not children/count. A selector
  group has at most one entry. All-match selector SQL results can be opened
  as separate groups, but that does not verify their joint completeness or
  restore document order. Subtree reads handle structured ordered results.
- SQL children/count preparation is available. A parent-bound child-scalar
  opening helper from the previous plan is **not implemented** by
  `json_open`; child entries are not complete subtree rows. If that convenience
  remains required, implement and test it separately rather than marking it
  complete with token preparation. A full subtree read can supply plaintext
  children with different transfer and leakage costs.

## Cascade and random storage order change the read contract

#1379 adds a digest of children's AEAD tags, in sibling ordinal order, to
each entry's AAD. A returned subtree is authenticated from its root through
all descendants. Child omission, substitution or movement beneath a returned
root breaks an ancestor's authentication. The sealed whole-document root
is a separate ciphertext and does not commit to the redundant tree entries.
[Exact cascade](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/packages/stack-encrypt/src/json/cascade.rs),
[AAD construction](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/packages/stack-encrypt/src/json/derive.rs#L830).

Stored `sv` slots are randomly permuted, except the root remains slot zero.
Object member ordinals and projection/query-list orders are random too.
The permutation is fresh randomness, not a deterministic encoding of the
plaintext or key. Consequently wildcard `->`, `->>` and ordering on
`ord_term(col -> selector)` select an **unspecified matching element** in
random stored order, not element zero or the first in document order. It
stays the same for that stored row until rewritten. For all matches use
`json_tree_path_query`; for ordered plaintext results use a subtree read.
[Shuffle implementation](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/packages/stack-encrypt/src/json/shuffle.rs),
[public leakage/read semantics](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/packages/eql/docs/reference/json-tree-leakage.md).

A nonempty container no longer opens from `->` because its children's tags
are absent. It returns `JsonNotALeaf`, which also covers an altered entry;
the client cannot reliably distinguish those causes before opening. Empty
container entries authenticate but still return `OpenedType`, since the
extraction interface returns a scalar or sealed root. Use a subtree for
containers. Decrypting a complete document with an open root now additionally
loads the index keyset to reconstruct the chain; settling `Pending` therefore
requires `IndexKeySource` as well as `DataKeySource`. Preserve this requirement
when designing future provider capabilities and no-network test sources.
[Extraction and full-document opening](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/packages/stack-encrypt/src/json/derive.rs),
[provider-bound change](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/packages/stack-encrypt/CHANGELOG.md#changed).

The cascade does not authenticate the complete query result. The server can
omit an entire requested root or a wildcard probe, answer with another row's
valid header and data, or substitute an equivalent-selector node at the top
of a read in the documented cases. Distinguish **complete descendants below
a returned root** from **complete query matches**. Do not expose an
unqualified authenticated-absence/completeness guarantee.
[Authentication scope](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/packages/eql/docs/reference/json-tree-leakage.md#what-is-authenticated).

## Limits and SQL behavior retained

Wildcard expansion still defaults to 64 and is capped at 8,192 total tokens.
Boundary probes cause `JsonWildcardTruncated` when returned; excessive
expansion yields `JsonWildcardTooWide`. Two wildcard levels use
`N² + N + 1` tokens. SQL walk budget defaults to 64 and controls sealed-root
fallback, not a hard response cap. Budget zero disables fallback; an open
root cannot fall back. The client reapplies the original paths and probes
after opening a sealed-root fallback.

Subtree SQL returns each named root at depth zero and its descendants.
Returned values distinguish missing, JSON null and empty containers.
Children SQL returns immediate entries, while child count is zero for a
scalar/empty container and NULL for absence or a sealed root. Treat the
count as a database observation, not an authenticated cardinality.
[Subtree expansion](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/packages/stack-encrypt/src/json/derive.rs),
[SQL signatures and semantics](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/packages/eql/src/v3/json_tree/functions.sql).

## Remaining profile and context decisions

The JSON header layout is still version 1, and the entry AAD domain still
ends in `/v1`, despite the pre-release cascade change. Identical envelope
fields do not imply that pre-cascade ciphertext opens under the new AAD.
Freeze the post-cascade vectors and semantics as the customer baseline;
do not claim compatibility from the unchanged header alone. The prototype
compatibility exemption permits this prior change, not future silent changes
to a released profile.
[Header encoding](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/packages/stack-encrypt/src/json/mod.rs#L268),
[entry AAD](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/packages/stack-encrypt/src/json/derive.rs#L830).

Ciphertext context and search scope are still not separate JSON capabilities.
`seal_pending` derives both from one caller context; the EQL layout accepts
an `Identifier`; dynamic targets reject extensions and context-field plans.
Keep the column-and-keyset profile explicit. Before enabling row binding,
introduce separate native PRF/AEAD inputs and the corresponding definition
roles. Never append a row ID to the current shared context. Keyset routing
and provider lock policy remain separate concerns.
[Sealing](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/packages/stack-encrypt/src/json/derive.rs#L779),
[EQL target restrictions](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/packages/stack-encrypt/src/dynamic/record.rs).

## Evidence inspected and release follow-up

Existing tests now cover configured-target parity and refusals, dynamic
operator shapes, request-bound opening, grouped rows, cascade tampering,
wildcard bounds/fallback and JSON ingress. Their presence resolves the old
claim that these paths have no implementation or tests. It does not replace
running the assembled customer release against the matching guest and SQL.
[Configured target tests](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/packages/eql/tests/encryption/tests/json_tree_data_plan.rs),
[dynamic operators/read tests](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/packages/stack-encrypt/tests/json_operators.rs),
[read authentication tests](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/packages/stack-encrypt/tests/json_read_checks.rs),
[JSON vectors](https://github.com/cipherstash/stack/blob/ffeed7adb3f7d8739cda53261046147852bffc82/packages/stack-encrypt/tests/fixtures/json_tree_vectors.json).

Update cross-language assertions: ciphertexts, stored slot order and query
projection order are randomized. Compare cross-opening, canonical selector
sets and SQL behavior; exact bytes require the test-only seeded RNG. Remaining
work is release conformance, formalizing the supported dynamic subset and
profile version boundary, deciding the child-opening gap, and the deferred
general API/context design. Reimplementing configured targets and JSON reads
from scratch is no longer an appropriate next step.
