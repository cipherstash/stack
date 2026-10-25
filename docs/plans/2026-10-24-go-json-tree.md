# Go JSON: revised dynamic contract and customer implementation plan

Date: 2026-10-25. Status: implementation direction agreed in API review;
contract spellings and examples remain proposals, not implemented API.
Tracking issue: [#1347](https://github.com/cipherstash/stack/issues/1347).
This plan under [#1353](https://github.com/cipherstash/stack/pull/1353) uses
merged `next` at `ebdb5de0a12bbec06842851eece283fb7faea30b` and the
[API redesign](https://github.com/cipherstash/stack/blob/c5efc48837d3cb48bc7e168f780fd616a4f4845e/docs/plans/2026-10-24-stack-encrypt-api-plan.md)
tracked in [#1365](https://github.com/cipherstash/stack/pull/1365).
The [engine findings](2026-10-25-go-json-engine-contract.md) cite the source
for the current behavior described below. The examples are proposed contract
shapes, not runnable instructions for the current SDK.

## Recommendation

Deliver Go JSON through the existing Rust engine and EQL guest. Implement
configured target definitions, operation-specific results, and request-bound
reads now. These are the parts of the API redesign that affect the customer
contract. The public Rust traits, derives, method renames and crate moves
can follow without changing this contract.

Keep the full JSON operation inventory in the first release, including
extraction, subtree reads, children and counts. Opening extracted values
is part of that release, alongside full-document writes and queries. The
merged engine already provides the main read machinery; adapting it safely is part of the work.

Adopt the forthcoming Vitamin C release separately for opaque blobs. Its
storage profile does not replace JSON tree's custom encrypted nodes or EQL
envelope. Freeze and test those existing JSON formats independently.

This recommendation makes no short-ngram mechanism decision. JSON's result
contract must be extensible without pretending that ngram Boolean-query
requirements have already been settled.

## Changes from the first-cut plan

| Original proposal | Revised requirement |
| --- | --- |
| JSON options travel as a special index configuration | A registered target owns typed options, validation and lowering; the same resolved definition serves writes, queries and reads |
| One query twin/domain per target; one or two byte terms | Describe each operation's input and output shape; containment, ordering, selector and subtree preparation have different results |
| `OpenEntry(cipher, rows)` without a request | A prepared selector/read object opens its own rows; expected path, definition and keyset come from the caller, never the database |
| Subtree token plus gates, `_subtree_at` | Current token lists, self tags, client wildcard expansion and probes; `json_tree_subtree(document, tokens, budget)` |
| Selector checks and number correctness are pending | Checks have landed; #1366 fixes #1364. Preserve their tests through the binding |
| Walks ship later | All required operations ship in the customer release |
| Nullable JSON field | SQL NULL, present JSON null and missing selection are distinct states |
| JSON implicitly means the old SteVec index | JSON is a plaintext kind; the target explicitly identifies the EQL JSON-tree representation |
| Reuse current EQL context plumbing | Current EQL targets are column-only and reject context extensions; do not advertise the redesign's row binding as implemented |

The catalog, guest dispatch, generator and Rust parity work in #1353 remain
valid. The proposal needs revised contracts rather than a second SDK or
crypto implementation. Its five tracking issues remain useful work items.

## 1. One configured target definition

Make the public interoperability unit a versioned definition, lowered to
internal plans. It contains field identity, source kind, target, resolved
options and declared context roles. Bind requests to a field of that
definition. Do not pass another options object to a query or decrypt call.

Proposed minimal JSON authoring form, for the existing column-only profile:

```json
{
  "version": 1,
  "fields": {
    "profile": {
      "type": "json",
      "context": ["users", "profile"],
      "target": {
        "name": "EncryptedJson",
        "options": {"sealed_root": true, "ordered": ["$.salary"]}
      }
    }
  }
}
```

`EncryptedJson` is the recommended role-based target name, mapping to the
current Rust `JsonTreeDocument` and SQL `public.eql_v4_json_tree`. Go spells
the generated ciphertext type `eql.EncryptedJSON`. These names are proposals;
the existing SQL domain does not need a rename. Target identifiers are
contract identifiers, not names obtained from Rust type reflection.

A string target remains shorthand for default options. Unknown keys,
unknown targets, unsupported versions and unsupported context capabilities
fail closed. Normalize defaults once. Resolve options into the same native
`JsonOptions` used by typed Rust, including its path validation. A new
configured definition is a new immutable instance, not mutation of one used
by an in-flight query.

Extend discovery with option schema/profile identity and per-operation
input, result and capability metadata. The existing target descriptor's
single `query`/`query_sql_domain` pair cannot describe JSON accurately.
Generate schemas and Go types from the maintained registry where possible;
keep semantic validation in Rust. Do not add an independent Go path parser.

The guest should cache validated definitions under their complete resolved
content and contract version. Generated field accessors share that immutable
content. Guest-local cache identifiers remain internal and can be recreated;
they must not become SQL values or customer persistence formats.

The SDK keeps its idiomatic generated `Encrypt`, `Decrypt` and `Fields`
entry points. It does not expose a Rust plan or require a Go `.using()`
method. Both tags and the existing generator policy path lower to this same
definition. Simple target options can use the tag grammar; complex quoted
paths need a structured options form, not a naive `|` split. Validate both
through the engine at generation time.

## 2. Explicit JSON values and three separate codecs

Use UTF-8 JSON text for plaintext documents and JSON query inputs at the
host/guest boundary. In Go, use `json.RawMessage` as the fundamental value.
A typed struct adapter may explicitly call `encoding/json` and decode into
a declared type. Never decode first into `map[string]any` with default
`float64` numbers just to send the tree to Rust.

Do not implicitly treat an ordinary `[]byte` as JSON: Go's JSON encoder
normally treats it as a byte string. Require an explicit `json.RawMessage`
conversion for raw JSON bytes. Containment accepts an explicit JSON needle,
not necessarily the field's full struct type, whose zero-valued fields can
accidentally narrow the query.

Across the binary ABI, the declared `json` input is a UTF-8 text/byte payload
in the ordinary transport frame. In JSON authoring/request examples below,
`json` is a string carrying that text. Define this mapping explicitly;
a JSON document's `null` is not the frame's absent-field/null marker.

| Boundary | Representation |
| --- | --- |
| Dynamic definitions, requests and responses | Versioned control schema carried by the existing Vitamin C transport frame |
| Searchable JSON plaintext | UTF-8 JSON parsed by Rust into the existing JSON value model |
| Stored searchable document | Existing EQL v4 JSON-tree envelope, header, encrypted nodes and search terms |
| Stored opaque whole struct | Vitamin C versioned storage blob from #520/#526, sealed as one value |

Use direct typed EQL/engine conversion when implementing the adapter; remove
the internal serialize-to-Value/deserialize bridge without changing stored
bytes. This is distinct from parsing user JSON text at ingress.

Pin the numeric model: signed/unsigned 64-bit integers and finite binary64
values, not arbitrary-precision PostgreSQL numeric. Preserve integer tokens
without first casting to float. Add ingress checks for unsupported integer
literals instead of accepting a parser's lossy fallback. Fractional/exponent
numbers follow the documented binary64 interpretation; JSON text, key order
and decimal spelling are not promised to round trip byte for byte. The
existing `float_roundtrip` fix must remain enabled. Separately document that
JSON numeric ordering converts to `f64`, so large distinct integers can tie.

Specify duplicate-member handling and invalid Unicode rather than inheriting
an accidental Go/Rust difference. Recommend rejecting duplicate object keys
and invalid Unicode at JSON ingress in Rust, before key I/O. This validation
is additional adapter work, not a claim about the current parser. A typed
Go encoder may already have transformed the caller's input; its explicit
adapter contract must describe that transformation.

For an optional document, a nil `*json.RawMessage` is SQL NULL. A non-nil
pointer containing `null` is a present encrypted JSON null. A nonoptional
`json.RawMessage` is a required document; empty bytes are invalid JSON, not
an absent document. `null=sql` is required for nullable fields, not every
JSON field. Length-padded sealed null is not supported for this target.

## 3. Operation-specific requests and results

Use operator names with distinct operand schemas, all bound to the same
field definition. For example:

```json
{"operation":"contains","field":"profile","input":{"json":"{\"active\":true}"}}
```

```json
{"operation":"eq_at","field":"profile","input":{"path":"$.name","json":"\"Alice\""}}
```

```json
{"operation":"subtree","field":"profile","input":{"path":"$.visits[*]","wildcard_bound":64}}
```

These fragments are operation bodies; the request envelope additionally
identifies protocol version, definition and execution/keyset inputs.

Replace the assumption that every operation yields one or two anonymous
byte strings with a tagged result model. Predicate operands, ordered ranges,
selectors and prepared reads have separate variants and named Go types.
Each operand states its wire encoding and SQL parameter type. A selector
is text; subtree tokens are `text[]`; query envelopes are EQL JSON. A token
list is not a BETWEEN range or a generic Boolean OR expression.

| Operation | Required Go/dynamic behavior | SQL use |
| --- | --- | --- |
| Encrypt/decrypt, including batches | Full document, both root policies, scalar/array/object/null | One `public.eql_v4_json_tree` column |
| Contains / ContainedBy | JSON needle and named containment query | `@>` / `<@` with `eql_v4.query_json_tree` |
| EqAt | Scalar JSON operand and validated selector-class path | Containment predicate; never ORE/OPE equality |
| LtAt/LteAt/GtAt/GteAt | Ordered path plus number/string | Extract entry, compare with `eql_v4.query_json_tree_leaf` |
| BetweenAt | Two ordered bounds plus selector | Inclusive lower/upper predicates |
| Selector | Prepared selection with named SQL selector | `->`, `->>`, first/all path query, path exists, sorting |
| Open selection | Original selection plus entries grouped by database document | Scalars; sealed root at `$`; ordinary container marker refused |
| Subtree | Prepared concrete or wildcard read with token list | `json_tree_subtree(document, tokens, budget)` |
| Open subtree | Original read plus grouped rows | Requested JSON only, including fallback |
| Children | Concrete node request and encrypted child entries | `json_tree_children(document, token)` |
| Open child scalars | Request-bound child validation in Rust | Additional adapter/helper work; never generic entry decryption |
| ChildCount | Concrete node token; nullable count | `json_tree_child_count(document, token)` |
| Stored-value comparisons | Same column/scope and compatible profile | Existing document containment and entry ordering operators |

Generate ordered-path accessors from validated options, with explicit
aliases or a generation error on name collisions. Runtime path methods use
the same native validator. Reject positions for selector-class operations
including EqAt; those selectors erase `[n]` to `[*]`. Exact positional reads
use `subtree`. Wildcard equality is any-match; wildcard ordering through
`->` is first-match. Multiple independent EqAt predicates need not match the
same array element; use one containment needle for correlated conditions.

For children, the SQL rows have depth one and are not complete subtrees.
Add a parent-bound opening helper that verifies child membership and opens
scalars; container children require a subtree read. Implement this in Rust
and reuse it from Go. Counts remain database observations: zero for a scalar
or empty container, NULL for absence or the sealed root. Neither counts nor
absence become authenticated merely because returned ciphertexts open.

## 4. A read object retains the verification request

Recommend an immutable host-owned read descriptor and guest rederivation.
Store the trusted definition/profile, resolved keyset identity, path,
wildcard bound and applicable scope inputs. Do not export PRF keys or
serialize a native `JsonSubtreeKey` expecting to recover its private state.
Its existing serialized token list is insufficient for opening checks.

The SQL parameter is a separate value derived from the read. Opening sends
the original descriptor and untrusted rows to Rust, rederives the native
selector/subtree key and uses its existing verifier. Enforce definition,
keyset and scope agreement. Caller `context.Context` is passed per call,
never retained in the read. The current Go client has one guest instance;
rederivation also avoids imposing instance affinity on future execution.

Proposed usage fragment, with database plumbing abbreviated deliberately:

```go
read, err := users.Fields.Profile.Subtree(ctx, cipher, "$.visits[*]",
    encrypt.JSONReadOptions{WildcardBound: 64})
if err != nil { return err }

// Bind read.Tokens() as PostgreSQL text[], using the driver's array adapter:
// SELECT e FROM eql_v4.json_tree_subtree($1::public.eql_v4_json_tree,
//                                       $2::text[], $3::integer) AS e
// $1 is the stored document; $3 is the SQL walk budget, e.g. 64.

selected, err := read.Open(ctx, cipher, encryptedRows)
if err != nil { return err }
// selected is an explicit list of JSON values, in document order.
```

Provide batch opening with groups keyed by the caller's database row
association. Never concatenate different documents' entries into one walk.
Go groups transport values; Rust still gathers and executes all key requests
in one logical batch. Do not promise one HTTP request for unlimited batches:
existing provider chunk limits and distinct keysets still apply.

Use a singular result with `Found` plus raw JSON, and a plural result with a
JSON-value list. Present JSON null is `Found=true` with text `null`; no match
is `Found=false` or an empty plural list. A singular read with multiple
results fails rather than silently choosing one. SQL first-match selection
is a separately explicit operation.

Name the two limits separately:

- `wildcard_bound`: defaults to 64 per wildcard, with boundary probes;
  total token expansion is capped at 8,192. A found boundary probe fails
  with `JsonWildcardTruncated`; excessive expansion fails before key I/O.
- `walk_budget`: SQL defaults to 64; selects sealed-root fallback. Zero
  disables fallback. With an unsealed root it does not cap response size.

Always apply the original selection after sealed-root fallback. Do not
return the whole decrypted document from a subtree request. Preserve the
engine's rejection of forged, spliced and malformed returned walks.
Document the existing limits: the server can omit whole matches/probes,
and successful opening is not proof of result completeness or database row
identity. Do not expose a `complete=true` claim from this protocol.

## 5. Context and provider boundary: freeze only implemented guarantees

This is the main redesign issue that cannot be solved by Go wrappers.
JSON currently derives index context and ciphertext AAD from the same
context piece. The EQL layout accepts a column identifier; dynamic targets
reject extensions and context-field plans.

Keep column identity, search scope, ciphertext binding and provider options
as distinct roles in the new contract. Validate source roles against the
trusted definition: a primary-key field cannot supply search scope; a
scope key is only used when explicitly selected. Keyset selection and
ZeroKMS lock policy remain execution inputs, not JSON target options.

**Delivery recommendation:** implement the complete JSON operation surface
first under the existing column-and-keyset context profile. Advertise that
profile explicitly and reject additional scope/row-binding declarations
until their lowering is implemented. This does not claim the accepted
context redesign is complete or defer JSON operations. The customer has
not stated a requirement for new row-bound JSON profiles in this task.

Before enabling row binding, split the native PRF and AEAD inputs and test
writes, all queries and all read paths together. Search uses column plus
scope; AEAD includes the additional row binding. Decrypt requests then need
the expected row values, including when SQL returns extracted entries.
Never append a row ID to today's shared context as a shortcut.

Pin the current context derivation as part of the storage/search profile.
Introducing the separated profile must be explicit and retain the reader
and query behavior of released profiles; it must not reinterpret old data
or silently reindex it. Decide the profile identifier and its association
with a column/definition before release. Schema version, EQL envelope/header
version and Vitamin C blob version are different version boundaries.

## 6. Specification and acceptance gates

Publish the first supported subset of the dynamic interoperability spec
alongside this implementation: JSON Schema, normative semantics, transport
mapping and conformance vectors. Use the general target model, not a
JSON-only replacement protocol. Unsupported future features fail explicitly;
reserved fields are not accepted and ignored.

The schema covers definitions, target options, operations, tagged results,
read descriptors, presence states and stable errors. The semantic contract
covers number normalization, path classes, contexts, limits and validation
before key I/O. Return machine-readable codes and safe locations, without
JSON values, paths or tokens in diagnostic text. Definition/field identifiers
can identify the failing operation without echoing user values.

Customer release gates:

1. Catalog, options and capability discovery match Rust and generated Go;
   schema/semantic fixtures reject unknown options and unsupported profiles.
2. Go writes open in Rust and Rust writes open in Go, with identical search
   terms under the same inputs. Use fixed randomness only in test fixtures;
   cross-opening and SQL behavior are the production compatibility criteria.
3. All operation rows above run through the real guest and PostgreSQL.
   Retain the engine's jsonb containment/read oracles; add Go binding coverage.
4. Test both root policies, nested arrays, quoted keys, scalar/null roots,
   SQL NULL, absence, empty containers, large integers and the #1366 float.
5. Test wildcard N-1/N/N+1, nested expansion caps, budget zero/default,
   fallback equivalence, malicious row substitutions, duplicates, mixed
   documents, truncated subtrees and the documented omission limitations.
6. Test actual SQL driver encodings: `driver.Valuer`/`Scanner`, pgx arrays,
   explicit casts, sqlc/GORM integration where the SDK promises support.
7. Freeze exact storage/header/search vectors and context derivation;
   verify guest/engine/EQL bundle compatibility. Record the accepted leakage
   profile. Future Rust/package changes must retain these fixtures.

## Implementation order and issue amendments

| Slice | Work | Existing issue to revise |
| --- | --- | --- |
| A. Contract and registry | Versioned configured targets, operation/result schemas, defaults, profile identity, catalog and generated types | #1348 plus contract portion of #1349 |
| B. Full-document path | JSON ingress/egress, typed target adapter, definition resolution, batched writes/decrypts | #1349 |
| C. Queries and reads in Rust/guest | JSON operators, selector preparation, token-list preparation, request-bound opening, child helper, stable errors | #1350 and #1352 together |
| D. Go surface | Tags/policies, checker, generated field methods, named SQL values, read objects and examples | #1351 |
| E. Customer release proof | Go/guest/PostgreSQL tests, conformance and storage vectors, supported-profile docs | #1347 acceptance checklist |

Start with A and a thin B/C vertical slice: one configured JSON field, batch
round trip, containment and a request-bound subtree read through the guest.
That proves the difficult seams before expanding the generator. It is an
implementation milestone, not permission to release a reduced operation set.

Coordinate opaque storage adoption with Vitamin C #520/#526 once reviewed
and released. Keep Rust facade/package refactors off this critical path.
Align tracking issue #1347 and work items #1348–#1352 with the slices above
before assigning implementation. Their external issue descriptions have not
yet been amended by this documentation change.

## Evidence and verification performed

Read #1353 and its six tracking issues; inspected merged engine, EQL SQL,
Go generator/runtime, guest dispatch and the API redesign documents. Read
Vitamin C #520/#526 descriptions to distinguish their storage deliverable
from Stack integration. The accompanying engine findings link immutable
source locations. Only documentation checks ran here; no new implementation,
Go/Rust build, live database test or performance claim is reported.

Additional primary sources:

- [SDK principles](https://github.com/cipherstash/stack/blob/ebdb5de0a12bbec06842851eece283fb7faea30b/docs/sdk-design-principles.md).
- [Dynamic target resolver and descriptor](https://github.com/cipherstash/stack/blob/ebdb5de0a12bbec06842851eece283fb7faea30b/packages/stack-encrypt/src/dynamic/target.rs).
- [Current Go query response](https://github.com/cipherstash/stack/blob/ebdb5de0a12bbec06842851eece283fb7faea30b/languages/golang/encrypt/query.go).
- [Guest target dispatch](https://github.com/cipherstash/stack/blob/ebdb5de0a12bbec06842851eece283fb7faea30b/languages/golang/encrypt/guest/src/targets.rs).
- [Current Go codec and opaque JSON storage](https://github.com/cipherstash/stack/blob/ebdb5de0a12bbec06842851eece283fb7faea30b/languages/golang/encrypt/gensupport/codec.go).
- [Vitamin C Rust storage profile #520](https://github.com/cipherstash/vitaminc/pull/520)
  and [Go storage profile #526](https://github.com/cipherstash/vitaminc/pull/526).
