# Go JSON: implementation status and remaining delivery plan

Updated: 2026-10-27. Reviewed `next` at
[`ffeed7adb3f7d8739cda53261046147852bffc82`](https://github.com/cipherstash/stack/commit/ffeed7adb3f7d8739cda53261046147852bffc82),
against the previous `ebdb5de0a` baseline. This is the plan in
[#1353](https://github.com/cipherstash/stack/pull/1353).
Tracking issue #1347 and implementation issues #1348–#1352 are now closed.

Go JSON is implemented on `next`. The remaining task is release readiness
and explicit closure of the narrower gaps below, not rebuilding the original
catalog/guest/generator sequence. Broader Rust API and packaging work remains
in [#1365](https://github.com/cipherstash/stack/pull/1365).

Source-backed details are in the [engine findings](2026-10-25-go-json-engine-contract.md)
and [Go implementation status](2026-10-27-go-json-implementation-status.md).
These distinguish inspected tests from tests rerun during this review.

## What has landed

| PR | Merged behavior | Change to the plan |
| --- | --- | --- |
| [#1381](https://github.com/cipherstash/stack/pull/1381) | Mutation CI computes the diff against the actual PR base | Verification infrastructure; no new public API task |
| [#1379](https://github.com/cipherstash/stack/pull/1379) | Cascade authentication and randomized JSON entry/object/projection order | Update read guarantees, wildcard SQL and storage fixtures |
| [#1369](https://github.com/cipherstash/stack/pull/1369) | Go Vitamin C storage-capable pseudo-version pin; final-release guard | Adoption is done; replace the temporary Go pin before a final release |
| [#1370](https://github.com/cipherstash/stack/pull/1370) | Opaque Go structs use the versioned storage profile | Remove codec adoption from future implementation work |
| [#1372](https://github.com/cipherstash/stack/pull/1372) | JSON catalog, configured targets, parser and full-document dynamic execution | Mark the registry/document path implemented |
| [#1373](https://github.com/cipherstash/stack/pull/1373) | JSON operators, operand encodings and request-bound guest reads | Mark query/read plumbing implemented |
| [#1378](https://github.com/cipherstash/stack/pull/1378) | Generated Go JSON fields, typed document adapters and typed query inputs | Mark the generated frontend implemented |
| [#1397](https://github.com/cipherstash/stack/pull/1397) | Short whole-word terms in EQL v4 match filters | Record current behavior separately from unresolved configurable-match/privacy work |
| [#1402](https://github.com/cipherstash/stack/pull/1402) | Go typed JSON docs, runnable example and documentation drift check | Use the shipped examples instead of speculative API recipes |

## The implemented public contract

Use the landed names for customer-facing code. Do not make a cosmetic rename
or a replacement Go builder a release dependency.

| Role | Current spelling |
| --- | --- |
| Registered target / tag | `JsonSearch`, `encrypt_into=JsonSearch` |
| Stored Go value | `eql.JSONSearch` |
| Containment operand | `eql.JSONSearchQuery` |
| Ordering operand | `eql.JSONSearchLeafQuery` |
| Returned encrypted entry | `eql.JSONEntry` |
| Prepared selector / subtree read | `encrypt.JSONSelection`, `encrypt.JSONRead` |
| SQL scalar / list parameter | `encrypt.JSONSelector`, `JSONToken`, `JSONTokens` |
| Singular plaintext result | `encrypt.JSONValue{Found, JSON}` |
| Stored SQL domain | `public.eql_v4_json_search` |
| Query SQL domains | `eql_v4.query_json`, `eql_v4.query_json_leaf` |
| Entry SQL domain | `public.eql_v4_json_entry` |

The lower-level engine still uses `JsonDocument`, and handwritten EQL Rust
adapters retain `JsonTree*` names. `eql.JSON` remains storage-only. EQL v4's
old SteVec entries have been removed; v3 remains a separate contract.

Configured target objects already work. The current data-plan grammar is a
field map, not the proposed `version`/`fields` envelope:

```json
{
  "profile": {
    "type": "json",
    "context": ["users", "profile"],
    "target": {
      "name": "JsonSearch",
      "options": {"sealed_root": true, "ordered": ["$.salary"]}
    }
  }
}
```

A string target selects defaults. Native options are resolved in the plan;
queries and reads use that field's options. Unsupported options and malformed
JSON/path inputs fail through the engine. This implements the configured
JSON target seam; it does not implement the full general definition cache,
role system or versioned interoperability specification from the API review.
The guest still parses submitted plans per operation.

Query results now identify `encoding` (`bytes`, `eql`, `text`, `text_array`),
and capability entries identify the input shape. Go's `QueryTerm` carries
byte terms or text values, and generated methods check the expected result.
That meets JSON's operand distinction; do not require a new sum-type API
solely because the earlier plan illustrated one.

## Go usage and input boundaries

The existing generated call shape remains `Encrypt`, `Decrypt` and `Fields`.
A representative declaration, using implemented syntax:

```go
type Profile struct {
    Name   string `json:"name"`
    Salary int64  `json:"salary"`
}

type User struct {
    _       struct{} `stash:"context=users"`
    ID      int64    `stash:"id,passthrough"`
    Profile Profile  `stash:"profile,encrypt_into=JsonSearch(ordered=$.salary)"`
}
```

`json.RawMessage` supports arbitrary JSON roots, including scalar and null.
Structs, supported maps and slices have explicit `encoding/json` adapters.
Pointer fields use `null=sql`; a nil pointer is absent, while a non-nil raw
message containing `null` is present JSON null. Typed nil maps/slices encode
as JSON null. The generator refuses unsupported typed shapes; use raw JSON
for roots not expressible by a supported typed document declaration.

Query methods accept Go values and explicit raw JSON needles. They guard
against plain byte slices, accidental string/null containment inputs and a
full field struct used as a containment needle with zero-valued members.
`DecodeJSON[T]` reads selected JSON into the requested type and uses
`json.Number` inside interface values. Typed adapters retain Go's own JSON
semantics, including replacement of invalid UTF-8 before Rust sees it.

The shared Rust parser rejects duplicate keys, invalid JSON/Unicode and
integer literals outside `i64::MIN..=u64::MAX`; finite fractional/exponent
numbers follow binary64 semantics. This validation is implemented, not a
future parser project. Arbitrary-precision PostgreSQL numbers remain outside
the contract. Numeric ordering still uses `f64`, so large integers can tie.

Ordered paths in tags are semicolon-separated. Generated `At.<Path>`
accessors and runtime path methods exist. Quoted-key paths work in the native
path grammar but not in the current simple tag spelling; define a structured
Go declaration route if that is required for the customer's ordered keys.

The complete executable example is maintained in
[languages/golang/encrypt/example/json](https://github.com/cipherstash/stack/tree/ffeed7adb3f7d8739cda53261046147852bffc82/languages/golang/encrypt/example/json).
Its current read shape is `read.Open(ctx, groupedEntries)`: the prepared read
already retains its cipher and declaration. The old proposed
`read.Open(ctx, cipher, rows)` is not the implemented API.

## Corrected operation and read semantics

| Capability | Implemented surface / current limit |
| --- | --- |
| Full-document writes/reads and batches | Generated `Encrypt`/`Decrypt`, including raw and typed documents |
| Contains / contained-by / scalar equality at path | Generated `Contains`, `ContainedBy`, `EqAt`; equality uses value terms, never ordering terms |
| Ordering and ranges | Declared-path accessors and runtime methods; `Between` returns named bounds |
| Existence / sorting / `->` / `->>` | Selector parameter plus application SQL; `->>` still returns encrypted text |
| Open selected entry | `JSONSelection.Open`, one optional entry per database row |
| Positional / wildcard subtree | `Subtree`, token list, `JSONRead.Open` / `OpenOne`; rederivation and verification happen in Rust |
| Enumerate / count children | `Children` / `ChildCount` prepare a concrete node token for SQL |
| Parent-bound plaintext child opening | Not implemented; do not pass child rows to the subtree or selector opener as if they were its requested result |
| All selector matches | SQL can enumerate them; the dynamic selector opener accepts at most one entry per document group. Use wildcard subtree reads for supported all-match plaintext retrieval |

A selector addresses an array path class; positional selector queries are
rejected. Use subtree reads for exact positions. Wildcard `->` returns an
**unspecified element**, because stored entry order is randomized. It is
not the first element in document order. For an existential ordering predicate,
use `EXISTS` over `json_tree_path_query`; define an explicit aggregate for
sorting a multi-valued path. Equality at a wildcard is any-match. Independent
EqAt predicates need not match the same array element; one containment
needle preserves correlation.

Cascade authentication binds a container's children into its ciphertext.
A nonempty container entry cannot open alone; use a subtree read. The
`JsonNotALeaf` error also covers alteration, since the client cannot reliably
distinguish those causes before opening. Empty ordinary containers instead
fail `OpenedType`; they also require subtree reads. Sealed-root fallback applies
the original requested path after decryption.

Reads retain the original trusted path/definition/keyset. SQL rows cannot
choose their own expected request. Entries are grouped per database document
and opened through the common batch engine. The protocol still does not
prove that the database returned every match or the intended database row;
whole results or probes may be withheld. Do not claim authenticated absence
or result-set completeness.

The two limits remain separate: wildcard bound defaults to 64 with probes
and an 8,192-token expansion cap; SQL walk budget defaults to 64 and selects
sealed-root fallback. A zero walk budget disables fallback; an open root
cannot use that fallback. `OpenOne` rejects wildcard reads up front.

## Storage and release compatibility

Opaque Go writes already call `vcffi.MarshalStorage`; readers recognize
storage blobs and retain the legacy JSON fallback. Future storage versions
fail as `ErrStorageVersion`, not JSON decode. Generated code now requires
`GeneratedVersion2` and `vc` tags. Record the implemented behavior: regenerate
code, upgrade readers first if earlier writers were deployed, nil containers
round-trip empty, nonfinite floats are allowed, and some formerly JSON-only
opaque types are refused. No new migration system is requested here.

Go currently pins Vitamin C at `06568ba93bd9` using pseudo-versions. Rust
workspaces remain on crates.io Vitamin C 0.8.0. The final Go release guard
rejects the pseudo-version pins; a prerelease may carry them. Replace the
Go module pins with released tags before a final release rather than blocking
all JSON work on a Rust dependency move.

JSON-tree storage remains separate. #1379 changed authentication and order
without changing the header version from 1. The old and new profiles are not
interchangeable merely because their header/envelope versions match. The
prototype compatibility exemption permits this pre-release change; freeze
the post-cascade vectors and context/search semantics for customer data.

Containment projections and query projections are now randomized too.
Compare canonical/set semantics and cross-opening/query behavior in parity
tests. Raw byte equality requires controlled randomness; never require two
ordinary query calls to serialize identical arrays.

## Context and broader API redesign

The shipping JSON profile still uses column identity and selected keyset.
EQL target extensions and context-field plans are refused. Separate row AAD,
search scope and role eligibility are not implemented by the configured-target
work. Preserve the accepted direction, but do not advertise those capabilities
or block the existing profile's release on implementing the whole redesign.

Before enabling row-bound JSON, split PRF and AEAD input roles and test all
read/query paths. Appending row IDs to the current shared context would make
search terms row-specific. Provider policy and keyset selection remain
separate from JSON options. Open-root JSON now also needs index-key loading
for verification; generic execution/provider bounds must account for both
`DataKeySource` and `IndexKeySource`.

## Remaining work, in delivery order

1. **Finish the supported-contract specification.** Describe the implemented
   field-map grammar, options, operator inputs, `encoding` results, grouped
   reads, error codes and supported context profile. Add the promised schema
   and shared conformance corpus; allocate versioning explicitly. Do not
   describe the earlier illustrative versioned envelope as already accepted
   by the runtime. General definition caches and Rust factories can follow.
2. **Close narrow coverage gaps.** Add parent-bound child-scalar opening
   to meet the comprehensive inventory requirement. SQL children
   and counts are present, but are not this opener. For all-match reads, use
   the existing subtree API; do not invent an unsafe selector-group shortcut.
   Confirm whether complex ordered-key declarations need a structured Go
   route. Complete direct typed EQL conversions as a format-preserving cleanup.
3. **Finish configurable match support for the customer.** #1397 supplies
   whole two-character words in the existing EQL filter, enabled by the
   pinned EQL match profile. Native Go `index=match` still refuses options
   (#1112); configurable tokenizers/filter pipelines are not thereby done.
   The implementation uses deterministic domain-separated word terms, not
   random variants. This review records that fact without settling the
   previously raised privacy concern or changing the uncommitted research.
4. **Validate and freeze the candidate.** Use the existing Rust, guest, Go
   and PostgreSQL tests and runnable example; verify supported operations,
   numeric/null behavior, both root policies, bounds/fallback, tampering and
   the known omission limits on the exact release build. Freeze post-cascade
   JSON and short-word search semantics. Rebuilding old Bloom rows is needed
   for reliable short-word queries if pre-change prototype data is retained.
5. **Release dependencies and artifacts.** Replace the temporary Go module
   pins for a final release; build production guests and the matching EQL v4
   bundle using the existing release workflow. Keep Rust facade/package moves
   behind this customer delivery.

The original thin vertical slice is complete and is no longer the next
implementation task. Closed issues #1347–#1352 should not remain labelled
unimplemented in the plan. Any residual work above needs its own scoped
acceptance item rather than reopening the whole JSON feature.

## Evidence and verification

This refresh inspected the nine first-parent merges, current source,
changelogs, tests and documentation, and checked the tracking issue states.
No new runtime code was written. Markdown/link/JSON checks are run on the
plan changes; runtime and database suites were not rerun for this review.
Merged PR verification reports and existing test files are evidence of
coverage, not a fresh certification of the customer release build.
