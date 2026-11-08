# Record query-refusal profile

`record-query-refusals-v1` describes the cases in `v1/query-refusals.json`:
what a query is refused for before any term exists, and the few inputs
that look refusable and are not. It is an experimental test contract for
native Rust and Go WASI under `NoTargets`. Python and TypeScript runners
remain pending.

The scalar and runtime profiles cover a handful of equality refusals. This
profile is the shared rejection corpus: every scalar operator against
every field capability of the plan, and the operand shapes and values
listed below, with the class of each refusal, its structured diagnostic,
and the observation that no key is requested.

The runners are `packages/stack-encrypt/tests/query_refusal_conformance.rs`
and `languages/golang/encrypt/query_refusal_conformance_test.go`.

## Plan and inputs

`fields` declares one plan every case queries, each field under context
`["conformance", <name>]`: equality-only text, match-only text, order-only
text (ORE and block ORE), an integer with equality and order, an order-only
float, a 128-bit integer with equality and OPE, a ciphertext-only bool and
text, a sealed-null and a SQL-null integer, and bytes with an order index.

A case names a `field`, an `operator` and an `input`: a scalar `{type, text}`
in the value profile's form, or `{"type": "list", "items": [...]}` for a
range. `accepted` is mandatory; a refused case carries `expected_error`.

## Refusal classes

| `class` | Engine error | Go sentinel | Diagnostic |
|---|---|---|---|
| `source` | `Error::Source` | `ErrEncoding` | `stack_encrypt::dynamic_source` with `reason` and `field` |
| `plan` | `Error::Plan` | `ErrEncoding` | `stack_encrypt::dynamic_plan` with `reason` and `field` |
| `term` | the index's own refusal of the value | `ErrTerm` | the term error's code (`stack_encrypt::empty_term_text`, `term_normalize`, `ore_block_too_long`, `ore_block_trailing_nul`); no reason or field |

Source and plan refusals cover every scalar operator (`eq`, `lt`, `lte`,
`gt`, `gte`, `between`, `matches`) on every field of the plan whose
indexes do not answer it, one case per pair: the equality-only text and
integer, the match-only text, the ORE and block ORE text, the order-only
float, the ciphertext-only bool and text, and the bytes field (equality
and an order index no operator reads). The 128-bit integer (equality and
OPE) and the 32-bit integer (equality and ORE) answer every operator but
`matches`. The SQL-null integer shares the equality-only
integer's indexes and is not repeated. A JSON document operator on an
integer is refused as well. The remaining source refusals are operand
shapes and values: a range that is not a list of two
(a scalar, one bound, three bounds, text), a value of another kind (text or
a fraction for an integer, a negative for an unsigned, an integer for text,
a bool for an integer, a null bound), a null on a field that does not seal
its nulls beside an equality term (ORE and OPE order indexes included), a field the plan does not name and an
operator name the engine does not know.

Term refusals cover match text that cuts no token (too short, empty, only
separators), text no index can normalize (a code point Unicode 16 does not
assign) under match, equality and order, and the block ORE limits (a fold
over 1023 bytes, a trailing NUL) on either bound of a range.

Accepted cases are the positive controls: an inverted range at 32-bit,
128-bit and float widths (neither path refuses it; as SQL's `BETWEEN`, it
matches nothing), the longest block ORE
text, an interior NUL, empty order text, a null equality query on a
sealed-null field, folded match text and a losslessly widened integer.

## Required observations

Both runners run every case through query-term derivation: `QueryTerm` in
Go, `dynamic::query_term` in Rust, which must refuse before returning a
pending operation. For `matches`, both also run verification of an empty
page (`Verify`, `dynamic::verify`) and require the same outcome. Rust also
runs the binding's key-free check, `dynamic::check_query`, and requires the
same diagnostic, and observes that no keyset lookup, data-key generation or
retrieval happens on any path. Go's deterministic guest makes no network
request; that is not a logical key-call count.

The operator vocabulary is closed in Rust (`OpSpec`), so the unknown
operator case is observed at the binding boundary alone; the Rust runner
checks that the case expects exactly that and continues.

## The typed chain

`typed` records how the typed Rust query chain answers the same query, for
the queries it can spell (text on the text fields, a `uint32` range under
ORE and an `int128` range under OPE): `before_keyset`, `after_keyset` or `none`. The Rust runner
builds a one-field typed plan with the index that answers the operator,
runs the chain under a keyset named for the case, and counts the keyset
load. A refusal before the load is `before_keyset`; one after it is
`after_keyset`. The error code must equal the binding's.

Today the two paths refuse the same inputs with the same codes, but not at
the same stage:

| Refusal | Binding (`check_query`, `query_term`) | Typed chain |
|---|---|---|
| Match text with no token or no normal form | before any keyset | before any keyset |
| Equality text with no normal form | before any keyset | after the keyset is loaded |
| Order text with no normal form (ORE, OPE) | before any keyset | after the keyset is loaded |
| Block ORE text too long or ending in NUL | before any keyset | after the keyset is loaded |

The binding checks every index's value refusals in `check_input`; the
typed chain's `Supports::check` runs before the keyset for the match index
alone, and the other indexes refuse the value when they derive its term.
This profile pins the current stage as a documented difference. Moving the
typed refusals earlier is step 2 of "The engine's rules, and the order of
the work" in the API plan (`docs/plans/2026-10-24-stack-encrypt-api-plan.md`),
which runs every check that needs no key before a key is used. When it
lands, the `typed` entries change to `before_keyset` on purpose, and this
table with them.

## Scope and remaining work

The corpus covers scalar operators under `NoTargets`. Match options the
index cannot use (an n-gram length of zero) are a declaration refusal, in
`v1/declarations.json` (`match-invalid-ngram-zero`). JSON document
operators against JSON fields, EQL target refusals, `target_limit` inputs and the match-case
mismatch only the typed chain can express remain with their existing
tests. The match-case mismatch goes away with the API plan's step 3,
which removes `Matches`'s case parameter and `.via`. The Go runner does not exercise generated query methods; those keep
their fixture tests. No existing test is removed.
