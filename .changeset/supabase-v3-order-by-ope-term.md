---
'@cipherstash/stack-supabase': minor
---

**`order()` works on EQL v3 encrypted ordering columns.**

A bare `ORDER BY col` on an EQL v3 domain is wrong — the bundle declares no btree
operator class on any domain, so the sort falls through to jsonb's default
`jsonb_cmp` and compares the envelope's keys in storage order, starting at the
random ciphertext `c`. Measured over ten rows it returns `r00,r04,r08,r01,…`
where the plaintext order is `r00..r09`. No error, a stable and
plausible-looking meaningless order.

But the correct sort key is reachable without a function call. `eql_v3.ord_term`
returns the domain's `op` term, and OPE is order-preserving, so ordering by the
term reproduces the plaintext order. PostgREST cannot emit
`ORDER BY eql_v3.ord_term(col)`, but it can emit a jsonb path. The builder emits
`order=col->op` for an encrypted ordering column, verified against a live
PostgREST for `eql_v3_integer_ord` and `eql_v3_text_search` in both directions.

The guard is on the ordering FLAVOUR, not on encryption:

- **`ope` present → supported.** Every plain `eql_v3_*_ord` domain, plus
  `eql_v3_text_ord` and `eql_v3_text_search`.
- **`ore` present → rejected.** The `ob` term is an array of ORE blocks whose
  comparison needs the superuser-only operator class, which no jsonb path can
  reach. (Such a column cannot hold data on managed Postgres anyway: its domain
  CHECK raises `ore_domain_unavailable`.) ORE columns are excluded from `order()`
  at COMPILE time as well as at runtime — `.order(oreColumn)` is a type error,
  matching the rejection.
- **neither → rejected.** Storage-only, equality-only and match-only columns
  carry no ordering term.

The path is `col->op` (jsonb), not `col->>op` (text). Neither avoids the
database collation — Postgres compares jsonb strings with `varstr_cmp` under the
default collation, exactly as it does text. What makes the ordering
collation-independent is the term's encoding: lowercase hex, fixed-width for
numeric and date domains, and per-character (16 hex chars each) for text, so
lexicographic order reproduces plaintext order including the prefix case
(`ada` < `adam`). `ope-term.integration.test.ts` pins that shape.

`OrderableKeys` admits OPE-backed ordering columns (`eql_v3_*_ord`,
`eql_v3_text_ord`, `eql_v3_text_search`) while excluding ORE
(`eql_v3_*_ord_ore`) columns, so `order()` typechecks exactly where it works.
`is(col, true)` is unaffected — it stays plaintext-only, with its own
`PlaintextKeys` rather than borrowing the orderable set.
