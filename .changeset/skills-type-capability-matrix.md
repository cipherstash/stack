---
'stash': patch
---

Add a type → predicate → domain → index capability matrix to the `stash-encryption` skill, cross-linked from `stash-indexing` and `stash-postgres`.

Picking the wrong `types.*` factory is silent at authoring time — there is no type error and no runtime warning, just a predicate that never runs. The skills documented the capability *suffixes* and the families they apply to, but never the 40 concrete factories in one lookup, so answering "can `types.Double` do a range query" meant composing two tables and knowing the exceptions. It cannot: `types.Double` is storage-only.

The new matrix has one row per factory with its Postgres column domain, the predicates it supports, the extractor to index it through, and whether it works on managed Postgres. Alongside it: a note on which schema holds what (`public` for column domains, `eql_v3` for query domains and operator functions, `eql_v3_internal` for index-term types) and why the Supabase grants have to cover the last two.

Two corrections came out of writing it:

- The `Ord` vs `OrdOre` callout said the install "disables the `_ord_ore` domains" on managed Postgres. Precisely: the bundle adds an always-raising `eql_ore_unavailable` CHECK to them, so a *write* fails — the domain is unusable, not merely unindexed. The callout now says that, notes that RDS and Aurora do support ORE while cloud-hosted Supabase does not, and points at `stash eql preflight` / `eql status` rather than asking the reader to guess.
- The `stash-postgres` naming table omitted `types.TextOrdOre` entirely (its `<N>` shorthand covers only the numeric and temporal families). Added.

A new test derives the matrix from the `types` namespace and fails if the skill disagrees — every factory present exactly once, mapped to the domain it actually builds, naming the extractors it actually emits and none it does not, with every ORE row marked unusable where the operator class is absent.
