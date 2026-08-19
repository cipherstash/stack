---
'stash': minor
---

Report the ORE-unavailable case once, at install time, instead of leaving it to surface as a failing predicate the first time a column is cast.

The EQL bundle skips the ORE btree operator class when the installing role cannot create one and poisons every `_ord_ore` domain with a loud-failure CHECK in its place. That is a supported configuration — but nothing said so where the choice between `types.*Ord` and `types.*OrdOre` is actually made, so the trade was discovered at query time.

- **`stash eql preflight` now probes whether the role can create an operator class** and reports it as a non-blocking `ORE operator class` row (`creatable` / `not creatable` / `unknown`; `canCreateOperatorClass` in `--json`). It is *probed*, not inferred from `superuser`: `CREATE OPERATOR CLASS` is superuser-gated in stock PostgreSQL, but AWS RDS and Aurora let their admin role create one while cloud-hosted Supabase does not, so `rolsuper` is not evidence either way. The probe attempts the DDL inside a transaction it always rolls back, leaving preflight read-only; a probe that could not ask reports `unknown` rather than guessing.
- **`stash eql install` names the consequence and the remedy** on its own line when the fallback was installed, rather than as a parenthetical on the "verified" line.
- **`stash eql status` reports the ORE state** on a v3 install, so the answer survives past the install output.
- **The remedy now names a type that exists.** The previous wording pointed at the `_ord_ope` domains; the bundle creates those, but `@cipherstash/stack` ships no `types.*OrdOpe` factory, so it named a column type no schema author could declare. Every command now says `types.*Ord` (`public.eql_v3_*_ord`), which is the same CLLW-OPE ordering and has a factory behind it.
- The ORE state machine, the catalogue probe, and this copy now live in one module shared by `eql preflight`, `eql install`, `eql status`, `eql verify`, and `eql validate`, so the five commands cannot drift into disagreeing about the same catalogue fact.
- The scaffolded encryption client's type cheat-sheet now says why ordered columns should be `*Ord` rather than `*OrdOre`.
