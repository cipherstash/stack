---
'stash': minor
---

Rewrite `db validate` as `eql validate`, for the EQL v3 domain-type vocabulary.

**Fixes a false finding on the most ordinary v3 columns.** The old rule set
checked for `ore` / `unique` / `match` / `ste_vec` indexes and never learned
about `ope`. EQL v3's default ordering domains emit `ope`, so
`types.IntegerOrd('age')` and `types.TimestampOrd('created_at')` were both
reported as "Column is encrypted but has no indexes — it will not be
searchable". They are now silent.

The command reads your tables through the new
`EncryptionClient.getSchemas()`, so it sees each column's **concrete domain**
rather than the lossy encrypt config, and gains a database pass when one is
reachable.

Schema checks (no database needed):

| Rule | Severity |
|---|---|
| An `_ord_ore` domain is declared — its ORE operator class needs superuser | Warning |
| Storage-only column: encrypts and decrypts, carries no query terms | Info |
| Searchable `boolean` column | Error |
| Free-text `match` index on a non-text domain | Error |
| Encrypted-JSONB (`ste_vec`) index without `types.Json` | Error |

Database checks (skipped with a notice, not a failure, when no database is
reachable):

| Rule | Severity |
|---|---|
| EQL v3 is not installed — reported once, remaining database checks skipped | Error |
| A declared table lives in a different schema than the one searched | Warning |
| A declared table exists in no schema at all | Error |
| A declared column is missing from a table that was found | Error |
| The database column's domain differs from the declared one | Error |
| The database column is still plain (no EQL domain) | Error |
| An `_ord_ore` domain where the EQL install could not create the ORE operator class | Error |
| A queryable column with no functional index over its term extractor | Info |

`--exclude-operator-family` is removed: it warned that an `ore` index would not
support `ORDER BY` without operator families, and the pinned EQL v3 bundle
self-adapts. `eql install` / `eql upgrade` had already rejected the flag;
`validate` was its last consumer.

The database pass inspects `current_schema()` only, but looks each declared
table name up across every schema before deciding what a miss means. Found
elsewhere — Prisma `multiSchema`, a tenant schema, a `schema.table` name — the
project is healthy and merely pointed at the wrong `search_path`, so that is a
Warning naming the schema that has it. Found nowhere, the migration has not
run, and that is an Error. Either way it is reported once per table rather
than once per column.

Against a project whose `@cipherstash/stack` predates `getSchemas()`, validate
says so and falls back to the encrypt config, running the index-derived rules
and skipping the domain ones.

`stash db validate` keeps working as a deprecated alias, like `db install` /
`db upgrade` / `db status`. Exits 1 on errors only.
